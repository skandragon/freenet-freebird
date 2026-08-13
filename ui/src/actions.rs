//! User-intent actions: onboard, post, follow, verify. Bridge between views
//! and the api layer; every action signs locally with the posting key.

use dioxus::prelude::*;
use directory_contract::{AuthorizedListingV3, ListingV1};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freebird_core::attestation::AttestationV2;
use freebird_core::delegate_api::FreebirdDelegateRequest;
use freebird_core::feed::legacy::LegacyFeedState;
use freebird_core::feed::{AttestationSlot, FeedStateV1, FeedStateV1Delta, PostsV1};
use freebird_core::types::{
    AuthorizedFollows, AuthorizedPost, AuthorizedProfile, FollowsV1, PostId, PostRef, ProfileV1,
};
use inbox_contract::state::{
    AuthorizedReplyPointerV3, InboxStateV3Delta, ReplierCredV3, ReplyPointerV3,
};

use crate::api;
use crate::ghostkey::{self, GhostkeyRequest};
use crate::keys;
use crate::state::*;

/// Sentinel `target_post` marking an inbox pointer as a follow announcement
/// (issue #12), not a reply. Reuses the deployed reply-pointer shape — the
/// contract never checks that target_post names a real post — so the inbox
/// contract bytes (and every derived address) stay unchanged. Real PostIds
/// are blake3 output; colliding with this ASCII tag is a 2^-128 event.
pub const FOLLOW_ANNOUNCE_TARGET: PostId = PostId(*b"freebird:follow!");

fn empty_delta() -> FeedStateV1Delta {
    FeedStateV1Delta {
        profile: None,
        follows: None,
        attestation: None,
        posts: None,
    }
}

/// Create a brand-new anonymous account: generate the posting key, persist
/// it in the delegate, and PUT the feed + inbox contracts.
pub async fn create_account(name: String) -> Result<(), String> {
    use rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();

    api::kv_request(FreebirdDelegateRequest::Store {
        key: "posting_key".into(),
        value: sk.to_bytes().to_vec(),
    })
    .await?;

    let state = FeedStateV1 {
        profile: AuthorizedProfile::new(
            ProfileV1 {
                name,
                bio: String::new(),
                version: 1,
            },
            &sk,
        ),
        follows: AuthorizedFollows::new(
            FollowsV1 {
                follows: Default::default(),
                version: 1,
            },
            &sk,
        ),
        attestation: AttestationSlot(None),
        posts: PostsV1::default(),
    };

    api::put_own_contracts(&vk, &state).await?;
    // Anchor cell: role → current contract generation, so future rotations
    // are soft for anyone reading us (issue #23). Best-effort — a missing
    // anchor just means readers fall back to derived addresses.
    if let Err(e) = api::publish_anchor(&sk).await {
        api::log(&format!("anchor publish failed: {e}"));
    }

    let author = vk.to_bytes();
    FEEDS.write().insert(author, Some(state));
    *ACCOUNT.write() = Some(sk.clone());
    // Mark the seed as loaded too, so a late carry-forward answer from an
    // old delegate generation can never clobber this fresh identity.
    *POSTING_KEY_LOADED.write() = Some(Some(sk.to_bytes().to_vec()));
    // Track so update notifications route; PUT already subscribed us.
    api::fetch_feed(author).await.ok();
    Ok(())
}

/// Resume an existing account from the delegate-stored seed.
pub async fn resume_account(seed: Vec<u8>) -> Result<(), String> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| "bad posting_key length")?;
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let author = vk.to_bytes();
    *ACCOUNT.write() = Some(sk.clone());
    // Owner-republish half of the #23 migration, best-effort and idempotent:
    // make sure our v2 feed and inbox exist (an account created before the
    // rotations never PUT either, and an Update against an absent contract
    // fails asynchronously — issue #79) and (re)publish the anchor cell
    // routing to them and the avatar. This runs
    // BEFORE the feed fetch and regardless of its outcome — reachability
    // for replies must not depend on a read succeeding, and the feed PUT
    // must precede `migrate_v1`'s first write, which the fetch gates on.
    if let Err(e) = api::ensure_own_feed(&sk).await {
        api::log(&format!("feed republish failed: {e}"));
    }
    if let Err(e) = api::ensure_own_inbox(&vk).await {
        api::log(&format!("v2 inbox republish failed: {e}"));
    }
    if let Err(e) = api::publish_anchor(&sk).await {
        api::log(&format!("anchor publish failed: {e}"));
    }
    api::fetch_feed(author).await
}

/// Restore an account from a user-supplied recovery seed (issue #53): decode,
/// persist it in the delegate, and resume as if it had been stored all along.
pub async fn import_account(encoded: &str) -> Result<(), String> {
    let seed: [u8; 32] = bs58::decode(encoded.trim())
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("not a valid recovery seed")?;
    api::kv_request(FreebirdDelegateRequest::Store {
        key: "posting_key".into(),
        value: seed.to_vec(),
    })
    .await?;
    // Resume first (it sets ACCOUNT synchronously), THEN publish the loaded
    // seed — the other order fires the App effect's own resume concurrently.
    resume_account(seed.to_vec()).await?;
    *POSTING_KEY_LOADED.write() = Some(Some(seed.to_vec()));
    Ok(())
}

fn signing_key() -> Result<SigningKey, String> {
    ACCOUNT
        .read()
        .as_ref()
        .map(|sk| SigningKey::from_bytes(&sk.to_bytes()))
        .ok_or_else(|| "no account".to_string())
}

fn own_feed() -> Option<FeedStateV1> {
    let author = own_author()?;
    FEEDS.read().get(&author)?.clone()
}

/// Publish a post; when it's a reply, also drop a pointer in the target
/// author's inbox. Anonymous accounts participate too (issue #23) — the
/// attestation, when we have one, only buys the pointer durable slots.
pub async fn publish_post(content: String, in_reply_to: Option<PostRef>) -> Result<(), String> {
    let sk = signing_key()?;
    // Resolve our slot tier BEFORE publishing anything: replying while the
    // own feed is still loading would mint an anonymous-fingerprint pointer
    // that the later-arriving attested cred orphans (the reply would
    // silently leave the thread). Failing up front avoids the partial state.
    let att = if in_reply_to.is_some() {
        own_feed()
            .ok_or("your feed is still loading — try again in a moment")?
            .attestation
            .0
    } else {
        None
    };
    let post = keys::make_post(&sk, content, in_reply_to);
    let mut delta = empty_delta();
    delta.posts = Some(vec![post.clone()]);
    api::update_own_feed(delta).await?;

    // Optimistic local apply so the timeline updates immediately.
    apply_own_posts(vec![post.clone()]);

    if let Some(target) = in_reply_to {
        send_inbox_pointer(
            &sk,
            att,
            target.author,
            target.post,
            post.post.id,
            post.post.time,
        )
        .await
        // The post itself is already out — say so, or the error invites
        // a duplicate repost.
        .map_err(|e| {
            format!("reply posted to your feed, but delivering it to the thread failed: {e}")
        })?;
    }
    Ok(())
}

/// Drop a pointer into `target_author`'s inbox: a reply pointer, or a follow
/// announcement when `target_post` is FOLLOW_ANNOUNCE_TARGET. `attestation`
/// picks the slot tier (attested = uncrowdable, None = anonymous share).
async fn send_inbox_pointer(
    sk: &SigningKey,
    attestation: Option<AttestationV2>,
    target_author: [u8; 32],
    target_post: PostId,
    reply_post: PostId,
    time: u64,
) -> Result<(), String> {
    let replier = sk.verifying_key().to_bytes();
    let cred = ReplierCredV3 {
        posting_key: sk.verifying_key(),
        attestation,
    };
    let ptr = ReplyPointerV3 {
        // v3 (issue #46): pointers are bound to their inbox instance.
        owner: target_author,
        replier,
        fingerprint: cred.fingerprint(),
        target_post,
        reply_post,
        time,
    };
    // Anonymous pointers must carry a proof-of-work stamp (issue #51);
    // attested (ghost-key) pointers skip PoW. The solve is a synchronous
    // hashcash loop — a fraction of a second at the floor, longer under a
    // raise — and it runs on the UI thread (ponytail: move to a Web Worker if
    // it ever stutters posting).
    //
    // Attaching the record (issue #66) is what LATCHES the raise into this
    // inbox's state, so every later write there is held to it too.
    // ponytail: an inbox no #66-aware client ever writes to keeps the floor
    // until one does — there is no global push into per-owner instances.
    // Closing that needs a publisher fan-out or an owner-side push on load.
    let difficulty = POW_DIFFICULTY.read().clone();
    let authorized = if cred.attestation.is_none() {
        let bits = freebird_pow::difficulty_bits(difficulty.as_ref());
        AuthorizedReplyPointerV3::new_anon(ptr, sk, bits)
    } else {
        AuthorizedReplyPointerV3::new(ptr, sk)
    };
    let delta = InboxStateV3Delta {
        creds: Some([(replier, cred)].into_iter().collect()),
        pointers: Some(vec![authorized]),
        pow_difficulty: difficulty,
    };
    api::update_inbox(target_author, delta).await
}

/// Legacy posts that still owe a v2 copy: everything in the v1 feed the v2
/// feed doesn't already hold, re-signed under the #47 canonical payload (v1
/// signed bare CBOR, so the old signatures don't verify here). `PostId` did
/// not change across the rotation, so re-signing preserves every id that
/// inbox pointers and `in_reply_to` links refer to.
fn posts_to_migrate(
    legacy: &[AuthorizedPost],
    current: &PostsV1,
    sk: &SigningKey,
) -> Vec<AuthorizedPost> {
    let held: std::collections::BTreeSet<PostId> =
        current.posts.iter().map(|p| p.post.id).collect();
    legacy
        .iter()
        .filter(|p| !held.contains(&p.post.id))
        .map(|p| AuthorizedPost::new(p.post.clone(), sk))
        .collect()
}

/// Legacy identity that still owes a v2 copy: the v1 profile and follow list,
/// re-signed under the #64 domain tags (the v1 signatures don't verify here).
/// Each is skipped unless it is strictly newer than what the v2 feed already
/// holds — a rotated feed starts at `seed_feed`'s version 0, so this normally
/// carries both across, but an edit made after the upgrade must never be
/// rolled back. Strictly-newer is also what makes the write land: the
/// contract's LWW breaks equal-version ties by content hash, so an
/// equal-version delta can be silently dropped.
fn identity_to_migrate(
    legacy: &LegacyFeedState,
    current: &FeedStateV1,
    sk: &SigningKey,
) -> (Option<AuthorizedProfile>, Option<AuthorizedFollows>) {
    let profile = (legacy.profile.profile.version > current.profile.profile.version)
        .then(|| AuthorizedProfile::new(legacy.profile.profile.clone(), sk));
    let follows = (legacy.follows.follows.version > current.follows.follows.version)
        .then(|| AuthorizedFollows::new(legacy.follows.follows.clone(), sk));
    (profile, follows)
}

/// One-time forward migration of this account's v1-era data into the v2
/// contracts (issue #56), so the `read_v1_*` dual-read flags can actually be
/// turned off without losing it:
///
/// - v1 profile + follow list → the v2 feed, re-signed (issue #82).
/// - v1 feed posts → the v2 feed, re-signed (ids preserved).
/// - v1-era replies → a v3 pointer in each target author's inbox.
/// - follows → a v3 follow announcement in each followed author's inbox.
///
/// The directory needs nothing here: the listing-refresh effect in `App`
/// already republishes our listing under the v2 key once per session.
///
/// Owner-driven by necessity, and that is the ceiling: pointers we RECEIVED
/// in v1 are signed by their repliers and only those repliers can re-sign
/// them, so the window closes cleanly only once enough of the network has
/// run this. Nothing is destroyed either way — the v1 state stays where it is.
///
/// `started_ms` is the in-progress marker's stamp, reused across retries so
/// a resumed run re-derives identical follow announcements.
pub async fn migrate_v1(started_ms: u64) -> Result<(), String> {
    let sk = signing_key()?;
    let author = sk.verifying_key().to_bytes();
    let legacy = LEGACY_FEEDS
        .read()
        .get(&author)
        .cloned()
        .flatten()
        .ok_or("legacy feed not loaded")?;
    let current = own_feed().ok_or("feed not loaded")?;

    // Mark in-progress BEFORE the first write: an interrupted run must resume
    // with the SAME stamp, or its follow announcements get fresh PostIds and
    // pile up as duplicate pointers in every followed author's inbox.
    api::kv_request(FreebirdDelegateRequest::Store {
        key: V1_MIGRATION_KEY.into(),
        value: started_ms.to_string().into_bytes(),
    })
    .await?;
    *V1_MIGRATION.write() = Some(V1Migration::Running(started_ms));

    let posts = posts_to_migrate(&legacy.posts.posts, &current.posts, &sk);
    let (profile, follows) = identity_to_migrate(&legacy, &current, &sk);
    if !posts.is_empty() || profile.is_some() || follows.is_some() {
        let delta = FeedStateV1Delta {
            profile,
            follows: follows.clone(),
            attestation: None,
            posts: (!posts.is_empty()).then_some(posts),
        };
        api::update_own_feed(delta.clone()).await?;
        apply_own_delta(delta);
    }

    // Slot tier from the CURRENT (v2) attestation — a v1 AttestationV1 can't
    // be lifted to v2 (it lacks the proof of possession), so an unverified
    // account migrates at the anonymous tier and pays a floor PoW solve per
    // pointer on the UI thread.
    // ponytail: same ceiling `send_inbox_pointer` already carries — move
    // both to a Web Worker if a long reply backlog stutters startup.
    let att = current.attestation.0.clone();
    for post in &legacy.posts.posts {
        let Some(target) = post.post.in_reply_to else {
            continue;
        };
        send_inbox_pointer(
            &sk,
            att.clone(),
            target.author,
            target.post,
            post.post.id,
            post.post.time,
        )
        .await?;
    }

    // Follow announcements only ever existed as inbox pointers, so the whole
    // follower list dies with the window. Re-announce every follow in the list
    // the migration just settled on — the restored legacy one, or the v2 one
    // when that was already newer — stamped with the migration's start time
    // (see `started_ms` above).
    let announce_id = PostId::compute(&sk.verifying_key(), started_ms, "follow", &None);
    let announce_to = follows.as_ref().unwrap_or(&current.follows);
    for target in &announce_to.follows.follows {
        send_inbox_pointer(
            &sk,
            att.clone(),
            *target,
            FOLLOW_ANNOUNCE_TARGET,
            announce_id,
            started_ms,
        )
        .await?;
    }

    api::kv_request(FreebirdDelegateRequest::Store {
        key: V1_MIGRATION_KEY.into(),
        value: b"done".to_vec(),
    })
    .await?;
    *V1_MIGRATION.write() = Some(V1Migration::Done);
    Ok(())
}

/// Re-sign our legacy profile picture into the rotated avatar contract
/// (issue #81) — the terminator for the avatar dual-read window, and the
/// only one that exists: nobody but the owner holds the key.
///
/// Deliberately NOT part of `migrate_v1`'s one-shot: an absent avatar and an
/// avatar that has not arrived yet look identical (Get for a contract that
/// does not exist gets no negative answer), so a one-shot gated on it would
/// either hang the whole migration or mark it done having read nothing. This
/// is idempotent and self-terminating instead — once the re-signed blob is
/// in `AVATARS`, in this session and every later one, it does nothing.
pub async fn migrate_avatar() -> Result<(), String> {
    let sk = signing_key()?;
    let author = sk.verifying_key().to_bytes();
    if AVATARS.read().get(&author).is_some_and(Option::is_some) {
        return Ok(());
    }
    let Some(legacy) = LEGACY_AVATARS.read().get(&author).cloned().flatten() else {
        return Ok(());
    };
    // Same bytes, same timestamp — only the signature scheme changes, so the
    // contract's LWW ordering cannot flip a later upload back to this one.
    let authorized = freebird_core::avatar::AuthorizedAvatar::new(legacy.avatar, &sk);
    freebird_core::avatar::check_avatar(&authorized, &sk.verifying_key())?;
    api::put_own_avatar(&sk.verifying_key(), &authorized).await?;
    AVATARS.write().insert(author, Some(authorized));
    Ok(())
}

/// Optimistic local apply of a delta we just wrote, so the UI updates without
/// waiting for the contract's notification back.
fn apply_own_delta(delta: FeedStateV1Delta) {
    let Some(author) = own_author() else { return };
    let Ok(vk) = VerifyingKey::from_bytes(&author) else {
        return;
    };
    let params = keys::feed_params(&vk);
    if let Some(Some(state)) = FEEDS.write().get_mut(&author) {
        use freenet_scaffold::ComposableState;
        let clone = state.clone();
        let _ = state.apply_delta(&clone, &params, &Some(delta));
    }
}

fn apply_own_posts(posts: Vec<freebird_core::types::AuthorizedPost>) {
    let mut delta = empty_delta();
    delta.posts = Some(posts);
    apply_own_delta(delta);
}

pub async fn publish_profile(name: String, bio: String) -> Result<(), String> {
    let sk = signing_key()?;
    let current = own_feed().ok_or("feed not loaded")?;
    let profile = AuthorizedProfile::new(
        ProfileV1 {
            name,
            bio,
            version: current.profile.profile.version + 1,
        },
        &sk,
    );
    let mut delta = empty_delta();
    delta.profile = Some(profile.clone());
    api::update_own_feed(delta).await?;
    if let Some(Some(state)) = FEEDS.write().get_mut(&own_author().unwrap()) {
        state.profile = profile;
    }
    Ok(())
}

/// Sign and publish a profile picture to our avatar contract (issue #10).
/// The caller supplies bytes already inside the size cap.
pub async fn publish_avatar(content_type: String, data: Vec<u8>) -> Result<(), String> {
    let sk = signing_key()?;
    let avatar = freebird_core::avatar::AvatarV1 {
        content_type,
        data,
        time: keys::now_ms(),
    };
    let authorized = freebird_core::avatar::AuthorizedAvatar::new(avatar, &sk);
    // Same check the contract runs — fail here with a real message instead
    // of a rejected update.
    freebird_core::avatar::check_avatar(&authorized, &sk.verifying_key())?;
    api::put_own_avatar(&sk.verifying_key(), &authorized).await?;
    AVATARS
        .write()
        .insert(sk.verifying_key().to_bytes(), Some(authorized));
    Ok(())
}

pub async fn set_follow(target: [u8; 32], follow: bool) -> Result<(), String> {
    let sk = signing_key()?;
    let current = own_feed().ok_or("feed not loaded")?;
    let mut follows = current.follows.follows.clone();
    let changed = if follow {
        follows.follows.insert(target)
    } else {
        follows.follows.remove(&target)
    };
    if !changed {
        return Ok(());
    }
    follows.version += 1;
    let authorized = AuthorizedFollows::new(follows, &sk);
    let mut delta = empty_delta();
    delta.follows = Some(authorized.clone());
    api::update_own_feed(delta).await?;
    if let Some(Some(state)) = FEEDS.write().get_mut(&own_author().unwrap()) {
        state.follows = authorized;
    }
    if follow {
        api::fetch_feed(target).await.ok();
        // Announce the follow into the target's inbox (#12). Best-effort
        // hint: their UI re-verifies against our signed follow list before
        // showing us. Anonymous accounts announce too (issue #23).
        let att = current.attestation.0.clone();
        let time = keys::now_ms();
        let announce_id = PostId::compute(&sk.verifying_key(), time, "follow", &None);
        if let Err(e) =
            send_inbox_pointer(&sk, att, target, FOLLOW_ANNOUNCE_TARGET, announce_id, time).await
        {
            api::log(&format!("follow announcement failed: {e}"));
        }
    }
    Ok(())
}

/// Toggle the public-directory listing (issue #11). Open to everyone
/// (issue #23): an attestation, when present, makes the listing uncrowdable;
/// anonymous listings share the bounded remainder. Delisting only stops the
/// refreshes — Freenet has no remove — so the entry ages out of the capped
/// set once others' activity evicts it.
pub async fn set_public_listing(on: bool) -> Result<(), String> {
    if on {
        let sk = signing_key()?;
        // Refuse to guess the tier while the feed is loading: publishing an
        // anonymous listing before our attestation arrives would demote a
        // verified author to the evictable tier until the next refresh.
        let att = own_feed().ok_or("feed not loaded")?.attestation.0;
        let listing = ListingV1 {
            author: sk.verifying_key().to_bytes(),
            last_active: keys::now_ms(),
        };
        // Anonymous listings must carry a proof-of-work stamp (issue #51);
        // attested listings skip it. Solve on the UI thread (see
        // send_inbox_pointer).
        //
        // Solve to the NEWER of the difficulty cell we track and the one the
        // directory state has already latched (issue #66) — gossip can carry
        // a raise into the directory before our cell subscription sees it,
        // and solving to the older one would just bounce the listing.
        let mut difficulty = POW_DIFFICULTY.read().clone();
        freebird_pow::adopt_difficulty(
            &mut difficulty,
            DIRECTORY
                .read()
                .as_ref()
                .and_then(|d| d.pow_difficulty.as_ref()),
        );
        let authorized = match att {
            Some(att) => AuthorizedListingV3::new(listing, &sk, Some(att)),
            None => {
                let bits = freebird_pow::difficulty_bits(difficulty.as_ref());
                AuthorizedListingV3::new_anon(listing, &sk, bits)
            }
        };
        api::put_directory_listing(&authorized, difficulty.clone()).await?;
        // Optimistic local apply so Discover shows us immediately.
        if let Some(dir) = DIRECTORY.write().as_mut() {
            let _ = dir.apply_delta(
                &keys::directory_params(),
                &directory_contract::DirectoryDeltaV3 {
                    listings: vec![authorized.clone()],
                    pow_difficulty: difficulty,
                },
            );
        }
    }
    api::kv_request(FreebirdDelegateRequest::Store {
        key: "public_listing".into(),
        value: (if on { "on" } else { "off" }).as_bytes().to_vec(),
    })
    .await?;
    *PUBLIC_LISTING.write() = Some(on);
    Ok(())
}

/// Nuke the account: delete the posting key from the delegate and drop all
/// local state. As close to "delete" as Freenet allows — the network has no
/// remove op, but a feed whose key is destroyed can never be updated again
/// and rots out of node caches once nothing renews its subscriptions.
pub async fn nuke_account() -> Result<(), String> {
    // Old delegate generations hold the seed too (issue #53): suppress the
    // probe so it can't resurrect the seed, then wipe them FIRST — a wipe
    // failure aborts the nuke with everything still intact.
    api::suppress_legacy_probe();
    #[cfg(target_arch = "wasm32")]
    api::wipe_legacy_seeds().await?;
    api::kv_request(FreebirdDelegateRequest::Delete {
        key: "posting_key".into(),
    })
    .await?;
    *ACCOUNT.write() = None;
    FEEDS.write().clear();
    LEGACY_FEEDS.write().clear();
    INBOXES.write().clear();
    *POSTING_KEY_LOADED.write() = Some(None);
    Ok(())
}

/// Start the check-mark flow: ask the ghostkey delegate to sign the
/// attestation payload. Completion arrives via GHOSTKEY_SIGN_RESULT.
pub async fn request_verification() -> Result<(), String> {
    let sk = signing_key()?;
    *GHOSTKEY_SIGN_RESULT.write() = None;
    api::ghostkey_request(GhostkeyRequest::SignWithDefault {
        message: AttestationV2::payload_for(&sk.verifying_key()),
    })
    .await
}

/// Finish the check-mark flow with the delegate's sign result.
pub async fn complete_verification(
    scoped_payload: Vec<u8>,
    signature: Vec<u8>,
    certificate_pem: String,
) -> Result<String, String> {
    let sk = signing_key()?;
    // The posting key counter-signs the ghost signature (issue #45): proof
    // of possession, without which the network rejects the attestation.
    let attestation =
        ghostkey::attestation_from_sign_result(scoped_payload, signature, &certificate_pem, &sk)?;
    // Verify locally against the real master key before publishing, so a
    // wrong-key vault answer surfaces as an error here, not a rejected update.
    let tier = attestation.verify(&sk.verifying_key(), None)?;
    let mut delta = empty_delta();
    delta.attestation = Some(attestation.clone());
    api::update_own_feed(delta).await?;
    if let Some(Some(state)) = FEEDS.write().get_mut(&own_author().unwrap()) {
        state.attestation = AttestationSlot(Some(attestation));
    }
    // A listed account that just verified upgrades its directory listing to
    // the attested (uncrowdable) tier. Best-effort.
    if *PUBLIC_LISTING.read() == Some(true) {
        if let Err(e) = set_public_listing(true).await {
            api::log(&format!("listing tier upgrade failed: {e}"));
        }
    }
    Ok(tier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use freebird_core::types::PostV1;

    /// A post signed the PRE-#47 way (bare CBOR) — what a v1 feed holds.
    fn legacy_post(sk: &SigningKey, time: u64, content: &str) -> AuthorizedPost {
        let post = PostV1 {
            id: PostId::compute(&sk.verifying_key(), time, content, &None),
            time,
            content: content.into(),
            in_reply_to: None,
        };
        let signature = sk.sign(&freebird_core::to_cbor(&post).unwrap());
        AuthorizedPost { post, signature }
    }

    #[test]
    fn migrated_posts_keep_their_ids_and_verify_under_v2() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let legacy = vec![legacy_post(&sk, 10, "one"), legacy_post(&sk, 20, "two")];
        // Precondition: the v1 signatures are exactly what v2 rejects.
        assert!(legacy[0].verify_signature(&sk.verifying_key()).is_err());

        let out = posts_to_migrate(&legacy, &PostsV1::default(), &sk);
        assert_eq!(out.len(), 2);
        for (a, b) in out.iter().zip(&legacy) {
            assert_eq!(a.post, b.post, "content and id must survive re-signing");
            a.verify_signature(&sk.verifying_key()).unwrap();
        }
    }

    /// Interrupted-migration recovery: a resumed run re-sends only what the
    /// v2 feed is still missing, and a completed one is a no-op.
    #[test]
    fn migration_resumes_without_redoing_landed_posts() {
        let sk = SigningKey::from_bytes(&[9; 32]);
        let legacy = vec![
            legacy_post(&sk, 10, "one"),
            legacy_post(&sk, 20, "two"),
            legacy_post(&sk, 30, "three"),
        ];
        // First attempt died after the first post landed in the v2 feed.
        let partial = PostsV1 {
            posts: vec![AuthorizedPost::new(legacy[0].post.clone(), &sk)],
        };
        let out = posts_to_migrate(&legacy, &partial, &sk);
        assert_eq!(
            out.iter().map(|p| p.post.time).collect::<Vec<_>>(),
            vec![20, 30]
        );

        let done = PostsV1 {
            posts: legacy
                .iter()
                .map(|p| AuthorizedPost::new(p.post.clone(), &sk))
                .collect(),
        };
        assert!(posts_to_migrate(&legacy, &done, &sk).is_empty());
    }

    fn profile(name: &str, version: u32) -> ProfileV1 {
        ProfileV1 {
            name: name.into(),
            bio: format!("{name}'s bio"),
            version,
        }
    }

    fn follow_list(follows: &[[u8; 32]], version: u32) -> FollowsV1 {
        FollowsV1 {
            follows: follows.iter().copied().collect(),
            version,
        }
    }

    /// A pre-#64 feed: profile and follows signed over BARE CBOR.
    fn legacy_feed(
        sk: &SigningKey,
        name: &str,
        pv: u32,
        follows: &[[u8; 32]],
        fv: u32,
    ) -> LegacyFeedState {
        use freebird_core::feed::legacy::{LegacyAttestationSlot, LegacyPosts};
        let p = profile(name, pv);
        let f = follow_list(follows, fv);
        LegacyFeedState {
            profile: AuthorizedProfile {
                signature: sk.sign(&freebird_core::to_cbor(&p).unwrap()),
                profile: p,
            },
            follows: AuthorizedFollows {
                signature: sk.sign(&freebird_core::to_cbor(&f).unwrap()),
                follows: f,
            },
            attestation: LegacyAttestationSlot(None),
            posts: LegacyPosts::default(),
        }
    }

    fn v2_feed(sk: &SigningKey, name: &str, pv: u32, follows: &[[u8; 32]], fv: u32) -> FeedStateV1 {
        FeedStateV1 {
            profile: AuthorizedProfile::new(profile(name, pv), sk),
            follows: AuthorizedFollows::new(follow_list(follows, fv), sk),
            attestation: AttestationSlot(None),
            posts: PostsV1::default(),
        }
    }

    /// Issue #82: the display name, bio and follow list must cross the v1→v2
    /// rotation. The v2 feed a rotation leaves behind is `seed_feed`'s empty
    /// version 0, so both records migrate — re-signed, since the #64 domain
    /// tags mean the v1 signatures no longer verify.
    #[test]
    fn migrated_identity_survives_the_rotation() {
        let sk = SigningKey::from_bytes(&[11; 32]);
        let vk = sk.verifying_key();
        let target = [4u8; 32];
        let legacy = legacy_feed(&sk, "alice", 2, &[target], 3);
        // Precondition: the v1 signatures are exactly what v2 rejects.
        assert!(legacy.profile.verify_signature(&vk).is_err());
        assert!(legacy.follows.verify_signature(&vk).is_err());
        // The rotated v2 feed: signed seed state, versioned below anything real.
        let current = v2_feed(&sk, "", 0, &[], 0);

        let (profile, follows) = identity_to_migrate(&legacy, &current, &sk);
        let profile = profile.expect("display name and bio migrate");
        let follows = follows.expect("follow list migrates");
        assert_eq!(profile.profile, legacy.profile.profile);
        assert_eq!(follows.follows, legacy.follows.follows);
        profile.verify_signature(&vk).unwrap();
        follows.verify_signature(&vk).unwrap();

        // Both are strictly newer than the seed, so the contract's LWW cannot
        // drop them — an equal-version tie is broken by content hash.
        use freenet_scaffold::ComposableState;
        let params = keys::feed_params(&vk);
        let mut live = current.clone();
        let clone = live.clone();
        live.apply_delta(
            &clone,
            &params,
            &Some(FeedStateV1Delta {
                profile: Some(profile),
                follows: Some(follows),
                attestation: None,
                posts: None,
            }),
        )
        .unwrap();
        assert_eq!(live.profile.profile.name, "alice");
        assert!(live.follows.follows.follows.contains(&target));
    }

    /// An edit made after the upgrade but before the migration ran outranks
    /// the legacy record and must not be rolled back to it.
    #[test]
    fn migration_never_rolls_back_a_newer_v2_record() {
        let sk = SigningKey::from_bytes(&[12; 32]);
        let legacy = legacy_feed(&sk, "alice", 2, &[[4u8; 32]], 3);
        let current = v2_feed(&sk, "alice-renamed", 2, &[], 4);
        assert_eq!(identity_to_migrate(&legacy, &current, &sk), (None, None));
    }
}
