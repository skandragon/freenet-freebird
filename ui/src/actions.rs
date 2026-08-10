//! User-intent actions: onboard, post, follow, verify. Bridge between views
//! and the api layer; every action signs locally with the posting key.

use dioxus::prelude::*;
use directory_contract::{AuthorizedListingV2, ListingV1};
use ed25519_dalek::{SigningKey, VerifyingKey};
use freebird_core::attestation::AttestationV1;
use freebird_core::delegate_api::FreebirdDelegateRequest;
use freebird_core::feed::{AttestationSlot, FeedStateV1, FeedStateV1Delta, PostsV1};
use freebird_core::types::{
    AuthorizedFollows, AuthorizedProfile, FollowsV1, PostId, PostRef, ProfileV1,
};
use inbox_contract::state::{
    AuthorizedReplyPointerV2, InboxStateV2Delta, ReplierCredV2, ReplyPointerV2,
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
    *ACCOUNT.write() = Some(sk);
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
    api::fetch_feed(author).await?;
    // Owner-republish half of the #23 migration, best-effort and idempotent:
    // make sure our v2 inbox exists (an account created pre-rotation never
    // PUT it) and (re)publish the anchor cell pointing at it.
    if let Err(e) = api::ensure_own_inbox(&vk).await {
        api::log(&format!("v2 inbox republish failed: {e}"));
    }
    if let Err(e) = api::publish_anchor(&sk).await {
        api::log(&format!("anchor publish failed: {e}"));
    }
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
    let post = keys::make_post(&sk, content, in_reply_to);
    let mut delta = empty_delta();
    delta.posts = Some(vec![post.clone()]);
    api::update_own_feed(delta).await?;

    // Optimistic local apply so the timeline updates immediately.
    apply_own_posts(vec![post.clone()]);

    if let Some(target) = in_reply_to {
        let att = own_feed().and_then(|f| f.attestation.0);
        send_inbox_pointer(&sk, att, target.author, target.post, post.post.id, post.post.time)
            .await?;
    }
    Ok(())
}

/// Drop a pointer into `target_author`'s inbox: a reply pointer, or a follow
/// announcement when `target_post` is FOLLOW_ANNOUNCE_TARGET. `attestation`
/// picks the slot tier (attested = uncrowdable, None = anonymous share).
async fn send_inbox_pointer(
    sk: &SigningKey,
    attestation: Option<AttestationV1>,
    target_author: [u8; 32],
    target_post: PostId,
    reply_post: PostId,
    time: u64,
) -> Result<(), String> {
    let replier = sk.verifying_key().to_bytes();
    let cred = ReplierCredV2 {
        posting_key: sk.verifying_key(),
        attestation,
    };
    let ptr = ReplyPointerV2 {
        replier,
        fingerprint: cred.fingerprint(),
        target_post,
        reply_post,
        time,
    };
    let authorized = AuthorizedReplyPointerV2::new(ptr, sk);
    let delta = InboxStateV2Delta {
        creds: Some([(replier, cred)].into_iter().collect()),
        pointers: Some(vec![authorized]),
    };
    api::update_inbox(target_author, delta).await
}

fn apply_own_posts(posts: Vec<freebird_core::types::AuthorizedPost>) {
    let Some(author) = own_author() else { return };
    let Ok(vk) = VerifyingKey::from_bytes(&author) else { return };
    let params = keys::feed_params(&vk);
    if let Some(Some(state)) = FEEDS.write().get_mut(&author) {
        use freenet_scaffold::ComposableState;
        let mut delta = empty_delta();
        delta.posts = Some(posts);
        let clone = state.clone();
        let _ = state.apply_delta(&clone, &params, &Some(delta));
    }
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
        let att = own_feed().and_then(|f| f.attestation.0);
        let listing = ListingV1 {
            author: sk.verifying_key().to_bytes(),
            last_active: keys::now_ms(),
        };
        let authorized = AuthorizedListingV2::new(listing, &sk, att);
        api::put_directory_listing(&authorized).await?;
        // Optimistic local apply so Discover shows us immediately.
        if let Some(dir) = DIRECTORY.write().as_mut() {
            let _ = dir.apply_delta(&keys::directory_params(), std::slice::from_ref(&authorized));
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
    api::kv_request(FreebirdDelegateRequest::Delete {
        key: "posting_key".into(),
    })
    .await?;
    *ACCOUNT.write() = None;
    FEEDS.write().clear();
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
        message: AttestationV1::payload_for(&sk.verifying_key()),
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
    let attestation =
        ghostkey::attestation_from_sign_result(scoped_payload, signature, &certificate_pem)?;
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
