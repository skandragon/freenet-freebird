//! Global UI state (Dioxus signals).

use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use freebird_core::feed::legacy::LegacyFeedState;
use freebird_core::feed::FeedStateV1;
use freebird_core::types::{FollowsV1, ProfileV1};
use freenet_stdlib::client_api::WebApi;
use inbox_contract::state::InboxStateV3;

#[derive(Clone, PartialEq, Debug, Default)]
pub enum SyncStatus {
    #[default]
    Connecting,
    Connected,
    Error(String),
}

pub static WEB_API: GlobalSignal<Option<WebApi>> = Signal::global(|| None);
pub static SYNC_STATUS: GlobalSignal<SyncStatus> = Signal::global(SyncStatus::default);

/// Last failure the node reported for a write to our OWN feed (issue #79).
/// Writes are fire-and-forget — `send` returns Ok once the request is on the
/// socket — so without this a rejected post clears the compose box and looks
/// like a success.
pub static FEED_WRITE_ERROR: GlobalSignal<Option<String>> = Signal::global(|| None);

/// The local account's posting key (None until onboarded).
pub static ACCOUNT: GlobalSignal<Option<SigningKey>> = Signal::global(|| None);

/// Feed states by author key. `None` value = requested, not yet arrived.
pub static FEEDS: GlobalSignal<BTreeMap<[u8; 32], Option<FeedStateV1>>> =
    Signal::global(BTreeMap::new);

/// LEGACY (pre-#64) feed states by author key — dual-read migration window
/// (issue #64 rotated the feed contract and changed its format in place).
/// `None` value = requested, not yet arrived. Never written back to the legacy
/// contract; our OWN entry is the source for the forward migration (#56,
/// `actions::migrate_v1`), which re-signs it into the v2 feed. Gated on
/// `read_v1_feed`.
pub static LEGACY_FEEDS: GlobalSignal<BTreeMap<[u8; 32], Option<LegacyFeedState>>> =
    Signal::global(BTreeMap::new);

/// Inbox (v2) states by owner key.
pub static INBOXES: GlobalSignal<BTreeMap<[u8; 32], InboxStateV3>> = Signal::global(BTreeMap::new);

/// LEGACY inbox states by owner key — dual-read migration window (issues
/// #23, #81): pointers written against the LIVE build stay visible until the
/// publisher closes the window via the `read_v1_inbox` control flag.
pub static LEGACY_INBOXES: GlobalSignal<BTreeMap<[u8; 32], crate::legacy::LegacyInboxState>> =
    Signal::global(BTreeMap::new);

/// Per-author anchor cells (issue #23): role → current contract version and
/// address. `None` value = requested, not yet arrived (or absent).
pub static ANCHORS: GlobalSignal<BTreeMap<[u8; 32], Option<freebird_anchor::AnchorV1>>> =
    Signal::global(BTreeMap::new);

/// Avatars by author key. `None` value = fetched (or fetching) but absent —
/// render the identicon. Write-rarely contract: fetch-on-view, no
/// subscription, cached here for the session.
pub static AVATARS: GlobalSignal<
    BTreeMap<[u8; 32], Option<freebird_core::avatar::AuthorizedAvatar>>,
> = Signal::global(BTreeMap::new);

/// LEGACY avatars by author key — dual-read migration window (issue #81).
/// Kept SEPARATE from `AVATARS` rather than merged into it: the rendering
/// fallback needs "we have only a legacy blob" to stay distinguishable, or
/// `migrate_avatar` cannot tell whether it still owes a re-signed upload.
pub static LEGACY_AVATARS: GlobalSignal<
    BTreeMap<[u8; 32], Option<freebird_core::avatar::AuthorizedAvatar>>,
> = Signal::global(BTreeMap::new);

/// The public author directory, v2 (issue #11). None = not fetched yet.
pub static DIRECTORY: GlobalSignal<Option<directory_contract::DirectoryStateV4>> =
    Signal::global(|| None);

/// The LEGACY directory — dual-read migration window (issues #23, #81).
pub static LEGACY_DIRECTORY: GlobalSignal<Option<crate::legacy::LegacyDirectoryState>> =
    Signal::global(|| None);

/// Our "list me publicly" preference, delegate-persisted like the theme:
/// None = delegate not answered yet.
pub static PUBLIC_LISTING: GlobalSignal<Option<bool>> = Signal::global(|| None);

/// The publisher's control record (latest deployed build + feature flags).
/// None = not arrived / not decodable — behave as if no control exists.
pub static CONTROL: GlobalSignal<Option<freebird_control::ControlV1>> = Signal::global(|| None);

/// The publisher's anonymous-PoW difficulty record (issue #66). We solve to
/// its bits AND attach it to our writes, which is how a raise reaches the
/// state of the contracts it governs. None = never arrived → the compiled
/// floor, which is what `difficulty_bits(None)` returns.
pub static POW_DIFFICULTY: GlobalSignal<Option<cell_contract::SignedCellV1>> =
    Signal::global(|| None);

/// Highest build the user dismissed the update banner for. None until the
/// delegate answers (the banner waits, so it never flashes pre-dismissal).
pub static DISMISSED_BUILD: GlobalSignal<Option<u64>> = Signal::global(|| None);

/// Delegate key holding the one-time v1→v2 forward-migration marker (#56).
pub const V1_MIGRATION_KEY: &str = "v1_migration";

/// State of this account's one-time v1→v2 forward migration (issue #56),
/// persisted in the delegate under [`V1_MIGRATION_KEY`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum V1Migration {
    /// Not confirmed complete: run it.
    ///
    /// There is deliberately no in-progress state (issue #91). The only
    /// thing the old `Running(started_ms)` stamp bought was a stable
    /// `PostId` for the follow announcements across a resumed run, and its
    /// Store was fire-and-forget — a dropped marker minted a fresh id and
    /// left a duplicate "followed you" pointer in every followed author's
    /// inbox. `actions::MIGRATION_ANNOUNCE_MS` derives that id from a
    /// constant instead, so nothing needs the stamp.
    Pending,
    /// Every write landed; never runs again.
    Done,
}

impl V1Migration {
    /// Anything but `done` = run it: the migration is idempotent, so
    /// re-running is always safer than skipping. That includes a pre-#91
    /// in-progress stamp, which is a bare number.
    pub fn decode(value: Option<&[u8]>) -> Self {
        match value.and_then(|v| std::str::from_utf8(v).ok()) {
            Some("done") => Self::Done,
            _ => Self::Pending,
        }
    }
}

/// None until the delegate answers.
pub static V1_MIGRATION: GlobalSignal<Option<V1Migration>> = Signal::global(|| None);

/// Result of asking the freebird delegate for `posting_key`:
/// None = not answered yet; Some(None) = no account stored (onboard);
/// Some(Some(seed)) = existing account.
pub static POSTING_KEY_LOADED: GlobalSignal<Option<Option<Vec<u8>>>> = Signal::global(|| None);

/// The carry-forward probe of old delegate generations (issue #53) is still
/// running: hold the account gate on Loading so onboarding can't create a
/// fresh account over a seed the probe is about to find.
pub static LEGACY_PROBE_PENDING: GlobalSignal<bool> = Signal::global(|| false);

/// The carry-forward probe errored or timed out with old generations still
/// unanswered — "no stored seed" is then unproven, so onboarding warns
/// instead of silently offering a fresh account.
pub static LEGACY_PROBE_FAILED: GlobalSignal<bool> = Signal::global(|| false);

/// The posting_key answer will never arrive: either the startup watchdog
/// timed out, or a second empty freebird-delegate response proved the node
/// is swallowing delegate errors (e.g. an unattested WebSocket after a node
/// restart or behind a proxy). Drives an explanatory error screen instead
/// of an eternal spinner.
pub static KEY_STORE_UNREACHABLE: GlobalSignal<bool> = Signal::global(|| false);

/// Ok((scoped_payload, signature, certificate_pem)) or Err(user message).
pub type GhostkeySignResult = Result<(Vec<u8>, Vec<u8>, String), String>;

/// Latest ghostkey-delegate sign flow result.
pub static GHOSTKEY_SIGN_RESULT: GlobalSignal<Option<GhostkeySignResult>> =
    Signal::global(|| None);
pub static GHOSTKEY_HAS_IDENTITY: GlobalSignal<Option<bool>> = Signal::global(|| None);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Theme {
    #[default]
    Auto,
    Light,
    Dark,
}

impl Theme {
    pub fn label(self) -> &'static str {
        match self {
            Theme::Auto => "auto",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
    pub fn next(self) -> Theme {
        match self {
            Theme::Auto => Theme::Light,
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Auto,
        }
    }
}

impl Theme {
    pub fn from_label(s: &str) -> Theme {
        match s {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::Auto,
        }
    }
}

// The app runs in an opaque-origin sandbox iframe: localStorage throws, so
// the theme persists in the freebird delegate (next to posting_key).
pub static THEME: GlobalSignal<Theme> = Signal::global(Theme::default);

/// Set (or clear, for Auto) the data-theme attribute the CSS keys off.
/// Persistence goes through the delegate; callers own that side.
pub fn apply_theme(theme: Theme) {
    *THEME.write() = theme;
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(root) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.document_element())
        {
            match theme {
                Theme::Auto => {
                    let _ = root.remove_attribute("data-theme");
                }
                _ => {
                    let _ = root.set_attribute("data-theme", theme.label());
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum View {
    #[default]
    Home,
    Profile,
    Discover,
    Thread(freebird_core::types::PostRef),
    Author([u8; 32]),
}

impl View {
    /// Canonical location.hash for this view (issue #2).
    pub fn to_hash(self) -> String {
        match self {
            View::Home => "#/".into(),
            View::Profile => "#/profile".into(),
            View::Discover => "#/discover".into(),
            View::Thread(r) => format!(
                "#/thread/{}/{}",
                bs58::encode(r.author).into_string(),
                bs58::encode(r.post.0).into_string()
            ),
            View::Author(a) => format!("#/author/{}", bs58::encode(a).into_string()),
        }
    }

    /// Parse a location.hash; anything unrecognized is Home.
    pub fn from_hash(hash: &str) -> View {
        let mut parts = hash.trim_start_matches(['#', '/']).split('/');
        match parts.next() {
            Some("profile") => View::Profile,
            Some("discover") => View::Discover,
            Some("thread") => (|| {
                let author = bs58::decode(parts.next()?)
                    .into_vec()
                    .ok()?
                    .try_into()
                    .ok()?;
                let post = bs58::decode(parts.next()?)
                    .into_vec()
                    .ok()?
                    .try_into()
                    .ok()?;
                Some(View::Thread(freebird_core::types::PostRef {
                    author,
                    post: freebird_core::types::PostId(post),
                }))
            })()
            .unwrap_or(View::Home),
            Some("author") => (|| {
                let author = bs58::decode(parts.next()?)
                    .into_vec()
                    .ok()?
                    .try_into()
                    .ok()?;
                Some(View::Author(author))
            })()
            .unwrap_or(View::Home),
            _ => View::Home,
        }
    }
}

pub static VIEW: GlobalSignal<View> = Signal::global(View::default);

// Items follow this module; moving them above it would be pure churn.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let thread = View::Thread(freebird_core::types::PostRef {
            author: [7; 32],
            post: freebird_core::types::PostId([9; 16]),
        });
        for v in [View::Home, View::Profile, thread, View::Author([3; 32])] {
            assert_eq!(View::from_hash(&v.to_hash()), v);
        }
        assert_eq!(View::from_hash(""), View::Home);
        assert_eq!(View::from_hash("#follow=abc"), View::Home);
        assert_eq!(View::from_hash("#/thread/junk"), View::Home);
        assert_eq!(View::from_hash("#/author/junk"), View::Home);
    }

    #[test]
    fn migration_marker_decode() {
        assert_eq!(V1Migration::decode(None), V1Migration::Pending);
        assert_eq!(V1Migration::decode(Some(b"done")), V1Migration::Done);
        // A pre-#91 in-progress stamp: re-runs, and now re-derives the same
        // announcement ids while doing it.
        assert_eq!(V1Migration::decode(Some(b"1700")), V1Migration::Pending);
        // Garbage re-runs the (idempotent) migration rather than skipping it.
        assert_eq!(V1Migration::decode(Some(b"")), V1Migration::Pending);
        assert_eq!(V1Migration::decode(Some(b"\xff\xfe")), V1Migration::Pending);
    }
}

/// The Identity Vault's current delegate key, auto-discovered at startup
/// from the vault webapp's published `delegate-key.json` (never hardcoded —
/// freenet/ghostkeys#21). None until discovery completes; stays None if the
/// vault app isn't reachable on this node.
pub static GHOSTKEY_DELEGATE: GlobalSignal<Option<freenet_stdlib::prelude::DelegateKey>> =
    Signal::global(|| None);

/// Author key from a ?follow= link the page was opened with.
pub static PENDING_FOLLOW: GlobalSignal<Option<[u8; 32]>> = Signal::global(|| None);

/// A control-cell feature flag, defaulting when control state is absent or
/// the flag unset. The dual-read window is gated per role on `read_v1_feed`
/// / `read_v1_inbox` / `read_v1_directory` / `read_v1_avatar` (default ON)
/// so the publisher can close each one network-wide once enough clients have
/// run the forward migration (issues #56, #81; `actions::migrate_v1`,
/// `actions::migrate_avatar`). See docs/dual-read-window.md for what
/// terminates each window.
pub fn flag_bool(name: &str, default: bool) -> bool {
    CONTROL
        .read()
        .as_ref()
        .map(|c| c.flag_bool(name, default))
        .unwrap_or(default)
}

pub fn own_author() -> Option<[u8; 32]> {
    ACCOUNT
        .read()
        .as_ref()
        .map(|sk| sk.verifying_key().to_bytes())
}

/// Has this v2 record been written since the rotation? Version 0 is exactly
/// the untouched seed — `api::seed_feed` is its only writer, `create_account`
/// starts at 1, and every later write is `current + 1`.
pub fn written_since_rotation(version: u32) -> bool {
    version > 0
}

/// An author's effective profile during the dual-read window: their v2 record
/// once they have written one, else the legacy (pre-#64) one.
///
/// Identity has no fallback of its own the way posts do (`legacy_posts`), so
/// without this a v1 account reads back as a blank name and empty bio until
/// `migrate_v1` lands — which is what prompts people to retype their name over
/// the empty seed, racing the migration. The gate matches
/// `actions::identity_to_migrate`'s, so nothing shifts under the user when the
/// migration finally runs.
pub fn effective_profile(author: &[u8; 32]) -> Option<ProfileV1> {
    let v2 = FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.profile.profile.clone());
    match &v2 {
        Some(p) if written_since_rotation(p.version) => v2,
        _ => LEGACY_FEEDS
            .read()
            .get(author)
            .and_then(|f| f.as_ref())
            .map(|f| f.profile.profile.clone())
            .or(v2),
    }
}

/// An author's effective follow list, on the same rule as [`effective_profile`].
///
/// Load-bearing for writes as well as display: `actions::set_follow` starts
/// from this set, so the first post-rotation follow or unfollow folds the
/// legacy list into v2 instead of writing a one-entry list over it.
pub fn effective_follows(author: &[u8; 32]) -> BTreeSet<[u8; 32]> {
    let v2 = FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.follows.follows.clone());
    let legacy = LEGACY_FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.follows.follows.clone());
    follows_of(v2.as_ref(), legacy.as_ref())
}

/// The precedence rule behind [`effective_follows`], as a pure function over
/// the two signed lists so callers that already hold the maps borrowed
/// (`views::confirmed_followers`) apply exactly the same rule. Both lists are
/// author-signed and verified at ingest, so either is trustworthy; what the
/// rule decides is *which* one is current — a migrated author's v2 list wins,
/// so an unfollow made after migrating is not undone by the stale legacy list.
pub fn follows_of(v2: Option<&FollowsV1>, legacy: Option<&FollowsV1>) -> BTreeSet<[u8; 32]> {
    match v2 {
        Some(f) if written_since_rotation(f.version) => f.follows.clone(),
        _ => legacy
            .map(|f| f.follows.clone())
            .unwrap_or_else(|| v2.map(|f| f.follows.clone()).unwrap_or_default()),
    }
}
