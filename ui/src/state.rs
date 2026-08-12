//! Global UI state (Dioxus signals).

use std::collections::BTreeMap;

use dioxus::prelude::*;
use ed25519_dalek::SigningKey;
use freebird_core::feed::legacy::LegacyFeedState;
use freebird_core::feed::FeedStateV1;
use freebird_core::inbox::InboxStateV1;
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

/// The local account's posting key (None until onboarded).
pub static ACCOUNT: GlobalSignal<Option<SigningKey>> = Signal::global(|| None);

/// Feed states by author key. `None` value = requested, not yet arrived.
pub static FEEDS: GlobalSignal<BTreeMap<[u8; 32], Option<FeedStateV1>>> =
    Signal::global(BTreeMap::new);

/// LEGACY (pre-#64) feed states by author key — dual-read migration window
/// (issue #64 rotated the feed contract and changed its format in place).
/// `None` value = requested, not yet arrived. Read-only: posts here are
/// merged into the display; nothing writes back. Gated on `read_v1_feed`.
pub static LEGACY_FEEDS: GlobalSignal<BTreeMap<[u8; 32], Option<LegacyFeedState>>> =
    Signal::global(BTreeMap::new);

/// Inbox (v2) states by owner key.
pub static INBOXES: GlobalSignal<BTreeMap<[u8; 32], InboxStateV3>> =
    Signal::global(BTreeMap::new);

/// LEGACY (v1) inbox states by owner key — dual-read migration window
/// (issue #23): old attested pointers stay visible until the publisher
/// closes the window via the `read_v1_inbox` control flag.
pub static LEGACY_INBOXES: GlobalSignal<BTreeMap<[u8; 32], InboxStateV1>> =
    Signal::global(BTreeMap::new);

/// Per-author anchor cells (issue #23): role → current contract version and
/// address. `None` value = requested, not yet arrived (or absent).
pub static ANCHORS: GlobalSignal<BTreeMap<[u8; 32], Option<freebird_anchor::AnchorV1>>> =
    Signal::global(BTreeMap::new);

/// Avatars by author key. `None` value = fetched (or fetching) but absent —
/// render the identicon. Write-rarely contract: fetch-on-view, no
/// subscription, cached here for the session.
pub static AVATARS: GlobalSignal<BTreeMap<[u8; 32], Option<freebird_core::avatar::AuthorizedAvatar>>> =
    Signal::global(BTreeMap::new);

/// The public author directory, v2 (issue #11). None = not fetched yet.
pub static DIRECTORY: GlobalSignal<Option<directory_contract::DirectoryStateV3>> =
    Signal::global(|| None);

/// The LEGACY (v1) directory — dual-read migration window (issue #23).
pub static LEGACY_DIRECTORY: GlobalSignal<Option<directory_contract::legacy::LegacyDirectoryState>> =
    Signal::global(|| None);

/// Our "list me publicly" preference, delegate-persisted like the theme:
/// None = delegate not answered yet.
pub static PUBLIC_LISTING: GlobalSignal<Option<bool>> = Signal::global(|| None);

/// The publisher's control record (latest deployed build + feature flags).
/// None = not arrived / not decodable — behave as if no control exists.
pub static CONTROL: GlobalSignal<Option<freebird_control::ControlV1>> = Signal::global(|| None);

/// Highest build the user dismissed the update banner for. None until the
/// delegate answers (the banner waits, so it never flashes pre-dismissal).
pub static DISMISSED_BUILD: GlobalSignal<Option<u64>> = Signal::global(|| None);

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

/// Latest ghostkey-delegate sign flow result:
/// Ok((scoped_payload, signature, certificate_pem)) or Err(user message).
pub static GHOSTKEY_SIGN_RESULT: GlobalSignal<Option<Result<(Vec<u8>, Vec<u8>, String), String>>> =
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
                let author = bs58::decode(parts.next()?).into_vec().ok()?.try_into().ok()?;
                let post = bs58::decode(parts.next()?).into_vec().ok()?.try_into().ok()?;
                Some(View::Thread(freebird_core::types::PostRef {
                    author,
                    post: freebird_core::types::PostId(post),
                }))
            })()
            .unwrap_or(View::Home),
            Some("author") => (|| {
                let author = bs58::decode(parts.next()?).into_vec().ok()?.try_into().ok()?;
                Some(View::Author(author))
            })()
            .unwrap_or(View::Home),
            _ => View::Home,
        }
    }
}

pub static VIEW: GlobalSignal<View> = Signal::global(View::default);

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
/// the flag unset. The v1 dual-read window is gated on `read_v1_inbox` /
/// `read_v1_directory` (default ON) so the publisher can close it network-
/// wide once the migration completes.
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
