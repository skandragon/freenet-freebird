//! UI components. One file — the MVP surface is small.

use dioxus::prelude::*;
use freebird_core::feed::FeedStateV1;
use freebird_core::types::{AuthorizedPost, PostRef};

use crate::actions;
use crate::api;
use crate::keys;
use crate::state::*;

/// The app's own base URL (path through the contract id, no query/hash).
#[cfg(target_arch = "wasm32")]
fn app_base_url() -> String {
    web_sys::window()
        .map(|w| {
            let l = w.location();
            format!(
                "{}{}",
                l.origin().unwrap_or_default(),
                l.pathname().unwrap_or_default()
            )
        })
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn app_base_url() -> String {
    String::new()
}

/// Mirror the current route onto the shell page's address bar.
///
/// Under Freenet the app runs in a sandboxed iframe; our in-app anchors carry
/// `data-freenet-no-intercept` so hash navigation stays inside the iframe
/// (the shell's navigate path would reload the whole app — issue: logo click
/// refreshes the page). The trade-off is the outer URL no longer follows, so
/// we post the shell's `hash` message, which replaceStates the fragment onto
/// the outer address bar without touching the iframe.
#[cfg(target_arch = "wasm32")]
fn sync_shell_hash(hash: &str) {
    let Some(win) = web_sys::window() else { return };
    // Top-level (no shell): the address bar is ours already.
    let Ok(Some(parent)) = win.parent() else { return };
    if parent == win {
        return;
    }
    let msg = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&msg, &"__freenet_shell__".into(), &true.into());
    let _ = js_sys::Reflect::set(&msg, &"type".into(), &"hash".into());
    let _ = js_sys::Reflect::set(&msg, &"hash".into(), &hash.into());
    let _ = parent.post_message(&msg, "*");
}

/// Shareable "this is me, follow me" link.
pub fn follow_link(author: &[u8; 32]) -> String {
    format!("{}?follow={}", app_base_url(), bs58::encode(author).into_string())
}

/// Parse ?follow=<addr> (also accepted in the fragment) from the page URL.
#[cfg(target_arch = "wasm32")]
fn parse_follow_param() -> Option<[u8; 32]> {
    let l = web_sys::window()?.location();
    let mut haystack = l.search().unwrap_or_default();
    haystack.push('&');
    haystack.push_str(&l.hash().unwrap_or_default());
    let start = haystack.find("follow=")? + "follow=".len();
    let rest = &haystack[start..];
    let end = rest.find(['&', '#']).unwrap_or(rest.len());
    bs58::decode(&rest[..end]).into_vec().ok()?.try_into().ok()
}

pub fn short_key(author: &[u8; 32]) -> String {
    let full = bs58::encode(author).into_string();
    full.chars().take(8).collect()
}

/// Stable diff key for a post rendered in a list. Without keys Dioxus diffs
/// positionally, so open reply/thread state sticks to the slot, not the post.
fn post_key(author: &[u8; 32], id: &freebird_core::types::PostId) -> String {
    format!("{}:{}", bs58::encode(author).into_string(), bs58::encode(id.0).into_string())
}

fn author_name(author: &[u8; 32]) -> String {
    FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.profile.profile.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| short_key(author))
}

#[cfg(target_arch = "wasm32")]
async fn copy_to_clipboard(text: String) -> Result<(), String> {
    let nav = web_sys::window().ok_or("no window")?.navigator();
    wasm_bindgen_futures::JsFuture::from(nav.clipboard().write_text(&text))
        .await
        .map(|_| ())
        .map_err(|_| "clipboard write failed".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn copy_to_clipboard(_text: String) -> Result<(), String> {
    Err("clipboard unavailable".to_string())
}

/// A link-style button that copies `text` and confirms inline.
#[component]
fn CopyButton(text: String, label: String) -> Element {
    // None = idle, Some(true) = copied, Some(false) = failed.
    let mut state = use_signal(|| None::<bool>);
    rsx! {
        button { class: "link",
            onclick: move |_| {
                let value = text.clone();
                spawn(async move {
                    let ok = copy_to_clipboard(value).await.is_ok();
                    state.set(Some(ok));
                    crate::sleep_ms(1500).await;
                    state.set(None);
                });
            },
            match *state.read() {
                Some(true) => "copied ✓".to_string(),
                Some(false) => "copy failed".to_string(),
                None => label.clone(),
            }
        }
    }
}

/// Deterministic per-author color chip: two hues derived from the key.
fn identicon_style(author: &[u8; 32]) -> String {
    let h1 = (((author[0] as u16) << 8 | author[1] as u16) % 360) as u16;
    let h2 = (h1 + 40 + (author[2] % 140) as u16) % 360;
    format!("background: linear-gradient(135deg, hsl({h1},65%,55%), hsl({h2},65%,38%))")
}

/// Profile picture with the identicon as fallback while loading or absent.
/// Fetches the author's avatar contract on first view (session-cached).
#[component]
fn Avatar(author: [u8; 32], #[props(default)] lg: bool) -> Element {
    use_effect(move || {
        if !AVATARS.read().contains_key(&author) {
            spawn(async move {
                let _ = api::fetch_avatar(author).await;
            });
        }
    });
    let src = AVATARS.read().get(&author).cloned().flatten().map(|a| {
        use base64::Engine;
        format!(
            "data:{};base64,{}",
            a.avatar.content_type,
            base64::engine::general_purpose::STANDARD.encode(&a.avatar.data)
        )
    });
    let class = if lg { "avatar lg" } else { "avatar" };
    match src {
        Some(src) => rsx! { img { class: class, src: src, alt: "" } },
        None => rsx! { span { class: class, style: identicon_style(&author) } },
    }
}

/// Center-crop to a square, downscale to ≤256px, re-encode as JPEG so any
/// normal photo lands under the avatar contract's size cap.
#[cfg(target_arch = "wasm32")]
async fn shrink_to_avatar(bytes: Vec<u8>) -> Result<(String, Vec<u8>), String> {
    use base64::Engine;
    use wasm_bindgen::JsCast;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let mime = freebird_core::avatar::sniff_mime(&bytes)
        .ok_or("not a png, jpeg, webp, or gif image")?;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let img: web_sys::HtmlImageElement = document
        .create_element("img")
        .map_err(|_| "create img")?
        .dyn_into()
        .map_err(|_| "img cast")?;
    img.set_src(&format!("data:{mime};base64,{}", b64.encode(&bytes)));
    wasm_bindgen_futures::JsFuture::from(img.decode())
        .await
        .map_err(|_| "image failed to decode")?;
    let (w, h) = (img.natural_width(), img.natural_height());
    if w == 0 || h == 0 {
        return Err("empty image".into());
    }
    let side = w.min(h);
    let out = side.min(256);
    let canvas: web_sys::HtmlCanvasElement = document
        .create_element("canvas")
        .map_err(|_| "create canvas")?
        .dyn_into()
        .map_err(|_| "canvas cast")?;
    canvas.set_width(out);
    canvas.set_height(out);
    let ctx: web_sys::CanvasRenderingContext2d = canvas
        .get_context("2d")
        .ok()
        .flatten()
        .ok_or("no 2d context")?
        .dyn_into()
        .map_err(|_| "context cast")?;
    ctx.draw_image_with_html_image_element_and_sw_and_sh_and_dx_and_dy_and_dw_and_dh(
        &img,
        ((w - side) / 2) as f64,
        ((h - side) / 2) as f64,
        side as f64,
        side as f64,
        0.0,
        0.0,
        out as f64,
        out as f64,
    )
    .map_err(|_| "draw failed")?;
    // JPEG: the one canvas encoder every browser honors with a quality knob.
    let url = canvas
        .to_data_url_with_type_and_encoder_options("image/jpeg", &wasm_bindgen::JsValue::from_f64(0.85))
        .map_err(|_| "encode failed")?;
    let data = b64
        .decode(
            url.strip_prefix("data:image/jpeg;base64,")
                .ok_or("unexpected canvas output")?,
        )
        .map_err(|e| format!("decode canvas output: {e}"))?;
    if data.len() > freebird_core::avatar::MAX_AVATAR_BYTES {
        return Err("image too large even after resizing".into());
    }
    Ok(("image/jpeg".into(), data))
}

#[cfg(not(target_arch = "wasm32"))]
async fn shrink_to_avatar(_bytes: Vec<u8>) -> Result<(String, Vec<u8>), String> {
    Err("image processing unavailable".into())
}

fn is_verified(author: &[u8; 32]) -> bool {
    FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.attestation.0.is_some())
        .unwrap_or(false)
}

/// One inbox pointer (reply or follow announcement), abstracted over the v2
/// inbox and the legacy v1 inbox read during the migration window (#23).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InboxPointer {
    replier: [u8; 32],
    target_post: freebird_core::types::PostId,
    reply_post: freebird_core::types::PostId,
    time: u64,
}

/// All pointers in `owner`'s inbox(es): v2 first, then legacy v1, deduped by
/// (replier, reply_post) — the same reply pointer present in both
/// generations counts once. Signatures are verified at ingest in `api.rs`
/// (the contract-grade merge/apply runs client-side for both generations);
/// this helper only re-checks referential integrity — a pointer whose
/// credential is absent is not trusted.
fn merged_pointers(owner: &[u8; 32]) -> Vec<InboxPointer> {
    let v2: Vec<InboxPointer> = INBOXES
        .read()
        .get(owner)
        .map(|inbox| {
            inbox
                .pointers
                .pointers
                .iter()
                .filter(|p| inbox.creds.creds.contains_key(&p.ptr.replier))
                .map(|p| InboxPointer {
                    replier: p.ptr.replier,
                    target_post: p.ptr.target_post,
                    reply_post: p.ptr.reply_post,
                    time: p.ptr.time,
                })
                .collect()
        })
        .unwrap_or_default();
    let v1: Vec<InboxPointer> = LEGACY_INBOXES
        .read()
        .get(owner)
        .map(|inbox| {
            inbox
                .pointers
                .pointers
                .iter()
                .filter(|p| inbox.creds.creds.contains_key(&p.ptr.replier))
                .map(|p| InboxPointer {
                    replier: p.ptr.replier,
                    target_post: p.ptr.target_post,
                    reply_post: p.ptr.reply_post,
                    time: p.ptr.time,
                })
                .collect()
        })
        .unwrap_or_default();
    dedup_generations(v2, v1)
}

/// Pure half of the dual-read merge: v2 wins, and the same reply pointer
/// present in both generations counts once. A regression here doubles every
/// migrated user's reply counts.
fn dedup_generations(v2: Vec<InboxPointer>, v1: Vec<InboxPointer>) -> Vec<InboxPointer> {
    let mut out: Vec<InboxPointer> = Vec::new();
    let mut seen: std::collections::BTreeSet<([u8; 32], freebird_core::types::PostId)> =
        Default::default();
    for p in v2.into_iter().chain(v1) {
        if seen.insert((p.replier, p.reply_post)) {
            out.push(p);
        }
    }
    out
}

/// Ancestors of a post, walked up `in_reply_to` through loaded feeds and
/// returned root-first. The second value is the first parent the walk could
/// not resolve (feed or post not loaded yet) — the caller fetches that feed
/// and re-renders. A reference cycle terminates the walk instead of looping.
fn ancestor_chain(
    feeds: &std::collections::BTreeMap<[u8; 32], Option<FeedStateV1>>,
    start: Option<PostRef>,
) -> (Vec<([u8; 32], AuthorizedPost)>, Option<PostRef>) {
    let mut chain: Vec<([u8; 32], AuthorizedPost)> = Vec::new();
    let mut seen: std::collections::BTreeSet<([u8; 32], freebird_core::types::PostId)> =
        Default::default();
    let mut cursor = start;
    let mut unresolved = None;
    while let Some(r) = cursor {
        if !seen.insert((r.author, r.post)) {
            break;
        }
        let found = feeds
            .get(&r.author)
            .and_then(|f| f.as_ref())
            .and_then(|f| f.posts.posts.iter().find(|p| p.post.id == r.post).cloned());
        match found {
            Some(post) => {
                cursor = post.post.in_reply_to;
                chain.push((r.author, post));
            }
            None => {
                unresolved = Some(r);
                break;
            }
        }
    }
    chain.reverse();
    (chain, unresolved)
}

fn ago(time: u64) -> String {
    let now = keys::now_ms();
    let delta_s = now.saturating_sub(time) / 1000;
    match delta_s {
        0..=59 => format!("{delta_s}s"),
        60..=3599 => format!("{}m", delta_s / 60),
        3600..=86399 => format!("{}h", delta_s / 3600),
        _ => format!("{}d", delta_s / 86400),
    }
}

#[component]
pub fn App() -> Element {
    use_effect(|| {
        let theme = THEME.peek().clone();
        apply_theme(theme);
        #[cfg(target_arch = "wasm32")]
        {
            *PENDING_FOLLOW.write() = parse_follow_param();
            // Hash routing (issue #2): adopt the load-time hash, then track
            // back/forward via hashchange.
            if let Some(w) = web_sys::window() {
                *VIEW.write() = View::from_hash(&w.location().hash().unwrap_or_default());
                use wasm_bindgen::JsCast;
                let on_hash = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(|| {
                    if let Some(w) = web_sys::window() {
                        *VIEW.write() = View::from_hash(&w.location().hash().unwrap_or_default());
                    }
                });
                w.set_onhashchange(Some(on_hash.as_ref().unchecked_ref()));
                on_hash.forget();
            }
        }
        spawn(async {
            #[cfg(target_arch = "wasm32")]
            {
                if let Err(e) = api::connect().await {
                    *SYNC_STATUS.write() = SyncStatus::Error(e);
                    return;
                }
                // Wait for the socket to open before registering.
                while *SYNC_STATUS.read() == SyncStatus::Connecting {
                    crate::sleep_ms(100).await;
                }
                match api::register_freebird_delegate().await {
                    Ok(()) => api::log("sent RegisterDelegate"),
                    Err(e) => api::log(&format!("delegate registration failed: {e}")),
                }
                match api::kv_request(
                    freebird_core::delegate_api::FreebirdDelegateRequest::Get {
                        key: "posting_key".into(),
                    },
                )
                .await
                {
                    Ok(()) => api::log("sent posting_key Get"),
                    Err(e) => api::log(&format!("posting_key get failed: {e}")),
                }
                // Stored theme lives in the delegate; the sandbox has no
                // localStorage.
                if let Err(e) = api::kv_request(
                    freebird_core::delegate_api::FreebirdDelegateRequest::Get {
                        key: "theme".into(),
                    },
                )
                .await
                {
                    api::log(&format!("theme get failed: {e}"));
                }
                // Public-directory listing preference (issue #11).
                if let Err(e) = api::kv_request(
                    freebird_core::delegate_api::FreebirdDelegateRequest::Get {
                        key: "public_listing".into(),
                    },
                )
                .await
                {
                    api::log(&format!("public_listing get failed: {e}"));
                }
                // Update-banner dismissal watermark.
                if let Err(e) = api::kv_request(
                    freebird_core::delegate_api::FreebirdDelegateRequest::Get {
                        key: "dismissed_build".into(),
                    },
                )
                .await
                {
                    api::log(&format!("dismissed_build get failed: {e}"));
                }
                // The publisher's control cell: newest deployed build + flags.
                if let Err(e) = api::fetch_control().await {
                    api::log(&format!("control fetch failed: {e}"));
                }
                // Auto-discover the Identity Vault's current delegate.
                match crate::ghostkey::discover_vault_delegate().await {
                    Ok(key) => {
                        api::log(&format!("vault delegate discovered: {key}"));
                        *GHOSTKEY_DELEGATE.write() = Some(key);
                    }
                    Err(e) => api::log(&format!("vault delegate discovery failed: {e}")),
                }
            }
        });
    });

    // VIEW -> location.hash. Skip when the hash already means this view:
    // breaks the hashchange feedback loop and leaves foreign hashes
    // (#follow=) alone.
    use_effect(move || {
        let view = *VIEW.read();
        #[cfg(target_arch = "wasm32")]
        if let Some(w) = web_sys::window() {
            let loc = w.location();
            if View::from_hash(&loc.hash().unwrap_or_default()) != view {
                let _ = loc.set_hash(&view.to_hash());
            }
            // Always mirror to the shell: anchor clicks change our hash
            // without going through set_hash above.
            sync_shell_hash(&view.to_hash());
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = view;
    });

    // When the stored posting key answer arrives, resume or leave onboarding.
    use_effect(move || {
        let loaded = POSTING_KEY_LOADED.read().clone();
        if let Some(Some(seed)) = loaded {
            if ACCOUNT.read().is_none() {
                spawn(async move {
                    if let Err(e) = actions::resume_account(seed).await {
                        api::log(&format!("resume failed: {e}"));
                    }
                });
            }
        }
    });

    // Refresh our directory listing's last_active once per session, so an
    // active listed author never ages to the bottom of the eviction order.
    // Anonymous authors refresh too (#23) — for them it's also what keeps
    // their bounded-share slot alive.
    let mut listing_refreshed = use_signal(|| false);
    use_effect(move || {
        let listed = *PUBLIC_LISTING.read() == Some(true);
        // Wait for the own FEED, not just the account: refreshing before the
        // attestation arrives would republish a verified author's listing at
        // the anonymous (evictable) tier.
        let feed_loaded = own_author()
            .and_then(|a| FEEDS.read().get(&a).cloned())
            .flatten()
            .is_some();
        if listed && feed_loaded && !*listing_refreshed.peek() {
            listing_refreshed.set(true);
            spawn(async {
                if let Err(e) = actions::set_public_listing(true).await {
                    api::log(&format!("directory listing refresh failed: {e}"));
                }
            });
        }
    });

    // Subscribe to newly-followed feeds as the follow list changes/arrives.
    use_effect(move || {
        let follows: Vec<[u8; 32]> = own_author()
            .and_then(|a| FEEDS.read().get(&a).cloned().flatten())
            .map(|f| f.follows.follows.follows.iter().copied().collect())
            .unwrap_or_default();
        let known: Vec<[u8; 32]> = FEEDS.read().keys().copied().collect();
        for target in follows {
            if !known.contains(&target) {
                spawn(async move {
                    let _ = api::fetch_feed(target).await;
                });
            }
        }
    });

    let status = SYNC_STATUS.read().clone();
    let onboarded = ACCOUNT.read().is_some();
    let awaiting_key = POSTING_KEY_LOADED.read().is_none();

    rsx! {
        // Inlined: the app is served under /v1/contract/web/<key>/, where
        // dx's absolute /assets/ URLs 404. Fonts are data:-embedded — the
        // sandbox CSP allows no external hosts.
        style { dangerous_inner_html: include_str!("../assets/fonts.css") }
        style { dangerous_inner_html: include_str!("../assets/main.css") }
        div { class: "app",
            header {
                h1 {
                    a { href: "{View::Home.to_hash()}", "data-freenet-no-intercept": "1",
                        svg {
                            view_box: "0 0 24 24",
                            fill: "currentColor",
                            "aria-hidden": "true",
                            path { d: "M3 13 C7 6 14 4 22 4 C19 7 17 8 14 9 C16 9 18 9 20 9 C17 12 13 13 10 13 C7 13 5 14 4 16 C3.5 15 3 14 3 13 Z" }
                        }
                        "Freebird"
                    }
                }
                button { class: "link theme-toggle",
                    title: "Theme",
                    onclick: move |_| {
                        let next = THEME.peek().next();
                        apply_theme(next);
                        spawn(async move {
                            if let Err(e) = api::kv_request(
                                freebird_core::delegate_api::FreebirdDelegateRequest::Store {
                                    key: "theme".into(),
                                    value: next.label().as_bytes().to_vec(),
                                },
                            )
                            .await
                            {
                                api::log(&format!("theme save failed: {e}"));
                            }
                        });
                    },
                    "theme: {THEME.read().label()}"
                }
                span { class: "status", aria_live: "polite",
                    match &status {
                        SyncStatus::Connecting => "connecting…".to_string(),
                        SyncStatus::Connected => "connected".to_string(),
                        SyncStatus::Error(e) => format!("error: {e}"),
                    }
                }
            }
            UpdateBanner {}
            if onboarded {
                nav { class: "tabs",
                    button { class: "link", onclick: move |_| *VIEW.write() = View::Home, "home" }
                    button { class: "link", onclick: move |_| *VIEW.write() = View::Discover, "discover" }
                }
                match *VIEW.read() {
                    View::Home => rsx! { Home {} },
                    View::Profile => rsx! { ProfilePage {} },
                    View::Thread(r) => rsx! { ThreadPage { author: r.author, post_id_bytes: r.post.0.to_vec() } },
                    View::Discover => rsx! { Discover {} },
                    View::Author(a) => rsx! { AuthorPage { author: a } },
                }
            } else if awaiting_key && matches!(status, SyncStatus::Connected | SyncStatus::Connecting) {
                p { class: "muted", "Loading account…" }
            } else {
                Onboarding {}
            }
            footer { class: "muted app-footer",
                a {
                    href: "https://github.com/skandragon/freenet-freebird",
                    target: "_blank",
                    rel: "noopener",
                    "freenet-freebird"
                }
                {format!(" · build {} ({})", env!("BUILD_HASH"), env!("BUILD_DATE"))}
            }
        }
    }
}

/// "A new version is available" banner, driven by the publisher's control
/// cell. Dismissing remembers the build in the delegate KV, so the banner
/// stays gone until an even newer build ships. Dev builds (build 0) and
/// missing/undecodable control state show nothing; the banner also waits
/// for the delegate's dismissal answer so it never flashes.
#[component]
fn UpdateBanner() -> Element {
    let control = CONTROL.read().clone();
    let Some(dismissed) = *DISMISSED_BUILD.read() else {
        return rsx! {};
    };
    let published = control.as_ref().map(|c| c.build);
    if !freebird_control::update_available(keys::own_build(), published, dismissed) {
        return rsx! {};
    }
    let build = published.unwrap_or_default();
    let label = control
        .as_ref()
        .map(|c| c.build_label.clone())
        .unwrap_or_default();
    rsx! {
        div { class: "update-banner", role: "status",
            span {
                "A new version of Freebird is available"
                if !label.is_empty() {
                    span { class: "muted", " (build {label})" }
                }
                "."
            }
            span { class: "update-banner-actions",
                button {
                    class: "link",
                    onclick: move |_| {
                        #[cfg(target_arch = "wasm32")]
                        if let Some(w) = web_sys::window() {
                            let _ = w.location().reload();
                        }
                    },
                    "Reload"
                }
                button {
                    class: "link muted",
                    onclick: move |_| {
                        *DISMISSED_BUILD.write() = Some(build);
                        spawn(async move {
                            if let Err(e) = api::kv_request(
                                freebird_core::delegate_api::FreebirdDelegateRequest::Store {
                                    key: "dismissed_build".into(),
                                    value: build.to_string().into_bytes(),
                                },
                            )
                            .await
                            {
                                api::log(&format!("dismissed_build save failed: {e}"));
                            }
                        });
                    },
                    "Dismiss"
                }
            }
        }
    }
}

#[component]
fn Onboarding() -> Element {
    let mut name = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);

    rsx! {
        section { class: "card onboarding",
            h2 { "Welcome" }
            p { "Pick a display name. Your account is a locally generated key — no signup, no server." }
            input {
                placeholder: "Display name",
                aria_label: "Display name",
                value: "{name}",
                oninput: move |e| name.set(e.value()),
            }
            button {
                disabled: *busy.read() || name.read().trim().is_empty(),
                onclick: move |_| {
                    busy.set(true);
                    error.set(String::new());
                    let n = name.read().trim().to_string();
                    spawn(async move {
                        if let Err(e) = actions::create_account(n).await {
                            error.set(e);
                        }
                        busy.set(false);
                    });
                },
                if *busy.read() { "Creating…" } else { "Create account" }
            }
            if !error.read().is_empty() {
                p { class: "error", "{error}" }
            }
        }
    }
}

#[component]
fn Home() -> Element {
    let pending = *PENDING_FOLLOW.read();
    rsx! {
        div { class: "columns",
            main {
                if let Some(target) = pending {
                    if Some(target) != own_author() {
                        div { class: "card follow-banner",
                            Avatar { author: target }
                            span {
                                "Follow "
                                strong { "{author_name(&target)}" }
                                " (@{short_key(&target)})?"
                            }
                            button {
                                onclick: move |_| {
                                    spawn(async move {
                                        let _ = actions::set_follow(target, true).await;
                                        *PENDING_FOLLOW.write() = None;
                                    });
                                },
                                "Follow"
                            }
                            button { class: "link",
                                onclick: move |_| *PENDING_FOLLOW.write() = None,
                                "dismiss"
                            }
                        }
                    }
                }
                Compose { in_reply_to: None }
                Timeline {}
            }
            aside {
                MyAccount {}
                FollowBox {}
            }
        }
    }
}

#[component]
fn Compose(in_reply_to: Option<PostRef>) -> Element {
    let mut text = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut notice = use_signal(String::new);
    let limit = freebird_core::feed::MAX_POST_BYTES;
    let is_reply = in_reply_to.is_some();
    let over = text.read().len() > limit;

    let mut submit = move || {
        let content = text.peek().trim().to_string();
        if content.is_empty() || text.peek().len() > limit {
            return;
        }
        error.set(String::new());
        notice.set(String::new());
        spawn(async move {
            match actions::publish_post(content, in_reply_to).await {
                Ok(()) => {
                    text.set(String::new());
                    if is_reply {
                        notice.set("Reply posted to the thread.".into());
                    }
                }
                Err(e) => error.set(e),
            }
        });
    };

    rsx! {
        div { class: "card compose",
            textarea {
                placeholder: if is_reply { "Write a reply…" } else { "What's peeping?" },
                aria_label: if is_reply { "Reply text" } else { "New peep" },
                value: "{text}",
                oninput: move |e| text.set(e.value()),
                onkeydown: move |e| {
                    let m = e.modifiers();
                    if e.key() == Key::Enter && (m.meta() || m.ctrl()) {
                        submit();
                    }
                },
            }
            div { class: "compose-row",
                span { class: if over { "error" } else { "muted" }, "{text.read().len()}/{limit} bytes" }
                button {
                    disabled: text.read().trim().is_empty() || over,
                    onclick: move |_| submit(),
                    if is_reply { "Reply" } else { "Peep" }
                }
            }
            if !notice.read().is_empty() { p { class: "muted", "{notice}" } }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn Timeline() -> Element {
    // Merge own + followed posts, newest first. FEEDS holds more than the
    // timeline (thread expansion caches repliers' feeds) — filter to the
    // feeds actually followed.
    let posts: Vec<([u8; 32], AuthorizedPost)> = {
        let feeds = FEEDS.read();
        let mut wanted: std::collections::BTreeSet<[u8; 32]> = Default::default();
        if let Some(own) = own_author() {
            wanted.insert(own);
            if let Some(Some(own_feed)) = feeds.get(&own) {
                wanted.extend(own_feed.follows.follows.follows.iter().copied());
            }
        }
        let mut all: Vec<([u8; 32], AuthorizedPost)> = feeds
            .iter()
            .filter(|(author, _)| wanted.contains(*author))
            .filter_map(|(author, state)| state.as_ref().map(|s| (author, s)))
            .flat_map(|(author, s)| {
                s.posts.posts.iter().map(move |p| (*author, p.clone()))
            })
            .collect();
        all.sort_by(|a, b| (b.1.post.time, b.1.post.id).cmp(&(a.1.post.time, a.1.post.id)));
        // A reply whose parent is in the timeline is reachable via the
        // parent's thread — showing it top-level too duplicates it.
        let ids: std::collections::BTreeSet<([u8; 32], freebird_core::types::PostId)> =
            all.iter().map(|(a, p)| (*a, p.post.id)).collect();
        all.retain(|(_, p)| {
            p.post
                .in_reply_to
                .is_none_or(|r| !ids.contains(&(r.author, r.post)))
        });
        all.truncate(100);
        all
    };

    rsx! {
        div { class: "timeline",
            if posts.is_empty() {
                p { class: "muted", "Nothing here yet. Peep something above, or add an author's address in the Following box." }
            }
            for (author, post) in posts {
                PostCard { key: "{post_key(&author, &post.post.id)}", author, post: post.clone() }
            }
        }
    }
}

#[component]
fn PostCard(author: [u8; 32], post: AuthorizedPost, #[props(default)] expand_thread: bool) -> Element {
    let mut show_reply = use_signal(|| false);
    let mut show_thread = use_signal(move || expand_thread);
    let name = author_name(&author);
    let verified = is_verified(&author);
    let post_ref = PostRef {
        author,
        post: post.post.id,
    };
    let thread_href = View::Thread(post_ref).to_hash();
    let reply_count = merged_pointers(&author)
        .iter()
        .filter(|p| p.target_post == post.post.id)
        .count();

    rsx! {
        article { class: "card post",
            div { class: "post-head",
                Avatar { author }
                a { href: "{View::Author(author).to_hash()}", "data-freenet-no-intercept": "1", strong { "{name}" } }
                if verified { span { class: "check", title: "Ghost Key verified", "✔" } }
                span { class: "muted", "@{short_key(&author)} · " }
                // Timestamp = thread permalink (deep link, issue #2).
                a { class: "muted", href: "{thread_href}", title: "thread", "data-freenet-no-intercept": "1", "{ago(post.post.time)}" }
            }
            if let Some(parent) = post.post.in_reply_to {
                p { class: "muted replying-to",
                    a { class: "muted", href: "{View::Thread(parent).to_hash()}", "data-freenet-no-intercept": "1",
                        "replying to @{short_key(&parent.author)}"
                    }
                }
            }
            p { class: "content", "{post.post.content}" }
            div { class: "post-actions",
                button { class: "link", onclick: move |_| show_reply.toggle(),
                    "reply"
                }
                button { class: "link", onclick: move |_| show_thread.toggle(),
                    if reply_count > 0 { "replies ({reply_count})" } else { "replies" }
                }
            }
            if *show_reply.read() {
                Compose { in_reply_to: Some(post_ref) }
            }
            if *show_thread.read() {
                Thread { author, post_id_bytes: post.post.id.0.to_vec() }
            }
        }
    }
}

#[component]
fn Thread(author: [u8; 32], post_id_bytes: Vec<u8>) -> Element {
    let post_id = freebird_core::types::PostId(post_id_bytes.clone().try_into().unwrap_or([0; 16]));

    // Pointers targeting this post — v2 and legacy inbox merged — resolved
    // into (replier_key, reply_id, post).
    let replies: Vec<([u8; 32], freebird_core::types::PostId, Option<AuthorizedPost>)> = {
        let feeds = FEEDS.read();
        merged_pointers(&author)
            .into_iter()
            .filter(|p| p.target_post == post_id)
            .map(|p| {
                let replier = p.replier;
                let found = feeds.get(&replier).and_then(|f| f.as_ref()).and_then(|f| {
                    f.posts
                        .posts
                        .iter()
                        .find(|x| x.post.id == p.reply_post)
                        // The reply must actually claim THIS post as its
                        // parent — a pointer alone must not let anyone graft
                        // an arbitrary peep into a stranger's thread.
                        .filter(|x| {
                            x.post.in_reply_to
                                == Some(PostRef {
                                    author,
                                    post: post_id,
                                })
                        })
                        .cloned()
                });
                (replier, p.reply_post, found)
            })
            .collect()
    };

    // Fetch replier feeds we don't have yet.
    use_effect(move || {
        let missing: Vec<[u8; 32]> = {
            let feeds = FEEDS.read();
            merged_pointers(&author)
                .into_iter()
                .map(|p| p.replier)
                .filter(|k| !feeds.contains_key(k))
                .collect()
        };
        for replier in missing {
            spawn(async move {
                let _ = api::fetch_feed(replier).await;
            });
        }
    });

    let inbox_loaded =
        INBOXES.read().contains_key(&author) || LEGACY_INBOXES.read().contains_key(&author);

    rsx! {
        div { class: "thread",
            if replies.is_empty() {
                if inbox_loaded {
                    p { class: "muted", "No replies yet." }
                } else {
                    p { class: "muted", "Checking for replies…" }
                }
            }
            for (replier, reply_id, reply) in replies {
                div { key: "{post_key(&replier, &reply_id)}",
                    match reply {
                        Some(post) => rsx! { PostCard { author: replier, post } },
                        None => rsx! { p { class: "muted", "loading reply from @{short_key(&replier)}…" } },
                    }
                }
            }
        }
    }
}

/// Deep-linked single post (`#/thread/<author>/<post>`): the post with its
/// reply thread expanded.
#[component]
fn ThreadPage(author: [u8; 32], post_id_bytes: Vec<u8>) -> Element {
    let post_id = freebird_core::types::PostId(post_id_bytes.clone().try_into().unwrap_or([0; 16]));
    use_effect(move || {
        if !FEEDS.read().contains_key(&author) {
            spawn(async move {
                let _ = api::fetch_feed(author).await;
            });
        }
    });
    let post = FEEDS
        .read()
        .get(&author)
        .and_then(|f| f.as_ref())
        .and_then(|f| f.posts.posts.iter().find(|p| p.post.id == post_id).cloned());

    // Conversation context above the focused post: walk `in_reply_to` up
    // through loaded feeds, root-first. An ancestor whose feed hasn't
    // arrived yet is fetched and the chain re-renders when it lands.
    let (ancestors, unresolved) = ancestor_chain(
        &FEEDS.read(),
        post.as_ref().and_then(|p| p.post.in_reply_to),
    );
    use_effect(move || {
        let parent = ancestor_chain(
            &FEEDS.read(),
            FEEDS
                .read()
                .get(&author)
                .and_then(|f| f.as_ref())
                .and_then(|f| f.posts.posts.iter().find(|p| p.post.id == post_id))
                .and_then(|p| p.post.in_reply_to),
        )
        .1;
        if let Some(r) = parent {
            if !FEEDS.read().contains_key(&r.author) {
                spawn(async move {
                    let _ = api::fetch_feed(r.author).await;
                });
            }
        }
    });

    rsx! {
        div { class: "thread-page",
            button { class: "link", onclick: move |_| *VIEW.write() = View::Home,
                "← back to feed"
            }
            if let Some(r) = unresolved {
                if FEEDS.read().get(&r.author).is_none_or(|f| f.is_none()) {
                    p { class: "muted", "loading earlier peeps from @{short_key(&r.author)}…" }
                } else {
                    // Feed arrived but the post is gone (beyond retention).
                    p { class: "muted", "an earlier peep by @{short_key(&r.author)} is no longer available" }
                }
            }
            for (ancestor, apost) in ancestors {
                PostCard { key: "{post_key(&ancestor, &apost.post.id)}", author: ancestor, post: apost }
            }
            match post {
                Some(post) => rsx! { PostCard { author, post, expand_thread: true } },
                None => rsx! { p { class: "muted", "Loading post…" } },
            }
        }
    }
}

/// An author's timeline (`#/author/<author>`): their posts, newest first.
#[component]
fn AuthorPage(author: [u8; 32]) -> Element {
    use_effect(move || {
        if !FEEDS.read().contains_key(&author) {
            spawn(async move {
                let _ = api::fetch_feed(author).await;
            });
        }
    });

    let loaded = FEEDS.read().get(&author).is_some_and(|f| f.is_some());
    let posts: Vec<AuthorizedPost> = FEEDS
        .read()
        .get(&author)
        .and_then(|f| f.as_ref())
        .map(|f| {
            let mut v = f.posts.posts.clone();
            v.sort_by(|a, b| (b.post.time, b.post.id).cmp(&(a.post.time, a.post.id)));
            // Same rule as the home timeline: a reply whose parent is in the
            // list is reachable via the parent's thread — hide it top-level.
            let ids: std::collections::BTreeSet<freebird_core::types::PostId> =
                v.iter().map(|p| p.post.id).collect();
            v.retain(|p| {
                p.post
                    .in_reply_to
                    .is_none_or(|r| r.author != author || !ids.contains(&r.post))
            });
            v
        })
        .unwrap_or_default();

    let own = own_author();
    let following = own
        .and_then(|a| FEEDS.read().get(&a).cloned().flatten())
        .is_some_and(|f| f.follows.follows.follows.contains(&author));

    rsx! {
        div { class: "thread-page",
            button { class: "link", onclick: move |_| *VIEW.write() = View::Home,
                "← back to feed"
            }
            section { class: "card",
                h2 {
                    Avatar { author }
                    " {author_name(&author)}"
                    if is_verified(&author) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                }
                p { class: "muted", "@{short_key(&author)}" }
                if Some(author) == own {
                    p { class: "muted", "This is you." }
                } else if following {
                    p { class: "muted", "following" }
                } else {
                    button { class: "link",
                        onclick: move |_| {
                            spawn(async move { let _ = actions::set_follow(author, true).await; });
                        },
                        "follow"
                    }
                }
            }
            div { class: "timeline",
                if !loaded {
                    p { class: "muted", "Loading feed…" }
                } else if posts.is_empty() {
                    p { class: "muted", "No peeps yet." }
                }
                for post in posts {
                    PostCard { key: "{post_key(&author, &post.post.id)}", author, post }
                }
            }
        }
    }
}

#[component]
fn MyAccount() -> Element {
    let Some(author) = own_author() else {
        return rsx! {};
    };

    rsx! {
        section { class: "card",
            h3 {
                Avatar { author }
                " {author_name(&author)}"
                if is_verified(&author) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
            }
            p { class: "muted", "Anyone opening your follow link can follow you in one click." }
            CopyButton { text: follow_link(&author), label: "copy follow link" }
            button { class: "link", onclick: move |_| *VIEW.write() = View::Profile,
                "view profile"
            }
        }
    }
}

/// Public-directory opt-in (issue #11): open to everyone (issue #23) —
/// verified listings just can't be crowded out. Lives on the profile page.
#[component]
fn PublicListingToggle(author: [u8; 32]) -> Element {
    let mut listing_error = use_signal(String::new);
    let listed = *PUBLIC_LISTING.read() == Some(true);

    rsx! {
        p { class: "muted keyline", "Discovery:" }
        label { class: "toggle",
            input {
                r#type: "checkbox",
                checked: listed,
                onchange: move |e| {
                    let on = e.checked();
                    listing_error.set(String::new());
                    spawn(async move {
                        if let Err(err) = actions::set_public_listing(on).await {
                            listing_error.set(err);
                        }
                    });
                },
            }
            "List me publicly in Discover"
        }
        if !listing_error.read().is_empty() { p { class: "error", "{listing_error}" } }
    }
}

/// Current Discover rows from the two directory signals. Reads the signals,
/// so callers (render or effects) subscribe to directory updates.
fn current_listings() -> Vec<([u8; 32], u64)> {
    let legacy: Vec<([u8; 32], u64)> = LEGACY_DIRECTORY
        .read()
        .as_ref()
        .map(|d| {
            d.listings
                .values()
                .map(|l| (l.listing.author, l.listing.last_active))
                .collect()
        })
        .unwrap_or_default();
    let v2: Vec<([u8; 32], u64)> = DIRECTORY
        .read()
        .as_ref()
        .map(|d| {
            d.listings
                .values()
                .map(|l| (l.listing.author, l.listing.last_active))
                .collect()
        })
        .unwrap_or_default();
    merged_listings(&legacy, &v2)
}

/// Newest-first union of the legacy and v2 directory listings as
/// (author, last_active) pairs — one entry per author, v2 winning
/// unconditionally (dual-read window, #23).
fn merged_listings(
    legacy: &[([u8; 32], u64)],
    v2: &[([u8; 32], u64)],
) -> Vec<([u8; 32], u64)> {
    let mut by_author: std::collections::BTreeMap<[u8; 32], u64> = Default::default();
    for &(a, t) in legacy.iter().chain(v2) {
        by_author.insert(a, t);
    }
    let mut v: Vec<([u8; 32], u64)> = by_author.into_iter().collect();
    v.sort_by(|a, b| (b.1, b.0).cmp(&(a.1, a.0)));
    v
}

/// Which of the top `sample` listed authors still need a feed fetch: feed
/// not resolved (absent OR the pending/failed `None` placeholder) and not
/// already attempted during this Discover visit. Treating the placeholder
/// as fetchable is deliberate — a GET that failed must not black-hole the
/// author's name for the whole session.
fn feeds_to_fetch(
    listings: &[([u8; 32], u64)],
    feeds: &std::collections::BTreeMap<[u8; 32], Option<FeedStateV1>>,
    attempted: &std::collections::BTreeSet<[u8; 32]>,
    sample: usize,
) -> Vec<[u8; 32]> {
    listings
        .iter()
        .take(sample)
        .map(|&(a, _)| a)
        .filter(|a| feeds.get(a).is_none_or(|f| f.is_none()) && !attempted.contains(a))
        .collect()
}

/// Discover tab (issue #11): the well-known public directory — authors who
/// opted in, newest activity first, with a sampled preview of their feeds.
#[component]
fn Discover() -> Element {
    const SAMPLE: usize = 20;

    let mut requested = use_signal(|| false);
    use_effect(move || {
        if !*requested.peek() {
            requested.set(true);
            spawn(async {
                if let Err(e) = api::fetch_directory().await {
                    api::log(&format!("directory fetch failed: {e}"));
                }
            });
        }
    });

    let loaded = DIRECTORY.read().is_some() || LEGACY_DIRECTORY.read().is_some();
    let listings = current_listings();

    // Fetch a sample of listed authors' feeds (names, latest peeps) through
    // the existing fetch_feed plumbing. Every read happens INSIDE the effect
    // so it re-fires as the directory and feeds stream in — computing the
    // sample at render time left the effect with the empty first-render
    // snapshot, and no names ever loaded. `attempted` (peeked, so its own
    // write can't re-trigger us) caps each author at one fetch per visit;
    // remount resets it, so a feed that failed to resolve is retried on the
    // next visit instead of being black-holed for the session.
    let mut attempted = use_signal(std::collections::BTreeSet::<[u8; 32]>::new);
    use_effect(move || {
        let listings = current_listings();
        let sample = feeds_to_fetch(&listings, &FEEDS.read(), &attempted.peek(), SAMPLE);
        if sample.is_empty() {
            return;
        }
        attempted.write().extend(sample.iter().copied());
        for a in sample {
            spawn(async move {
                let _ = api::fetch_feed(a).await;
            });
        }
    });

    let own = own_author();
    let own_follows: std::collections::BTreeSet<[u8; 32]> = own
        .and_then(|a| FEEDS.read().get(&a).cloned().flatten())
        .map(|f| f.follows.follows.follows.clone())
        .unwrap_or_default();

    rsx! {
        div { class: "profile-page",
            section { class: "card",
                h2 { "Discover" }
                p { class: "muted",
                    "Authors who chose to be listed publicly. Follow someone to see \
                     their peeps in your timeline."
                }
                if !loaded {
                    p { class: "muted", "Loading directory…" }
                } else if listings.is_empty() {
                    p { class: "muted",
                        "Nobody is listed yet. Be the first — turn on \
                         “List me publicly” on your profile page."
                    }
                }
                for (a, last_active) in listings.into_iter().take(50) {
                    div { class: "follow-row", key: "{bs58::encode(&a).into_string()}",
                        span {
                            Avatar { author: a }
                            " "
                            a { href: "{View::Author(a).to_hash()}", "data-freenet-no-intercept": "1", "{author_name(&a)}" }
                            if is_verified(&a) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                            span { class: "muted", " @{short_key(&a)} · active {ago(last_active)}" }
                            if let Some(latest) = FEEDS.read().get(&a).and_then(|f| f.as_ref()).and_then(|f| f.posts.posts.last()) {
                                p { class: "muted", "“{latest.post.content}”" }
                            }
                        }
                        if Some(a) == own {
                            span { class: "muted", "you" }
                        } else if own_follows.contains(&a) {
                            span { class: "muted", "following" }
                        } else {
                            button { class: "link",
                                onclick: move |_| {
                                    spawn(async move { let _ = actions::set_follow(a, true).await; });
                                },
                                "follow"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FollowBox() -> Element {
    let mut input = use_signal(String::new);
    let mut error = use_signal(String::new);
    let follows: Vec<[u8; 32]> = own_author()
        .and_then(|a| FEEDS.read().get(&a).cloned().flatten())
        .map(|f| f.follows.follows.follows.iter().copied().collect())
        .unwrap_or_default();

    rsx! {
        section { class: "card",
            h3 { "Following ({follows.len()})" }
            for f in follows {
                div { class: "follow-row",
                    span {
                        Avatar { author: f }
                        " {author_name(&f)}"
                        if is_verified(&f) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                    }
                    button { class: "link",
                        onclick: move |_| {
                            spawn(async move { let _ = actions::set_follow(f, false).await; });
                        },
                        "unfollow"
                    }
                }
            }
            input {
                placeholder: "Author address",
                aria_label: "Author address",
                value: "{input}",
                oninput: move |e| input.set(e.value()),
            }
            button {
                disabled: input.read().trim().is_empty(),
                onclick: move |_| {
                    error.set(String::new());
                    let raw = input.read().trim().to_string();
                    match bs58::decode(&raw).into_vec().ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                        Some(target) => {
                            spawn(async move {
                                match actions::set_follow(target, true).await {
                                    Ok(()) => input.set(String::new()),
                                    Err(e) => error.set(e),
                                }
                            });
                        }
                        None => error.set("not a valid author address".into()),
                    }
                },
                "Follow"
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

/// Confirmed followers (issue #12): follow announcements in the inbox are
/// hints only. A follower shows once their fetched feed proves `owner` is in
/// their signed follow list — no forged "X follows you", and unfollows age
/// out because the claim re-verifies against the live list. Anonymous
/// followers announce and appear like anyone else (issue #23).
fn confirmed_followers(
    pointers: &[InboxPointer],
    feeds: &std::collections::BTreeMap<[u8; 32], Option<FeedStateV1>>,
    owner: &[u8; 32],
) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = pointers
        .iter()
        .filter(|p| p.target_post == actions::FOLLOW_ANNOUNCE_TARGET)
        .map(|p| p.replier)
        .collect();
    out.sort();
    out.dedup();
    out.retain(|k| {
        feeds
            .get(k)
            .and_then(|f| f.as_ref())
            .is_some_and(|f| f.follows.follows.follows.contains(owner))
    });
    out
}

#[component]
fn FollowersBox() -> Element {
    let Some(author) = own_author() else {
        return rsx! {};
    };
    let followers = {
        let pointers = merged_pointers(&author);
        let feeds = FEEDS.read();
        confirmed_followers(&pointers, &feeds, &author)
    };
    let own_follows: std::collections::BTreeSet<[u8; 32]> = FEEDS
        .read()
        .get(&author)
        .cloned()
        .flatten()
        .map(|f| f.follows.follows.follows.clone())
        .unwrap_or_default();

    // Fetch announcers' feeds we don't have yet, to verify their claims.
    use_effect(move || {
        let missing: Vec<[u8; 32]> = {
            let feeds = FEEDS.read();
            merged_pointers(&author)
                .into_iter()
                .filter(|p| p.target_post == actions::FOLLOW_ANNOUNCE_TARGET)
                .map(|p| p.replier)
                .filter(|k| !feeds.contains_key(k))
                .collect()
        };
        for k in missing {
            spawn(async move {
                let _ = api::fetch_feed(k).await;
            });
        }
    });

    rsx! {
        section { class: "card",
            h3 { "Followers ({followers.len()})" }
            if followers.is_empty() {
                p { class: "muted",
                    "No followers yet. Followers appear here once their follow \
                     announcement reaches your inbox."
                }
            }
            for f in followers {
                div { class: "follow-row",
                    span {
                        Avatar { author: f }
                        " {author_name(&f)}"
                        if is_verified(&f) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                    }
                    if own_follows.contains(&f) {
                        span { class: "muted", "following" }
                    } else {
                        button { class: "link",
                            onclick: move |_| {
                                spawn(async move { let _ = actions::set_follow(f, true).await; });
                            },
                            "follow back"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn VerifyBox() -> Element {
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let verified = own_author().map(|a| is_verified(&a)).unwrap_or(false);
    let vault_found = GHOSTKEY_DELEGATE.read().is_some();

    // Auto-detect a Ghost Key: HasIdentity never prompts the user.
    use_effect(move || {
        if GHOSTKEY_DELEGATE.read().is_some() && GHOSTKEY_HAS_IDENTITY.read().is_none() {
            spawn(async {
                let _ = api::ghostkey_request(crate::ghostkey::GhostkeyRequest::HasIdentity).await;
            });
        }
    });
    let has_identity = *GHOSTKEY_HAS_IDENTITY.read();

    // Complete the flow when the ghostkey delegate answers.
    use_effect(move || {
        let result = GHOSTKEY_SIGN_RESULT.read().clone();
        if let Some(result) = result {
            *GHOSTKEY_SIGN_RESULT.write() = None;
            match result {
                Ok((scoped, sig, cert)) => {
                    spawn(async move {
                        match actions::complete_verification(scoped, sig, cert).await {
                            Ok(_tier) => message.set(
                                "Congratulations! You have earned the Prized Checkmark! ✔".into(),
                            ),
                            Err(e) => message.set(format!("Verification failed: {e}")),
                        }
                        busy.set(false);
                    });
                }
                Err(e) => {
                    message.set(e);
                    busy.set(false);
                }
            }
        }
    });

    rsx! {
        section { class: "card",
            h3 { "Verification" }
            if verified {
                p { span { class: "check", "✔" } " This account has earned the Prized Checkmark. Your replies and listings can never be crowded out." }
            } else {
                p { class: "muted",
                    "Anonymous accounts have full run of Freebird — peep, reply into \
                     threads, get listed in Discover. Anonymous replies and listings \
                     share a bounded pool of slots, so in busy places delivery is \
                     best-effort. A Ghost Key adds the check mark and makes your \
                     presence durable: verified replies and listings are never \
                     crowded out."
                }
                match has_identity {
                    Some(true) => rsx! {
                        p { span { class: "check", "✔" } " Ghost Key detected in your vault." }
                    },
                    Some(false) => rsx! {
                        p { class: "muted",
                            "No Ghost Key in your node's vault yet — "
                            a { href: "https://freenet.org/ghostkey", target: "_blank", rel: "noopener noreferrer", "get one here" }
                            ", import it in the Identity Vault, then come back."
                        }
                    },
                    None => rsx! {
                        if !vault_found {
                            p { class: "muted",
                                "Looking for the Identity Vault on this node…"
                            }
                        }
                    },
                }
                button {
                    disabled: *busy.read() || has_identity == Some(false),
                    onclick: move |_| {
                        busy.set(true);
                        message.set(String::new());
                        spawn(async move {
                            if let Err(e) = actions::request_verification().await {
                                message.set(e);
                                busy.set(false);
                            }
                        });
                    },
                    if *busy.read() { "Waiting for Identity Vault…" } else { "Get check mark" }
                }
            }
            if !message.read().is_empty() { p { "{message}" } }
        }
    }
}

#[component]
fn DangerZone() -> Element {
    let mut arming = use_signal(|| false);

    rsx! {
        section { class: "card danger-zone",
            h3 { "Danger zone" }
            if *arming.read() {
                p { class: "error",
                    "This destroys your posting key. Your feed can never be \
                     updated again and will age out of the network. There is \
                     no undo."
                }
                button { class: "danger",
                    onclick: move |_| {
                        spawn(async move {
                            if let Err(e) = actions::nuke_account().await {
                                api::log(&format!("nuke failed: {e}"));
                            }
                            *VIEW.write() = View::Home;
                        });
                    },
                    "Yes, delete forever"
                }
                button { class: "link", onclick: move |_| arming.set(false), "cancel" }
            } else {
                button { class: "link danger-link", onclick: move |_| arming.set(true),
                    "Delete account"
                }
            }
        }
    }
}

/// Your own profile: identity, editing, verification, and the danger zone.
#[component]
fn ProfilePage() -> Element {
    let mut editing = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut bio = use_signal(String::new);
    let mut edit_error = use_signal(String::new);
    let mut pic_busy = use_signal(|| false);
    let mut pic_error = use_signal(String::new);

    let Some(author) = own_author() else {
        return rsx! {};
    };
    let feed: Option<FeedStateV1> = FEEDS.read().get(&author).cloned().flatten();
    let full_key = bs58::encode(&author).into_string();

    rsx! {
        div { class: "profile-page",
            button { class: "link", onclick: move |_| *VIEW.write() = View::Home,
                "← back to feed"
            }
            section { class: "card",
                h2 {
                    Avatar { author, lg: true }
                    " {author_name(&author)}"
                    if is_verified(&author) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                }
                if let Some(f) = &feed {
                    if !f.profile.profile.bio.is_empty() {
                        p { "{f.profile.profile.bio}" }
                    }
                }
                p { class: "muted keyline", "Profile picture (shown on your posts; auto-cropped square):" }
                input {
                    r#type: "file",
                    accept: "image/png,image/jpeg,image/webp,image/gif",
                    aria_label: "Upload profile picture",
                    disabled: *pic_busy.read(),
                    onchange: move |e| {
                        let Some(file) = e.files().into_iter().next() else { return };
                        pic_error.set(String::new());
                        pic_busy.set(true);
                        spawn(async move {
                            let result = async {
                                let bytes = file
                                    .read_bytes()
                                    .await
                                    .map_err(|e| format!("read failed: {e}"))?;
                                let (ct, data) = shrink_to_avatar(bytes.to_vec()).await?;
                                actions::publish_avatar(ct, data).await
                            }
                            .await;
                            if let Err(e) = result {
                                pic_error.set(e);
                            }
                            pic_busy.set(false);
                        });
                    },
                }
                if *pic_busy.read() { p { class: "muted", "Uploading picture…" } }
                if !pic_error.read().is_empty() { p { class: "error", "{pic_error}" } }
                p { class: "muted keyline", "Your address:" }
                code { class: "keyline", "{full_key}" }
                CopyButton { text: full_key.clone(), label: "copy address" }
                p { class: "muted keyline", "Share this link — anyone opening it can follow you in one click:" }
                code { class: "keyline", "{follow_link(&author)}" }
                CopyButton { text: follow_link(&author), label: "copy follow link" }
                PublicListingToggle { author }
                if *editing.read() {
                    input { value: "{name}", oninput: move |e| name.set(e.value()), placeholder: "Name", aria_label: "Name" }
                    input { value: "{bio}", oninput: move |e| bio.set(e.value()), placeholder: "Bio", aria_label: "Bio" }
                    button {
                        onclick: move |_| {
                            let (n, b) = (name.read().clone(), bio.read().clone());
                            edit_error.set(String::new());
                            spawn(async move {
                                match actions::publish_profile(n, b).await {
                                    Ok(()) => editing.set(false),
                                    Err(e) => edit_error.set(e),
                                }
                            });
                        },
                        "Save"
                    }
                    button { class: "link",
                        onclick: move |_| {
                            edit_error.set(String::new());
                            editing.set(false);
                        },
                        "cancel"
                    }
                    if !edit_error.read().is_empty() { p { class: "error", "{edit_error}" } }
                } else {
                    button { class: "link",
                        onclick: move |_| {
                            if let Some(f) = FEEDS.read().get(&author).cloned().flatten() {
                                name.set(f.profile.profile.name.clone());
                                bio.set(f.profile.profile.bio.clone());
                            }
                            edit_error.set(String::new());
                            editing.set(true);
                        },
                        "edit profile"
                    }
                }
            }
            FollowersBox {}
            VerifyBox {}
            DangerZone {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freebird_core::feed::AttestationSlot;
    use freebird_core::types::{
        AuthorizedFollows, AuthorizedProfile, FollowsV1, PostId, ProfileV1,
    };
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn feed_following(sk: &SigningKey, follows: &[[u8; 32]]) -> FeedStateV1 {
        FeedStateV1 {
            profile: AuthorizedProfile::new(ProfileV1::default(), sk),
            follows: AuthorizedFollows::new(
                FollowsV1 {
                    follows: follows.iter().copied().collect(),
                    version: 1,
                },
                sk,
            ),
            attestation: AttestationSlot(None),
            posts: Default::default(),
        }
    }

    fn announce(sk: &SigningKey, target_post: PostId, time: u64) -> InboxPointer {
        let vk = sk.verifying_key();
        InboxPointer {
            replier: vk.to_bytes(),
            target_post,
            reply_post: PostId::compute(&vk, time, "follow", &None),
            time,
        }
    }

    fn feed_with_posts(sk: &SigningKey, posts: Vec<AuthorizedPost>) -> FeedStateV1 {
        let mut feed = feed_following(sk, &[]);
        feed.posts.posts = posts;
        feed
    }

    /// Walking up from a reply yields every loaded ancestor root-first and
    /// reports nothing left to fetch.
    #[test]
    fn ancestor_chain_walks_to_root() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let root = keys::make_post(&a, "root".into(), None);
        let mid = keys::make_post(
            &b,
            "mid".into(),
            Some(PostRef { author: a.verifying_key().to_bytes(), post: root.post.id }),
        );
        let start = Some(PostRef { author: b.verifying_key().to_bytes(), post: mid.post.id });

        let mut feeds: BTreeMap<[u8; 32], Option<FeedStateV1>> = BTreeMap::new();
        feeds.insert(a.verifying_key().to_bytes(), Some(feed_with_posts(&a, vec![root.clone()])));
        feeds.insert(b.verifying_key().to_bytes(), Some(feed_with_posts(&b, vec![mid.clone()])));

        let (chain, unresolved) = ancestor_chain(&feeds, start);
        assert_eq!(unresolved, None);
        assert_eq!(
            chain.iter().map(|(k, p)| (*k, p.post.id)).collect::<Vec<_>>(),
            vec![
                (a.verifying_key().to_bytes(), root.post.id),
                (b.verifying_key().to_bytes(), mid.post.id),
            ]
        );
    }

    /// A parent whose feed isn't loaded stops the walk and is reported as
    /// unresolved so the caller can fetch it; loaded ancestors below it are
    /// still returned.
    #[test]
    fn ancestor_chain_reports_unloaded_parent() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let far = PostRef { author: a.verifying_key().to_bytes(), post: PostId([9u8; 16]) };
        let mid = keys::make_post(&b, "mid".into(), Some(far));
        let start = Some(PostRef { author: b.verifying_key().to_bytes(), post: mid.post.id });

        let mut feeds: BTreeMap<[u8; 32], Option<FeedStateV1>> = BTreeMap::new();
        feeds.insert(b.verifying_key().to_bytes(), Some(feed_with_posts(&b, vec![mid.clone()])));

        let (chain, unresolved) = ancestor_chain(&feeds, start);
        assert_eq!(unresolved, Some(far));
        assert_eq!(
            chain.iter().map(|(k, p)| (*k, p.post.id)).collect::<Vec<_>>(),
            vec![(b.verifying_key().to_bytes(), mid.post.id)]
        );
    }

    /// A malicious `in_reply_to` cycle must terminate instead of hanging the
    /// renderer.
    #[test]
    fn ancestor_chain_survives_cycles() {
        let a = SigningKey::generate(&mut OsRng);
        let key = a.verifying_key().to_bytes();
        // Two posts pointing at each other (ids forged for the test — the
        // walk never verifies signatures, it only follows references).
        let mut p1 = keys::make_post(&a, "one".into(), None);
        let mut p2 = keys::make_post(&a, "two".into(), None);
        p1.post.id = PostId([1u8; 16]);
        p2.post.id = PostId([2u8; 16]);
        p1.post.in_reply_to = Some(PostRef { author: key, post: p2.post.id });
        p2.post.in_reply_to = Some(PostRef { author: key, post: p1.post.id });

        let mut feeds: BTreeMap<[u8; 32], Option<FeedStateV1>> = BTreeMap::new();
        feeds.insert(key, Some(feed_with_posts(&a, vec![p1.clone(), p2])));

        let (chain, unresolved) = ancestor_chain(
            &feeds,
            Some(PostRef { author: key, post: p1.post.id }),
        );
        assert_eq!(unresolved, None);
        assert_eq!(chain.len(), 2);
    }

    /// Anonymous announcers count exactly like verified ones (#23): the
    /// confirmation is the announcer's own signed follow list, never the
    /// attestation.
    #[test]
    fn follower_shown_only_when_their_follow_list_confirms() {
        let owner = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let real = SigningKey::generate(&mut OsRng);
        let liar = SigningKey::generate(&mut OsRng);
        let unfetched = SigningKey::generate(&mut OsRng);

        let mut pointers: Vec<InboxPointer> = Vec::new();
        // Real follower announces twice (refollow) — must dedupe to one.
        pointers.push(announce(&real, actions::FOLLOW_ANNOUNCE_TARGET, 1));
        pointers.push(announce(&real, actions::FOLLOW_ANNOUNCE_TARGET, 2));
        // Liar announces but their follow list doesn't contain owner.
        pointers.push(announce(&liar, actions::FOLLOW_ANNOUNCE_TARGET, 3));
        // Announcer whose feed hasn't arrived yet.
        pointers.push(announce(&unfetched, actions::FOLLOW_ANNOUNCE_TARGET, 4));
        // Ordinary reply pointer must not count as a follower.
        pointers.push(announce(&real, PostId([7u8; 16]), 5));

        let mut feeds: BTreeMap<[u8; 32], Option<FeedStateV1>> = BTreeMap::new();
        feeds.insert(real.verifying_key().to_bytes(), Some(feed_following(&real, &[owner])));
        feeds.insert(liar.verifying_key().to_bytes(), Some(feed_following(&liar, &[])));
        feeds.insert(unfetched.verifying_key().to_bytes(), None);

        assert_eq!(
            confirmed_followers(&pointers, &feeds, &owner),
            vec![real.verifying_key().to_bytes()]
        );
    }

    /// The same reply pointer held in both inbox generations must count
    /// once; distinct replies from one replier must all survive.
    #[test]
    fn generation_dedup_counts_shared_pointer_once() {
        let sk = SigningKey::generate(&mut OsRng);
        let shared = announce(&sk, PostId([1u8; 16]), 10);
        let v2_only = announce(&sk, PostId([1u8; 16]), 20);
        let v1_only = announce(&sk, PostId([1u8; 16]), 30);

        let merged = dedup_generations(
            vec![shared, v2_only],
            vec![shared, v1_only],
        );
        assert_eq!(merged.len(), 3);
        assert_eq!(merged.iter().filter(|p| **p == shared).count(), 1);
    }

    /// Dual-read merge for Discover: one row per author, v2 wins even when
    /// its last_active is older, rows sorted newest-active first.
    #[test]
    fn discover_listings_merge_v2_wins_newest_first() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let legacy = [(a, 50), (b, 90)];
        let v2 = [(b, 10), (c, 70)];
        assert_eq!(merged_listings(&legacy, &v2), vec![(c, 70), (a, 50), (b, 10)]);
    }

    /// The fetch sample must include authors whose feed is absent AND
    /// authors stuck on the pending/failed `None` placeholder (the session
    /// black-hole), skip resolved feeds and ones already attempted this
    /// visit, and honor the sample cap.
    #[test]
    fn discover_fetches_unresolved_feeds_once_per_visit() {
        let missing = [1u8; 32];
        let pending = [2u8; 32];
        let loaded = [3u8; 32];
        let tried = [4u8; 32];
        let beyond = [5u8; 32];

        let sk = SigningKey::generate(&mut OsRng);
        let mut feeds: BTreeMap<[u8; 32], Option<FeedStateV1>> = BTreeMap::new();
        feeds.insert(pending, None);
        feeds.insert(loaded, Some(feed_following(&sk, &[])));
        feeds.insert(tried, None);

        let attempted: std::collections::BTreeSet<[u8; 32]> =
            [tried].into_iter().collect();
        let listings =
            vec![(missing, 50), (pending, 40), (loaded, 30), (tried, 20), (beyond, 10)];

        assert_eq!(
            feeds_to_fetch(&listings, &feeds, &attempted, 4),
            vec![missing, pending]
        );
    }
}
