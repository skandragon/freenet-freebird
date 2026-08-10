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

fn author_name(author: &[u8; 32]) -> String {
    FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.profile.profile.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| short_key(author))
}

/// Deterministic per-author color chip: two hues derived from the key.
fn identicon_style(author: &[u8; 32]) -> String {
    let h1 = (((author[0] as u16) << 8 | author[1] as u16) % 360) as u16;
    let h2 = (h1 + 40 + (author[2] % 140) as u16) % 360;
    format!("background: linear-gradient(135deg, hsl({h1},65%,55%), hsl({h2},65%,38%))")
}

fn is_verified(author: &[u8; 32]) -> bool {
    FEEDS
        .read()
        .get(author)
        .and_then(|f| f.as_ref())
        .map(|f| f.attestation.0.is_some())
        .unwrap_or(false)
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
                    svg {
                        view_box: "0 0 24 24",
                        fill: "currentColor",
                        "aria-hidden": "true",
                        path { d: "M3 13 C7 6 14 4 22 4 C19 7 17 8 14 9 C16 9 18 9 20 9 C17 12 13 13 10 13 C7 13 5 14 4 16 C3.5 15 3 14 3 13 Z" }
                    }
                    "Freebird"
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
            if onboarded {
                match *VIEW.read() {
                    View::Home => rsx! { Home {} },
                    View::Profile => rsx! { ProfilePage {} },
                }
            } else if awaiting_key && matches!(status, SyncStatus::Connected | SyncStatus::Connecting) {
                p { class: "muted", "Loading account…" }
            } else {
                Onboarding {}
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
                            span { class: "avatar", style: identicon_style(&target) }
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
    let own_verified = own_author().map(|a| is_verified(&a)).unwrap_or(false);
    let over = text.read().len() > limit;

    let mut submit = move || {
        let content = text.peek().trim().to_string();
        if content.is_empty() || text.peek().len() > limit {
            return;
        }
        let verified_now = own_author().map(|a| is_verified(&a)).unwrap_or(false);
        error.set(String::new());
        notice.set(String::new());
        spawn(async move {
            match actions::publish_post(content, in_reply_to).await {
                Ok(()) => {
                    text.set(String::new());
                    if is_reply {
                        notice.set(if verified_now {
                            "Reply posted to the thread.".into()
                        } else {
                            "Reply posted to your feed.".into()
                        });
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
            if is_reply && !own_verified {
                p { class: "muted",
                    "This reply will post to your own feed, where your followers see it. \
                     It won't appear in this thread — that takes a verified account."
                }
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
        all.truncate(100);
        all
    };

    rsx! {
        div { class: "timeline",
            if posts.is_empty() {
                p { class: "muted", "Nothing here yet. Peep something above, or add an author's address in the Following box." }
            }
            for (author, post) in posts {
                PostCard { author, post: post.clone() }
            }
        }
    }
}

#[component]
fn PostCard(author: [u8; 32], post: AuthorizedPost) -> Element {
    let mut show_reply = use_signal(|| false);
    let mut show_thread = use_signal(|| false);
    let name = author_name(&author);
    let verified = is_verified(&author);
    let post_ref = PostRef {
        author,
        post: post.post.id,
    };
    let reply_count = INBOXES
        .read()
        .get(&author)
        .map(|i| {
            i.pointers
                .pointers
                .iter()
                .filter(|p| p.ptr.target_post == post.post.id)
                .count()
        })
        .unwrap_or(0);

    rsx! {
        article { class: "card post",
            div { class: "post-head",
                span { class: "avatar", style: identicon_style(&author) }
                strong { "{name}" }
                if verified { span { class: "check", title: "Ghost Key verified", "✔" } }
                span { class: "muted", "@{short_key(&author)} · {ago(post.post.time)}" }
            }
            if let Some(parent) = post.post.in_reply_to {
                p { class: "muted replying-to", "replying to @{short_key(&parent.author)}" }
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

    // Pointers targeting this post, resolved into (replier_key, post).
    let replies: Vec<([u8; 32], Option<AuthorizedPost>)> = {
        let inboxes = INBOXES.read();
        let feeds = FEEDS.read();
        inboxes
            .get(&author)
            .map(|inbox| {
                inbox
                    .pointers
                    .pointers
                    .iter()
                    .filter(|p| p.ptr.target_post == post_id)
                    .filter_map(|p| {
                        inbox.creds.creds.get(&p.ptr.replier)?;
                        let replier = p.ptr.replier;
                        let found = feeds.get(&replier).and_then(|f| f.as_ref()).and_then(|f| {
                            f.posts
                                .posts
                                .iter()
                                .find(|x| x.post.id == p.ptr.reply_post)
                                // The reply must actually claim THIS post as
                                // its parent — a pointer alone must not let
                                // anyone graft an arbitrary peep into a
                                // stranger's thread.
                                .filter(|x| {
                                    x.post.in_reply_to
                                        == Some(PostRef {
                                            author,
                                            post: post_id,
                                        })
                                })
                                .cloned()
                        });
                        Some((replier, found))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    // Fetch replier feeds we don't have yet.
    use_effect(move || {
        let missing: Vec<[u8; 32]> = {
            let inboxes = INBOXES.read();
            let feeds = FEEDS.read();
            inboxes
                .get(&author)
                .map(|inbox| {
                    inbox
                        .pointers
                        .pointers
                        .iter()
                        .map(|p| p.ptr.replier)
                        .filter(|k| !feeds.contains_key(k))
                        .collect()
                })
                .unwrap_or_default()
        };
        for replier in missing {
            spawn(async move {
                let _ = api::fetch_feed(replier).await;
            });
        }
    });

    let inbox_loaded = INBOXES.read().contains_key(&author);

    rsx! {
        div { class: "thread",
            if replies.is_empty() {
                if inbox_loaded {
                    p { class: "muted", "No verified replies yet." }
                } else {
                    p { class: "muted", "Checking for replies…" }
                }
            }
            for (replier, reply) in replies {
                match reply {
                    Some(post) => rsx! { PostCard { author: replier, post } },
                    None => rsx! { p { class: "muted", "loading reply from @{short_key(&replier)}…" } },
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
    let full_key = bs58::encode(&author).into_string();

    rsx! {
        section { class: "card",
            h3 {
                span { class: "avatar", style: identicon_style(&author) }
                " {author_name(&author)}"
                if is_verified(&author) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
            }
            p { class: "muted keyline", "Your address (share to be followed):" }
            code { class: "keyline", "{full_key}" }
            button { class: "link", onclick: move |_| *VIEW.write() = View::Profile,
                "view profile"
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
                        span { class: "avatar", style: identicon_style(&f) }
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
                p { span { class: "check", "✔" } " This account has earned the Prized Checkmark. Your replies land in other people's threads." }
            } else {
                p { class: "muted",
                    "Anonymous accounts peep freely to their own feed, but replies are only \
                     visible to followers. A Ghost Key adds a check mark and puts your replies \
                     in the thread."
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
                    span { class: "avatar lg", style: identicon_style(&author) }
                    " {author_name(&author)}"
                    if is_verified(&author) { span { class: "check", role: "img", title: "Ghost Key verified", aria_label: "Ghost Key verified", "✔" } }
                }
                if let Some(f) = &feed {
                    if !f.profile.profile.bio.is_empty() {
                        p { "{f.profile.profile.bio}" }
                    }
                }
                p { class: "muted keyline", "Your address:" }
                code { class: "keyline", "{full_key}" }
                p { class: "muted keyline", "Share this link — anyone opening it can follow you in one click:" }
                code { class: "keyline", "{follow_link(&author)}" }
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
            VerifyBox {}
            DangerZone {}
        }
    }
}
