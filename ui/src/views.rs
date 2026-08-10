//! UI components. One file — the MVP surface is small.

use dioxus::prelude::*;
use freebird_core::feed::FeedStateV1;
use freebird_core::types::{AuthorizedPost, PostRef};

use crate::actions;
use crate::api;
use crate::keys;
use crate::state::*;

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
                if let Err(e) = api::register_freebird_delegate().await {
                    api::log(&format!("delegate registration failed: {e}"));
                }
                let _ = api::kv_request(
                    freebird_core::delegate_api::FreebirdDelegateRequest::Get {
                        key: "posting_key".into(),
                    },
                )
                .await;
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
        document::Stylesheet { href: asset!("/assets/main.css") }
        div { class: "app",
            header {
                h1 { "Freebird" }
                span { class: "status",
                    match &status {
                        SyncStatus::Connecting => "connecting…".to_string(),
                        SyncStatus::Connected => "connected".to_string(),
                        SyncStatus::Error(e) => format!("error: {e}"),
                    }
                }
            }
            if onboarded {
                Home {}
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
    rsx! {
        div { class: "columns",
            main {
                Compose { in_reply_to: None }
                Timeline {}
            }
            aside {
                MyAccount {}
                FollowBox {}
                VerifyBox {}
                SettingsBox {}
            }
        }
    }
}

#[component]
fn Compose(in_reply_to: Option<PostRef>) -> Element {
    let mut text = use_signal(String::new);
    let mut error = use_signal(String::new);
    let limit = freebird_core::feed::MAX_POST_BYTES;

    rsx! {
        div { class: "card compose",
            textarea {
                placeholder: if in_reply_to.is_some() { "Write a reply…" } else { "What's peeping?" },
                value: "{text}",
                oninput: move |e| text.set(e.value()),
            }
            div { class: "compose-row",
                span { class: "muted", "{text.read().len()}/{limit}" }
                button {
                    disabled: text.read().trim().is_empty() || text.read().len() > limit,
                    onclick: move |_| {
                        let content = text.read().trim().to_string();
                        error.set(String::new());
                        spawn(async move {
                            match actions::publish_post(content, in_reply_to).await {
                                Ok(()) => text.set(String::new()),
                                Err(e) => error.set(e),
                            }
                        });
                    },
                    if in_reply_to.is_some() { "Reply" } else { "Peep" }
                }
            }
            if !error.read().is_empty() { p { class: "error", "{error}" } }
        }
    }
}

#[component]
fn Timeline() -> Element {
    // Merge own + followed posts, newest first.
    let posts: Vec<([u8; 32], AuthorizedPost)> = {
        let feeds = FEEDS.read();
        let mut all: Vec<([u8; 32], AuthorizedPost)> = feeds
            .iter()
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
                p { class: "muted", "Nothing here yet. Peep something, or follow an author from the sidebar." }
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
                        let cred = inbox.creds.creds.get(&p.ptr.fingerprint)?;
                        let replier = cred.posting_key.to_bytes();
                        let found = feeds.get(&replier).and_then(|f| f.as_ref()).and_then(|f| {
                            f.posts
                                .posts
                                .iter()
                                .find(|x| x.post.id == p.ptr.reply_post)
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
                        .filter_map(|p| inbox.creds.creds.get(&p.ptr.fingerprint))
                        .map(|c| c.posting_key.to_bytes())
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

    rsx! {
        div { class: "thread",
            if replies.is_empty() {
                p { class: "muted", "No verified replies yet." }
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
    let author = own_author();
    let mut editing = use_signal(|| false);
    let mut name = use_signal(String::new);
    let mut bio = use_signal(String::new);

    let Some(author) = author else {
        return rsx! {};
    };
    let feed: Option<FeedStateV1> = FEEDS.read().get(&author).cloned().flatten();
    let full_key = bs58::encode(&author).into_string();

    rsx! {
        section { class: "card",
            h3 {
                "{author_name(&author)}"
                if is_verified(&author) { span { class: "check", "✔" } }
            }
            if let Some(f) = &feed {
                if !f.profile.profile.bio.is_empty() {
                    p { "{f.profile.profile.bio}" }
                }
            }
            p { class: "muted keyline", "Your address (share to be followed):" }
            code { class: "keyline", "{full_key}" }
            if *editing.read() {
                input { value: "{name}", oninput: move |e| name.set(e.value()), placeholder: "Name" }
                input { value: "{bio}", oninput: move |e| bio.set(e.value()), placeholder: "Bio" }
                button {
                    onclick: move |_| {
                        let (n, b) = (name.read().clone(), bio.read().clone());
                        spawn(async move {
                            if actions::publish_profile(n, b).await.is_ok() {
                                editing.set(false);
                            }
                        });
                    },
                    "Save"
                }
            } else {
                button { class: "link",
                    onclick: move |_| {
                        if let Some(f) = FEEDS.read().get(&author).cloned().flatten() {
                            name.set(f.profile.profile.name.clone());
                            bio.set(f.profile.profile.bio.clone());
                        }
                        editing.set(true);
                    },
                    "edit profile"
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
                        "{author_name(&f)}"
                        if is_verified(&f) { span { class: "check", "✔" } }
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
                placeholder: "Author address (base58)",
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
                        None => error.set("not a valid 32-byte base58 key".into()),
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

    // Complete the flow when the ghostkey delegate answers.
    use_effect(move || {
        let result = GHOSTKEY_SIGN_RESULT.read().clone();
        if let Some(result) = result {
            *GHOSTKEY_SIGN_RESULT.write() = None;
            match result {
                Ok((scoped, sig, cert)) => {
                    spawn(async move {
                        match actions::complete_verification(scoped, sig, cert).await {
                            Ok(tier) => message.set(format!("Verified ({tier})")),
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
                p { span { class: "check", "✔" } " This account is Ghost Key verified. Your replies land in other people's threads." }
            } else {
                p { class: "muted",
                    "Anonymous accounts peep freely to their own feed, but replies are only \
                     visible to followers. A Ghost Key adds a check mark and puts your replies \
                     in the thread."
                }
                button {
                    disabled: *busy.read(),
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
                p { class: "muted",
                    "Requires a Ghost Key in your node's Identity Vault — "
                    a { href: "https://freenet.org/ghostkey", target: "_blank", "get one here" }
                    "."
                }
            }
            if !message.read().is_empty() { p { "{message}" } }
        }
    }
}

#[component]
fn SettingsBox() -> Element {
    let mut value = use_signal(|| SETTINGS.read().ghostkey_delegate.clone());
    let mut saved = use_signal(|| false);

    rsx! {
        section { class: "card",
            h3 { "Settings" }
            label { class: "muted", "Ghostkey delegate code hash (base58)" }
            input {
                value: "{value}",
                oninput: move |e| { value.set(e.value()); saved.set(false); },
            }
            button {
                onclick: move |_| {
                    save_settings(&Settings { ghostkey_delegate: value.read().trim().to_string() });
                    saved.set(true);
                },
                "Save"
            }
            if *saved.read() { span { class: "muted", " saved" } }
        }
    }
}
