# The dual-read window

Contract addresses are content-derived: rotating a contract's wasm bytes
mints a new address, and the state at the old one is still there — just
unread. The dual-read window is the period during which a new build reads
BOTH generations and writes only the new one.

Issue #81 was the window being open but aimed wrong: the vendored `_v1`
blobs named generation 1 while the live build had rotated the inbox and the
directory twice past it, and the avatar had no legacy read at all. Feeds and
identity survived an upgrade; Discover listings, replies and profile
pictures did not.

## The invariant

> A `ui/contracts/<role>_v1.wasm` must be byte-identical to the currently
> published build's `ui/contracts/<role>.wasm`.

`_v1` is a **name**, not a generation number. The live commit is recorded in
`scripts/live-build.txt`; `make check-legacy-wasm` (run in CI, and as a
prerequisite of `make publish`) compares each blob against that commit's
bytes straight out of git.

`freebird_delegate_v1.wasm` is deliberately **exempt**. The delegate has no
dual-read window: `LEGACY_DELEGATE_WASMS` is a *cumulative* registry of every
generation ever shipped, because the startup probe folds each old
generation's stored posting-key seed forward (#53). Forcing it to equal the
live build would overwrite the oldest entry and destroy the seed of anyone
still on it.

Rotating a contract therefore means, in one reviewed change:

1. rebuild reproducibly (`make build-docker`) and vendor the new bytes;
2. re-vendor `<role>_v1.wasm` from the commit in `scripts/live-build.txt`;
3. `make pin-hashes`; bump the role's `*_GENERATION` in `ui/src/keys.rs` if
   it has one (inbox, feed and avatar are anchor roles and do; the directory
   is a doorbell contract with no anchor role and no constant), and update
   `golden_addresses_pinned`;
4. mirror the outgoing wire types in `ui/src/legacy.rs` if their shape or
   signature scheme changed, give the role a read path, and **regenerate the
   CBOR KATs** in that module's tests.

If a release rotates only *some* roles, the un-rotated ones' `_v1` blob is
legitimately identical to the current one. Drop that role's legacy GET for
the release rather than pointing a window at your own address, and drop its
row from `each_generation_derives_a_distinct_address`.

Step 4 is why the legacy types live in the **UI crate**: a `legacy` module
inside a contract crate is compiled into that contract's wasm, so adding one
rotates that contract's *current* address — opening a new window instead of
closing one.

## Two traps in the current tree

**`directory_contract::legacy` is dead code that must not be deleted.** It
still says it exists "so clients can decode the old directory during the
dual-read migration window" — no longer true; the UI mirrors the live shape
in `ui/src/legacy.rs` and nothing outside `directory-contract` references
it. It is left in place because removing a `pub mod` from a contract crate
changes that crate's wasm bytes and **rotates the live directory address**.
Its comment was not corrected in place for the same reason: contracts embed
`file:line` panic locations, so even a comment-only edit can shift bytes.
Retire it on the next intentional directory rotation, never as cleanup. Note
it exports `DIRECTORY_SEED_V1` — the dead-generation seed that caused #81.
Do not reach for it.

**`scripts/live-build.txt` is human-maintained.** `make check-legacy-wasm`
proves the blobs agree with the commit that file *names*; nothing proves
that commit is what is actually deployed. Skip the post-publish follow-up
and the window aims a generation behind with CI green — #81's exact failure.
`make publish` prints the steps and gates on the check, but closing this
properly needs the publisher to write the commit as part of publishing.

## What closes each window

A window with no terminator never closes; #56 was filed about exactly that.
Per role, as of this release:

| role | per-account terminator | network-wide closure |
|---|---|---|
| feed | `actions::migrate_v1` re-signs old posts into the new feed | as each owner resumes — no cross-account dependency |
| avatar | `actions::migrate_avatar` re-signs the legacy blob | as each owner resumes — no cross-account dependency |
| directory | the listing-refresh effect republishes our own listing | **only as every listed author returns** |
| inbox | `migrate_v1` re-sends the replies we *sent* | **only as every replier returns** |

Feed and avatar are self-contained: an account's own data is whole once that
account has resumed once, so those windows can close on a schedule.

**The directory and the inbox cannot.** Both are collections of records
written by *other* people, and only the signer can re-sign. Our listing
refresh republishes exactly one row — our own — so Discover is complete only
when every listed author has come back; a reply pointer is signed by its
replier, so a thread is complete only when every replier has. `migrate_v1`
covers the replies we sent, which is the same population seen from the other
side, but neither window closes on a date — only on "enough of the network
has resumed once".

This is worth stating plainly because the *opposite* claim — "listings
re-seat on republish, and inbox creds/pointers re-staple as repliers repost"
— is what justified shipping no window at all across five rotations, and is
the direct cause of issue #81. Re-seating is real; it is just not something
any one client can drive, and treating it as automatic empties Discover.

Closing is a publisher act, per role, via the control-cell flags — the
defaults are all ON:

- `read_v1_feed`
- `read_v1_inbox`
- `read_v1_directory`
- `read_v1_avatar`

Turning one off stops the legacy GET entirely. Nothing is destroyed either
way: the old state stays at its old address, it simply stops being read.
