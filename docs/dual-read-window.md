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

Rotating a contract therefore means, in one reviewed change:

1. rebuild reproducibly (`make build-docker`) and vendor the new bytes;
2. re-vendor `<role>_v1.wasm` from the commit in `scripts/live-build.txt`;
3. `make pin-hashes`, bump the role's `*_GENERATION` in `ui/src/keys.rs`,
   update `golden_addresses_pinned`;
4. mirror the outgoing wire types in `ui/src/legacy.rs` if their shape or
   signature scheme changed, and give the role a read path.

Step 4 is why the legacy types live in the **UI crate**: a `legacy` module
inside a contract crate is compiled into that contract's wasm and would
rotate the very address it exists to read.

## What closes each window

A window with no terminator never closes; #56 was filed about exactly that.
Per role, as of this release:

| role | terminator | forced by |
|---|---|---|
| feed | `actions::migrate_v1` re-signs v1 posts into the new feed | the owner, automatically at resume |
| avatar | `actions::migrate_avatar` re-signs the legacy blob into the rotated contract | the owner, automatically once the legacy read lands |
| directory | the listing-refresh effect republishes our listing under the new key each session | the owner, automatically at resume |
| inbox | repliers reposting — **nothing can force it** | nobody |

The inbox is the honest exception. A pointer is signed by its replier and
only that replier can re-sign it, so the pointers an account *received*
under the old generation migrate only as those repliers return.
`migrate_v1` migrates the replies each account *sent*, which is the same
population seen from the other side: the window closes when enough of the
network has resumed once, not on a date.

Closing is a publisher act, per role, via the control-cell flags — the
defaults are all ON:

- `read_v1_feed`
- `read_v1_inbox`
- `read_v1_directory`
- `read_v1_avatar`

Turning one off stops the legacy GET entirely. Nothing is destroyed either
way: the old state stays at its old address, it simply stops being read.
