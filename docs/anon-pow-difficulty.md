# Anonymous-PoW difficulty lives in the state (#51 → #65 → #66)

## What #66 was

#65 gave the anonymous inbox/directory tiers an in-contract proof-of-work
bar. The difficulty had two sources: a compiled floor (`POW_FLOOR_BITS`, 20)
and a publisher-signed record the *writer attached to their own delta*.

The second source bound nobody. `pow_difficulty` was an `Option` on the
delta, so an attacker set it to `None` and paid the floor; gossip did the
same, re-admitting at the floor so replicas converged. The publisher's knob
therefore constrained honest opt-in writers **only**, and could not be raised
to any effect under active attack.

The issue framed the fix as blocked on freenet-stdlib: `update_state` — the
path every gossiped delta takes — receives no `RelatedContracts`, so the
control cell cannot be read live at merge time.

## What actually closes it

`update_state` receives no related contracts, but it does receive the
**state**. That is a third channel the issue did not consider, and it is
enough:

- `DirectoryStateV4` and `InboxStateV3` each carry
  `pow_difficulty: Option<SignedCellV1>`.
- `freebird_pow::adopt_difficulty` latches a record into that slot iff it is
  publisher-signed **and** strictly increases `seq`.
- Admission reads the bar off the **latched** record, not off the delta.

An attacker consequently cannot forge a record (no publisher key), cannot
downgrade one (monotone `seq`), and cannot omit their way past one (the bar
comes from state, not from their write). That is acceptance box 1.

The record reaches replicas by ordinary sync: the state summary carries
`pow_seq`, and `delta()` emits the record on its own when the peer's is
older — so a raise propagates to a quiet replica with no listings or
pointers to send. `merge()` (full-state sync) carries it too.

## Deliberate limits

**Not retroactive.** Full-state `verify()` still checks seated entries
against the compiled floor alone. This is not an oversight — it is the
convergent, fabricated-state-facing invariant. Gating re-validation on a
value that changes over time would make a state's validity depend on *when*
it was checked, and a raise would retroactively invalidate every entry
already seated. `verify()` does check that a latched record is genuinely
publisher-signed, so a fabricated state cannot seat a bogus one.

**Not instantaneous.** An entry admitted at a replica that has not yet
received the raise is rejected by one that has, so tier membership can differ
for the propagation window. Both tiers are LWW-evicting sets that authors
republish into, so the divergence ages out. The alternative — a raise nobody
is bound by — is worse.

**Per-owner inboxes latch lazily.** The publisher writes one global cell; the
directory is one global contract, so it latches as soon as any client relays
the record. Inboxes are per-owner instances with no global push, so an inbox
latches the raise the first time a #66-aware client writes to it. An inbox no
honest client ever writes to stays at the floor. Closing that needs a
publisher fan-out or an owner-side push on load; it is not in this change.

**The floor is still the adversary's true minimum** anywhere the raise has
not landed. Raising `POW_FLOOR_BITS` remains a deliberate wasm rotation.

## Operating it

```
freebird-ctl publish-difficulty --bits 24    # clamped to [20, 26]
freebird-ctl show                            # prints control + pow cells
```

The cell is the frozen cell kernel with `purpose = "pow"` — a distinct
address from the control cell, so a build record can never be read as a
difficulty record. Clients GET+subscribe it at startup
(`api::fetch_pow_difficulty`), solve to its bits, and attach it to anonymous
writes, which is what latches it into the contracts it governs.

Lowering works the same way: publish a lower value at a higher `seq`.

## Rotation this change requires

Contract source changed, so directory and inbox wasm bytes — and their
addresses — rotate. Per `docs/reproducible-builds.md`, before this ships:

1. On an amd64 host, rebuild `directory_contract` + `inbox_contract`, vendor
   into `ui/contracts/` (leave the other three alone).
2. `make pin-hashes`; refresh those two lines in
   `scripts/repro-reference-hashes.txt` (the unchanged crates must still
   match — that is the proof the environment is canonical).
3. Update the directory/inbox golden addresses in `ui/src/keys.rs`.
4. Migration: follow the #45/#49/#50/#51/#52 no-window precedent — listings
   re-seat on republish, inbox creds/pointers re-staple as repliers repost.

Both state types added their field with `#[serde(default)]`, so the CBOR wire
form of an existing state still decodes; the rotation is driven by the wasm
bytes, not by an incompatible encoding.
