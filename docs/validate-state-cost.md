# Full-state `validate_state` cost — why it stays uncached (#52 / #71)

Issue #52 flagged unbounded, uncached RSA attestation verification on the
network's hot contracts. PR #70 fixed the delta path (verify-after-LWW +
held-attestation skip: replayed and losing entries cost zero crypto). This
note records why the **full-state** `validate_state` path stays as it is, so
the analysis isn't redone every time someone rediscovers the cost. Residual
tracked in #71.

This doc deliberately lives in `docs/` and not as comments in the contract
crates: contract source is byte-frozen between rotations (any wasm byte
change rotates the address — see `docs/reproducible-builds.md` — and CI
pins exact hashes). Even comment-only edits can change the bytes: the
vendored wasm embeds panic-location file:line strings (check with
`strings ui/contracts/directory_contract.wasm`), which shift with source
lines.

## The cost, bounded

`validate_state` → `DirectoryStateV4::verify()` (directory,
`contracts/directory-contract/src/lib.rs`) and the inbox `verify()`
(`contracts/inbox-contract/src/state.rs`) run the full attestation chain —
ed25519 listing signature, master→notary ed25519, notary→ghost blind-RSA,
proof-of-possession ed25519 — for every attested entry. Bounded at
`MAX_LISTINGS = 1000` / `MAX_POINTERS = 300` per call; never cached across
calls.

Measured natively (arm64, release, ghostkey_lib 0.2.0, 2026-08-12):
`AttestationV2::verify` ≈ 270µs per entry, of which the certificate chain
(notary ed25519 + ghost blind-RSA) ≈ 190µs and the notary cert alone
(master ed25519) ≈ 40µs. A full 1000-listing state is therefore ≈ 0.3s of
signature work natively, before the wasm slowdown multiplier (unmeasured).

## Why no in-contract cache is possible

1. **No cross-call memory.** freenet-core creates a fresh wasm instance per
   contract call and drops it afterward (`RunningInstance` RAII in
   `crates/core/src/wasm_runtime/runtime.rs`; verified at freenet-core
   `cc70301e`). Only compiled modules are cached — linear memory never
   survives, so a `static` memo of verified attestations is dead on arrival.
2. **No held-state context.** `validate_state` receives (parameters, state,
   related), but the `RelatedContracts` channel that could carry the held
   state arrives empty — the mechanism is incomplete upstream (freenet-core
   #2870, the same blocker as our #66). So it cannot skip entries "already
   held and verified" because it cannot see what is held.
3. **It cannot be weakened.** Fresh adoption of a state a node has never
   held (`verify_and_store_contract` in freenet-core) is guarded by
   `validate_state` **alone** — no merge runs. Skipping RSA there would let
   a fabricated state seat unattested entries in the attested tier.
4. **No whole-attestation duplicates within a call.** Attestations are
   unique per author / posting key (one slot each), so a per-call memo of
   whole verified attestations has nothing to hit. The one sub-component
   shared across entries — the notary certificate inside every ghost cert —
   IS duplicated intra-call; memoizing it is the small deferred lever below,
   not an impossibility.

## Where the replay amplification actually lives (upstream)

As of freenet-core `cc70301e`, `bridged_upsert_contract_state_inner`
validates an incoming full state at entry
(`contract/executor/runtime/executor_impl.rs:411`) **before** the
byte-identical dedup short-circuit (`executor_impl.rs:735`). Worse, any
**subset** of a valid state is itself a valid state with distinct bytes, so
one harvested state yields unbounded distinct valid replay variants — free
to mint (no keys, no PoW), each costing every receiving node a full
validate. No contract-side change can distinguish these from a legitimate
first sync. The real fix is upstream (held-state-aware validation, verdict
cache, or rate limiting) — tracked in #71. (Line numbers are exact at the
pinned commit; the function names are the durable anchors.)

## What is already cheap

- Delta path: replayed and LWW-losing entries cost zero crypto (#70).
- Client re-PUT of an already-held state: merge returns unchanged →
  early return, `validate_state` never runs
  (freenet-core `contract_ops.rs`, re-PUT branch).

## Deferred in-repo lever

Per-call notary-certificate memo: every attestation in a state typically
shares one `NotaryCertificateV1`, so its master-ed25519 verify could run
once per call instead of per entry — measured at ~40µs of the ~270µs
per-entry verify (~15%, native). The per-entry blind-RSA verify is
irreducible, and the RSA key's parse happens at state CBOR deserialization
before `verify()` is ever called, so a memo cannot save it. Changing this
code rotates the directory/inbox addresses, so it is only worth batching
with a rotation those contracts need anyway (#71).
