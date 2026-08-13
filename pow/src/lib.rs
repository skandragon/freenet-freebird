//! Proof-of-work for anonymous writes (issue #51).
//!
//! The anonymous tier of the inbox and directory contracts had no cost
//! function: a throwaway keygen loop captured an inbox's anon share (~34 keys)
//! or the whole anonymous Discover share (~250 keys) in milliseconds. This
//! crate adds a hashcash-style stamp that every ANONYMOUS write must carry;
//! attested (ghost-key) writes skip it entirely — the free path pays PoW, the
//! ghost key is the accelerator that skips the wait.
//!
//! Two knobs, and the split matters:
//!
//! - [`POW_FLOOR_BITS`] is COMPILED IN and enforced universally — in `verify`
//!   (fabricated full states) and in every apply/merge. It is the only rule
//!   all peers agree on without coordination, so it is the only one that keeps
//!   the CRDT convergent, and therefore the only difficulty an ADVERSARY is
//!   actually held to. Set it to the guaranteed-minimum cost.
//! - The DIFFICULTY is the RETUNABLE bar: a publisher-signed record
//!   ([`difficulty_bits`]), verified in-contract, that a write carries and
//!   the contract then LATCHES INTO ITS STATE ([`adopt_difficulty`]). Raising
//!   it raises the cost with NO wasm rebuild (the "wasm-baked-constant"
//!   objection). It is clamped to `[POW_FLOOR_BITS, POW_CEILING_BITS]` so a
//!   compromised or fat-fingered publisher record can neither drop below the
//!   floor nor price honest users out.
//!
//! # Why the difficulty lives in the STATE (issue #66)
//!
//! #65 carried the difficulty record on the DELTA only. freenet-stdlib's
//! `update_state` gets no `RelatedContracts`, so the control cell can't be
//! read live at merge time — and a delta-only record is one an attacker
//! simply omits, paying the compiled floor while the knob bound honest
//! writers alone. `update_state` DOES get the state, so the record now
//! rides there: a delta's record is adopted into state by [`adopt_difficulty`]
//! (publisher-signed, strictly increasing `seq`), and every subsequent
//! admission is enforced against the LATCHED bits. An attacker can neither
//! forge a record (no publisher key) nor downgrade one (seq is monotone) nor
//! omit their way past it (the bar comes from state, not from their write).
//!
//! ponytail: a raise is not retroactive and not instantaneous. Entries seated
//! before it stay seated (full-state `verify` remains floor-only — that is
//! the convergent, fabricated-state-facing invariant), and an entry admitted
//! at a replica that has not yet received the raise is rejected by one that
//! has, so tier membership can differ for the propagation window. Both tiers
//! are LWW-evicting sets that authors republish into, so that divergence ages
//! out; the alternative (a raise nobody is bound by) is worse.

use cell_contract::{CellParametersV1, SignedCellV1};
use ed25519_dalek::VerifyingKey;

/// Compiled adversary floor: leading zero bits every anonymous stamp must
/// clear no matter what. ~2^20 ≈ 1M blake3 tries ≈ a fraction of a second of
/// browser CPU per key — milliseconds-per-key attacks become
/// seconds-to-minutes-per-share. Raising this rotates the contract wasm.
pub const POW_FLOOR_BITS: u8 = 20;

/// Compiled ceiling on the control-cell difficulty: the publisher can retune
/// UP to here without a rebuild, never past it. ponytail: keeps a bad control
/// record from demanding minutes of CPU and bricking honest posting; lift it
/// (a wasm rotation) only if a few seconds is provably not enough.
pub const POW_CEILING_BITS: u8 = 26;

/// Cell purpose naming the difficulty channel (frozen cell kernel, publisher
/// owner). Distinct from "control" so a build-number record can never be read
/// as a difficulty record or vice versa.
pub const POW_PURPOSE: &str = "pow";

/// Domain tags separating the inbox and directory PoW namespaces so a stamp
/// solved for one is worthless for the other. The `-v1` suffix is the
/// PoW-SCHEME version — it is independent of the inbox/directory CONTRACT
/// generation (currently v3) and does not track `DIRECTORY_SEED`. Cross-target
/// replay is prevented by the per-target binding (inbox owner / directory
/// author) in `meets_*`, not by these tags; bump a suffix only if the hashcash
/// scheme itself changes.
pub const POW_DOMAIN_INBOX: &[u8] = b"freebird-pow-inbox-v1";
pub const POW_DOMAIN_DIRECTORY: &[u8] = b"freebird-pow-dir-v1";

/// The control-cell publisher key (hex) — the ONLY key whose difficulty
/// records the contracts honor. Duplicated from `freebird-control`'s
/// `PUBLISHER_VK_HEX` on purpose: contracts must not depend on that
/// client-side crate. Keep the two in sync if the publisher key is ever
/// rotated.
pub const PUBLISHER_VK_HEX: &str =
    "7fd93de864ba7940a06433143f4e1454092ca1226d5233305df499431a3181d2";

/// Well-known publisher SECRET used only under the `test-publisher` feature so
/// downstream contract tests can mint valid difficulty records. Never present
/// in a shipped wasm.
#[cfg(feature = "test-publisher")]
pub const PUBLISHER_TEST_SECRET: [u8; 32] = [42u8; 32];

#[cfg(feature = "test-publisher")]
pub fn publisher_key() -> VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(&PUBLISHER_TEST_SECRET).verifying_key()
}

#[cfg(not(feature = "test-publisher"))]
pub fn publisher_key() -> VerifyingKey {
    let bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(PUBLISHER_VK_HEX.as_bytes())
        .expect("compiled-in publisher key is hex")
        .try_into()
        .expect("publisher key is 32 bytes");
    VerifyingKey::from_bytes(&bytes).expect("compiled-in publisher key parses")
}

/// Params of the difficulty cell: publisher-owned, purpose "pow".
pub fn pow_params() -> CellParametersV1 {
    CellParametersV1 {
        owner: publisher_key(),
        purpose: POW_PURPOSE.into(),
    }
}

/// Encode a difficulty record body: a single clamped byte. `SignedCellV1::new`
/// wraps and signs it with the publisher key.
pub fn difficulty_body(bits: u8) -> Vec<u8> {
    vec![bits.clamp(POW_FLOOR_BITS, POW_CEILING_BITS)]
}

/// The effective admission difficulty for a write that carries `record`.
///
/// A validly publisher-signed record raises the bar to its clamped bits; a
/// missing record — or any record that fails the publisher signature — falls
/// back to the floor. Never returns below `POW_FLOOR_BITS` or above
/// `POW_CEILING_BITS`.
pub fn difficulty_bits(record: Option<&SignedCellV1>) -> u8 {
    match record {
        Some(cell) if cell.check(&pow_params()).is_ok() => cell
            .body
            .first()
            .copied()
            .unwrap_or(POW_FLOOR_BITS)
            .clamp(POW_FLOOR_BITS, POW_CEILING_BITS),
        _ => POW_FLOOR_BITS,
    }
}

/// The `seq` of a latched difficulty record; 0 when there is none. Rides the
/// state summary so a raise propagates on its own, without waiting for a
/// listing/pointer delta to carry it.
pub fn difficulty_seq(record: Option<&SignedCellV1>) -> u64 {
    record.map_or(0, |c| c.seq)
}

/// Latch `incoming` into `held` if it is a genuine publisher record that
/// strictly supersedes what is held. Returns whether `held` changed.
///
/// This is the whole of #66's fix: monotone in `seq` and gated on the
/// publisher signature, so the only party who can move the bar — in either
/// direction — is the publisher. An attacker can replay an old record (no
/// effect) or omit one (no effect); they cannot lower the latched bar, and
/// the bar they must clear is the latched one, not the one they chose to
/// send.
pub fn adopt_difficulty(held: &mut Option<SignedCellV1>, incoming: Option<&SignedCellV1>) -> bool {
    let Some(cell) = incoming else { return false };
    if cell.seq <= difficulty_seq(held.as_ref()) || cell.check(&pow_params()).is_err() {
        return false;
    }
    *held = Some(cell.clone());
    true
}

/// blake3 over domain-tag ‖ key ‖ binding ‖ nonce. `key` is the anonymous
/// posting key (so a solve is per-sybil), `binding` ties the stamp to THIS
/// target (inbox owner / directory generation) so it can't be replayed
/// elsewhere.
pub fn pow_hash(domain: &[u8], key: &[u8; 32], binding: &[u8], nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(key);
    h.update(binding);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Leading zero bits of a 32-byte hash.
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Does `nonce` clear `bits` leading zeros for this binding?
pub fn meets(domain: &[u8], key: &[u8; 32], binding: &[u8], nonce: u64, bits: u8) -> bool {
    leading_zero_bits(&pow_hash(domain, key, binding, nonce)) >= bits as u32
}

/// Find a nonce clearing `bits`. Pure integer loop, no RNG — safe in wasm.
/// ponytail: single-threaded scan; the caller (UI) runs it off the render
/// path. Expected ~2^bits tries.
pub fn solve(domain: &[u8], key: &[u8; 32], binding: &[u8], bits: u8) -> u64 {
    (0u64..).find(|&n| meets(domain, key, binding, n, bits)).expect("u64 nonce space exhausted")
}

// ---- per-contract binders ----

/// Inbox anon stamp: keyed by the replier's posting key, bound to the inbox
/// owner (so a solve for inbox A is worthless in inbox B).
pub fn meets_inbox(owner: &[u8; 32], replier: &[u8; 32], nonce: u64, bits: u8) -> bool {
    meets(POW_DOMAIN_INBOX, replier, owner, nonce, bits)
}

pub fn solve_inbox(owner: &[u8; 32], replier: &[u8; 32], bits: u8) -> u64 {
    solve(POW_DOMAIN_INBOX, replier, owner, bits)
}

/// Directory anon stamp: keyed by (and bound to) the author's posting key —
/// the directory is a single global instance, so the key alone is the target.
/// Republishing (a new `last_active`) reuses the same solve, so refreshing a
/// listing stays free.
pub fn meets_directory(author: &[u8; 32], nonce: u64, bits: u8) -> bool {
    meets(POW_DOMAIN_DIRECTORY, author, &[], nonce, bits)
}

pub fn solve_directory(author: &[u8; 32], bits: u8) -> u64 {
    solve(POW_DOMAIN_DIRECTORY, author, &[], bits)
}

// ---- test helpers: a stamp provably INSIDE a difficulty band ----
// A plain `lo`-bit solve also clears `hi` bits with probability 2^-(hi-lo), so
// tests that need a stamp accepted at `lo` but rejected at `hi` must pin it to
// the band or they flake. Public (not #[cfg(test)]) because the inbox/directory
// crates' tests consume them.

pub fn solve_inbox_band(owner: &[u8; 32], replier: &[u8; 32], lo: u8, hi: u8) -> u64 {
    (0u64..)
        .find(|&n| meets_inbox(owner, replier, n, lo) && !meets_inbox(owner, replier, n, hi))
        .expect("u64 nonce space exhausted")
}

pub fn solve_directory_band(author: &[u8; 32], lo: u8, hi: u8) -> u64 {
    (0u64..)
        .find(|&n| meets_directory(author, n, lo) && !meets_directory(author, n, hi))
        .expect("u64 nonce space exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    // A low bar so the solver stays instant in tests; production uses the
    // floor. leading_zero_bits/meets are difficulty-agnostic.
    const TEST_BITS: u8 = 8;

    /// Drift-guard: our compiled-in publisher key must match the canonical one
    /// in freebird-control. A future publisher-key rotation that touches only
    /// one copy fails here instead of silently making difficulty records
    /// unverifiable in-contract.
    #[test]
    fn publisher_key_matches_control() {
        assert_eq!(PUBLISHER_VK_HEX, freebird_control::PUBLISHER_VK_HEX);
    }

    #[test]
    fn leading_zeros_counts() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        let mut h = [0u8; 32];
        h[0] = 0x0f; // 0000_1111
        assert_eq!(leading_zero_bits(&h), 4);
        h[0] = 0x80;
        assert_eq!(leading_zero_bits(&h), 0);
    }

    #[test]
    fn solve_then_meets() {
        let key = [7u8; 32];
        let owner = [9u8; 32];
        let n = solve_inbox(&owner, &key, TEST_BITS);
        assert!(meets_inbox(&owner, &key, n, TEST_BITS));
        // Same solve is worthless against a different inbox owner (replay).
        assert!(!meets_inbox(&[10u8; 32], &key, n, TEST_BITS) || TEST_BITS == 0);
    }

    #[test]
    fn directory_solve_binds_to_author() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let n = solve_directory(&a, TEST_BITS);
        assert!(meets_directory(&a, n, TEST_BITS));
        assert!(!meets_directory(&b, n, TEST_BITS) || TEST_BITS == 0);
    }

    #[test]
    fn difficulty_floor_and_ceiling() {
        // No record → floor.
        assert_eq!(difficulty_bits(None), POW_FLOOR_BITS);

        let sk = SigningKey::generate(&mut OsRng);
        let real_pub = sk.verifying_key();
        // A record signed by the WRONG key is ignored → floor.
        let bogus = SignedCellV1::new(&sk, POW_PURPOSE, 1, difficulty_body(24));
        assert_eq!(difficulty_bits(Some(&bogus)), POW_FLOOR_BITS);

        // Sanity: a record signed by `real_pub` and checked against `real_pub`
        // reads its clamped bits (mirrors the publisher path).
        let params = CellParametersV1 {
            owner: real_pub,
            purpose: POW_PURPOSE.into(),
        };
        let rec = SignedCellV1::new(&sk, POW_PURPOSE, 1, difficulty_body(99));
        assert!(rec.check(&params).is_ok());
        assert_eq!(rec.body[0], POW_CEILING_BITS, "body clamps to ceiling");
    }

    /// Issue #66: nothing an attacker can mint moves the latched bar. (The
    /// publisher-signed accept path needs the `test-publisher` key, so it is
    /// exercised in the directory/inbox crates, which enable that feature.)
    #[test]
    fn adopt_rejects_forged_and_stale() {
        let sk = SigningKey::generate(&mut OsRng);
        let forged = SignedCellV1::new(&sk, POW_PURPOSE, 9, difficulty_body(26));

        let mut held = None;
        assert!(!adopt_difficulty(&mut held, Some(&forged)), "unsigned by publisher");
        assert!(held.is_none());
        assert!(!adopt_difficulty(&mut held, None));

        // A held record is never displaced by an equal-or-lower seq, even a
        // genuine one — so a replayed old record cannot walk difficulty back.
        held = Some(SignedCellV1::new(&sk, POW_PURPOSE, 5, difficulty_body(24)));
        let stale = SignedCellV1::new(&sk, POW_PURPOSE, 5, difficulty_body(20));
        assert!(!adopt_difficulty(&mut held, Some(&stale)));
        assert_eq!(difficulty_seq(held.as_ref()), 5);
    }
}
