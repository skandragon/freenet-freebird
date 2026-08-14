---
type: feature
title: The trust rule — everyone writes, paying buys durability
description: Anonymous accounts have the full product; a Ghost Key check mark buys durable, uncrowdable presence on shared-write surfaces rather than permission to write. How the two-tier slot policy expresses that in the inbox and the directory.
timestamp: 2026-08-14T00:00:00Z
---

The positioning no centralized competitor can copy, and the constraint every
shared-write surface has to satisfy. Product framing and principles live in
[`PRODUCT.md`](../../PRODUCT.md); this is the behavior the contracts enforce.

- MUST let an anonymous account do everything: post, follow, reply into a
  thread, and appear in Discover. Signup is a locally generated key, instant and
  offline.
- MUST NOT gate any shared-write surface on payment. A surface that refuses
  anonymous writes has broken the rule, whatever else it gains.
- MUST divide each shared-write surface into two tiers: anonymous writers share
  a bounded slot pool and can be crowded out under load; attested writers
  cannot. The check mark therefore means "durable, uncrowdable presence", never
  "permitted to write".
- MUST verify attestation in the contract, offline, against the certificate
  chain — never trust a claim the UI asserts. Attestation is verified where it
  is enforced.
- MUST bind an attestation to this application, so a Ghost Key signature
  harvested by another application cannot be replayed here. [#45]
- MUST hold attestation optional. A dead or unreachable mint costs durability,
  not access — which is what keeps the centrally operated mint from being a
  central point of control.

The anonymous tier is additionally rate-limited by proof of work rather than by
identity; see [anonymous-PoW difficulty](../specs/anon-pow-difficulty.md).

## Disclosure obligation

Wherever verification is offered, the UI states plainly that the check mark
costs money, that the money funds Freenet, and that the mint is centrally
operated — a master-key compromise could issue unlimited check marks, and card
rails can decline or geo-block. Honesty about the one centralized component is
part of the feature, not a caveat bolted onto it.

The two-tier policy replaced an earlier design that gated inbox writes on a
Ghost Key outright. Design record:
[`docs/superpowers/specs/2026-08-10-anonymous-parity.md`](../../docs/superpowers/specs/2026-08-10-anonymous-parity.md).
