---
type: policy
title: Publishing a release
description: The site goes out before the control cell, never the other way round, and every publish owes a follow-up PR that re-points the dual-read window at the newly live build. Issue #81 is what skipping that follow-up looks like.
timestamp: 2026-08-14T00:00:00Z
covers:
  - scripts/publish-ui.sh
  - scripts/live-build.txt
  - tools/freebird-ctl/**
  - Makefile
---

`make publish` does two things in a fixed order: build and push the site bundle,
then publish the control cell advertising the build number and label.

- MUST publish the site before the control cell. The control cell is what tells
  running clients a new build exists; advertising a build users cannot yet load
  shows an update banner that leads nowhere.
- MUST gate on the legacy-blob check first. `make publish` depends on
  `check-legacy-wasm`, so a tree whose dual-read window is aimed at the wrong
  generation cannot be published at all.
- MUST NOT publish from a machine with an empty site keystore. The publish
  script initializes a new key — and therefore a new site address — when it
  finds no existing entry, silently forking the site rather than updating it.
  Check the keystore before publishing from an unfamiliar machine.

## The follow-up is part of the release

The moment a publish succeeds, the commit that was published becomes the live
generation — which means it is the generation the *next* release's dual-read
window must read. `make publish` prints the steps; they are not optional:

1. Write the published commit into `scripts/live-build.txt`.
2. Re-vendor each `ui/contracts/<role>_v1.wasm` from that commit. Write to a
   temp file and move it into place — a shell redirect truncates the target
   before git runs, and a zero-byte blob is how this check used to be fooled.
3. `make pin-hashes`, then update the golden addresses in the UI's key module.

Skipping this leaves the window aimed a generation behind with CI green, because
the check proves the blobs agree with the commit the file *names* — nothing
proves that commit is what is actually deployed. That gap is
[the dual-read window](../specs/dual-read-window.md)'s one human-maintained
seam, and issue #81 is what fell through it: Discover emptied and threads lost
their replies.

## The webapp container id is load-bearing

The published site has a stable contract instance id — stable by construction,
since the container wasm and its parameters are fixed and a republish updates
state rather than identity. That id is compiled into the attestation code, which
binds a Ghost Key signature request to *this* application. Without that binding,
a signature harvested by another application could be replayed here. [#45]

Key material, keystore locations, and which host holds them are deliberately not
recorded in this repo — it is public. They live in the maintainer's private
notes.
