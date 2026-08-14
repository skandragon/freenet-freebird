# Vault authoring policy

Rules for writing in `kb/`. Written so a human, or an agent without the kb plugin, can
maintain the vault correctly from this file alone.

## Shape of a concept

One surface, behavior, or decision per file. Kebab-case filename, roughly 20–60 lines,
in the area that fits. Frontmatter — `type` is required:

```markdown
---
type: spec           # feature | spec | policy | decision | convention
title: Dual-read window
description: One line for the future searcher — symptoms and literal terms they'd type.
timestamp: 2026-08-14T00:00:00Z
covers:              # spec files only: the spec → code reverse index
  - ui/src/legacy.rs
  - ui/src/keys.rs
status: living       # spec files: living | draft | legacy
---
```

Body discipline for specs:

- Atomic claims, one per line, in product language:
  `- MUST <clause>. [#PR]  {evidence: <type>: <value>}`
- Never fabricate provenance. If you can't find the PR, omit it.
- Claims must not name functions, file paths, or internal types — `covers:` points at the
  code; claims describe behavior.
- Relative markdown links in bodies. No wikilinks.

Every write is two steps, both or it didn't happen: write the concept, then update its
one-line entry in **its own directory's** `index.md`. A directory index opens with two or
three sentences of context and orders its entries along the data flow.

## This repo adds two rules

**1. Contract-rotation consequences are part of the claim.**
Contract and delegate addresses derive from wasm bytes, so any spec covering
`contracts/**`, `common/**`, `delegates/**`, or `ui/src/keys.rs` must state what a byte
change costs: which generation constant bumps, whether a dual-read window is required, and
what happens to existing posts and stored posting keys if it is skipped. A spec in this
area that describes only the happy path is incomplete — the failure it omits is the one
that has already cost users data.

**2. Cite the issue, not just the PR.**
The hard-won invariants here are tracked by GitHub issue (#51, #53, #80, #81), and the
issue carries the reasoning the PR title doesn't. Claims cite both where available:
`[#81, PR #88]`. An issue number alone is better than nothing.

## Decisions, not a journal

The vault is current state. A superseded decision is rewritten in place with a bumped
`timestamp` — never appended to. Concepts that turn out wrong get deleted, along with
their index line. No changelogs, no update-history sections: git is the journal.

The one sanctioned piece of history is a drift marker, inline, when code intentionally
departs from spec:

```
⚠ KNOWN DRIFT: <what>. Intentional <date> by <who> — "<reason>."
```

## Standing obligations

- Behavior changed under a `covers:` glob? Update the claim, or add a drift marker, **in
  the same change**. A spec that lags the code is worse than no spec.
- Before renaming, deleting, or splitting a concept, find its referrers and fix them.
- Answered a question the vault couldn't? That answer is a candidate concept.

## What does not belong here

Infrastructure, credentials, machine-local setup, and personal preferences — those are
cross-repo and this repo is public. They go to the private brain instead. Nothing lives in
both places.
