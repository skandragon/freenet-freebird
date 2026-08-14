# Freebird knowledge vault

Repo-scoped knowledge in [Open Knowledge Format](https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf)
markdown: one concept per file, `type` required in frontmatter. Answers a question by
reading one small file rather than scanning the codebase.

The division of labour: **why** a thing exists lives in `product/`, **what we meant to
build** lives in `specs/`, **what we actually built** is the code (reached from a spec's
`covers:` globs), and **how we work** lives in `policies/`. Design documents that are
snapshots of a moment stay in `docs/superpowers/specs/`; the vault carries current state.

Before writing anything here, read [policy.md](policy.md) — authoring rules, and the two
this repo adds.

## Areas

- `product/` — features as a user experiences them: peeps, replies, follows, Discover,
  check marks, onboarding. Written in the vocabulary of the README, not of the code.
- `specs/` — atomic claims about intended behavior, each with `covers:` globs pointing at
  the code that implements it. This is the map from behavior to source.
- `policies/` — how we work: the build/publish sequence, the contract-rotation procedure,
  testing strategy, CI gates, release practice.

Each area gets its directory and its own `index.md` when its first concept arrives; empty
areas are not pre-created.

## Not here

Infrastructure, credentials, machine setup, and personal working preferences go to the
private cross-project brain, never into this repo.
