# kb / policies

How we work on this repo. Both entries here exist because of the same fact: the
vendored wasm bytes are the addressing truth, so the build and the checks around
it are load-bearing in a way they would not be in an ordinary Rust workspace.

- [reproducible builds](reproducible-builds.md) — the vendored wasm is the
  immutable source of truth; amd64 is the single build-of-record; the
  step-by-step procedure for a legitimate rotation, and how to build one without
  Docker
- [testing, linting, and the CI gates](testing-and-ci.md) — why test and lint
  run in three separate cargo resolves, what each CI job proves, and why there
  is deliberately no formatting check
