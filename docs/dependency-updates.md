# Dependency Updates

Renovate is currently disabled in `.github/renovate.json`. Dependency updates
across Cargo, npm, Gradle, SwiftPM, and GitHub Actions are reviewed manually.

The policy is simple:

- If Renovate is enabled, configure it to open reviewable pull requests without
  automerging them.
- Runtime cryptography updates are reviewed one dependency at a time.
- GitHub Actions stay pinned to immutable revisions.
- Lockfile maintenance is allowed, but still review-only.
- Every crypto dependency update must pass the conformance wall before merge.
- Provider behavior must remain explicit. No update may introduce silent
  fallback to another implementation.
- KMAC256 dependency updates for `sha3-kmac`, `sha3-utils`, or their transitive
  `sha3` implementation require a focused checksum, API, zeroization, and
  conformance-vector review.

Use [conformance.md](conformance.md) as the release gate. If an update changes
cryptographic bytes, provider behavior, error behavior, or supported algorithms,
update the vectors, policy, package facades, and documentation in the same
change.

Release-readiness policy files have reviewed SHA-256 pins in
`scripts/run_pinned_release_readiness.mjs`. When changing the checker or a
pinned dependency, review the policy diff and update its digest in the same
change. After reviewing a checker edit, run
`node scripts/run_pinned_release_readiness.mjs --refresh-checker-pin`.
This explicit operation updates only the checker digest and is forbidden in CI.
Dependency and core pins still require individual review and updates.

Run `node scripts/run_pinned_release_readiness.mjs --check-pins` and
`node --test --test-concurrency=4 "scripts/**/*.test.mjs" "packages/ts/scripts/*.test.mjs"`
before pushing.
These offline checks verify the current pins and rejection of modified,
missing, oversized, and substituted policy files. Both Code Checks and
Protobuf Checks verify the pins before installing their build dependencies.
Code Checks runs tooling tests independently on Linux and macOS and lints every
workflow with pinned actionlint and ShellCheck versions. Linux checks use an
explicit runner release. Concurrency separates event types and commit hashes,
so an older queued push cannot hold up checks for a new commit. Pull request
runs share their request number and allow cancellation of superseded work.
The direct local readiness checker verifies pins before importing policy modules.
The full runner executes the
hash-verified vendored core without downloading the same bytes again. Policy
upgrades must review and update the vendored core and its upstream commit and
digest together. To additionally verify the pinned upstream download, run
`node scripts/run_pinned_release_readiness.mjs --check-pins --verify-upstream`.
