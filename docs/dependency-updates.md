<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
-->

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
