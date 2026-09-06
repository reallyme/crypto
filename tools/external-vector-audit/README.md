<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
-->

# External Vector Audit

This package tests public primitive APIs against raw upstream vectors in
`vectors/external`. Its practical subset runs with the workspace tests; heavy
and supplementary adapters are explicitly ignored and run in separate CI jobs.

The coverage tables, CI gating, and public-boundary notes are documented in
[`docs/external-conformance-vectors.md`](../../docs/external-conformance-vectors.md).

Run the practical subset from the repository root with:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

Run the deliberately slow CCTV deep-audit command from the repository root with:

```sh
node scripts/run_external_cctv_deep_audit.mjs
```

DER and SEC1 byte construction for the signature adapters is delegated to the
intentionally independent reference encoder in [`src/refenc.rs`](src/refenc.rs)
— deliberately *not* the production encoders, so an encoding regression in
production surfaces as a mismatch instead of being masked. Its edge cases are
pinned by unit tests and bounded `#[cfg(kani)]` proofs in that module.

Supplementary corpora are committed with pinned source refs and hashes. Use
[`vendor_external_vectors.mjs`](../../scripts/vendor_external_vectors.mjs) to
refresh them only after reviewing the new upstream commit. The linked coverage
document owns the exact executable/status-only inventory, ignored-test commands,
and CI schedule; corpus presence alone does not establish conformance.
