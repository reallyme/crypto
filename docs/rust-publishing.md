<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Rust Publishing

Rust crates are published as a namespaced workspace, not as one collapsed
crate. Consumers normally depend on the umbrella crates:

- `reallyme-crypto`
- `reallyme-codec`

The smaller `reallyme-crypto-*` and `reallyme-codec-*` crates are transitive
workspace components. They keep the development boundaries, lint posture, and
feature gates clear while allowing crates.io to resolve published dependencies.

## Order

The dependency order matters. Core and codec leaves must exist on crates.io
before primitives and umbrellas can package cleanly.

Use the manual **Crates.io Release** workflow for Rust publishing. Its preflight
job inspects every publishable crate tarball in workspace dependency order. The
publish job runs only when the workflow is started with `publish=true` and the
repository has `CARGO_REGISTRY_TOKEN` configured.

The first publish cannot use `cargo publish --dry-run` end-to-end for downstream
workspace crates, because Cargo resolves already-published dependencies from
crates.io. Until the lower-level ReallyMe crates actually exist there, a
simulated downstream publish fails even when the real ordered publish would
succeed. The workflow therefore uses `scripts/publish_crates_in_order.mjs` to
inspect tarballs before publishing, then publishes crates in the same
topological order.

## Local Inspection

```sh
cargo package -p reallyme-crypto --list --allow-dirty
cargo package -p reallyme-codec --list --allow-dirty
node scripts/publish_crates_in_order.mjs inspect
```

Before publishing, inspect the package lists and make sure the umbrella crates
ship only source, README, license, and notice files.
