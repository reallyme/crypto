<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Argon2id Vectors (Audit Record)

This file records fixed regression vectors for `crypto-argon2id`.

## Policy / Profile

The vectors below are generated using the crate's pinned V1 profile:

- Algorithm: `Argon2id`
- Version: `0x13` (Argon2 v1.3)
- Memory cost (`m`): `262144` KiB
- Time cost (`t`): `3`
- Lanes (`p`): `1`
- Derived key length: `32` bytes

These values are pinned in source constants:

- `ARGON2ID_V1_MEMORY_COST_KIB`
- `ARGON2ID_V1_TIME_COST`
- `ARGON2ID_V1_LANES`
- `ARGON2ID_DERIVED_KEY_LENGTH`

## Snapshot Vectors

1. Input:
- kdf_version: `1`
- secret: `"password"`
- salt: `"somesaltvalue1234"` (16 bytes)

Expected derived key (hex):
- `53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757`

2. Input:
- kdf_version: `1`
- secret: `"client-controlled-root-secret-material"`
- salt: `"domain-separation-salt-000000001"` (32 bytes)

Expected derived key (hex):
- `7e4c6ef85993a6829ad0ec14e60a05e7273abfbe60d73a5a6bed513fd1612df7`

## Test Anchors

These vectors are enforced by:

- `snapshot_vector_password_and_salt_16`
- `snapshot_vector_client_secret_and_salt_32`

in:

- `crates/crypto/src/argon2id/tests/argon2id_tests.rs`

## Reproduction

Run:

```bash
cargo test -p reallyme-crypto-argon2id snapshot_vector_password_and_salt_16 -- --exact
cargo test -p reallyme-crypto-argon2id snapshot_vector_client_secret_and_salt_32 -- --exact
```

If either expected hex value changes, treat it as a cryptographic breaking change and require explicit review.
