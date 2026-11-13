#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# Every algorithm feature must compile independently without a Rust backend.
# This catches accidental facade re-exports of provider-only symbols.
features=(
  aes aes-kw aes-gcm-siv argon2id chacha20-poly1305 concat-kdf
  constant-time csprng ed25519 hmac hkdf kmac p256 p384 p521
  pbkdf2 rsa secp256k1 x25519 x-wing ml-dsa-44 ml-dsa-65 ml-dsa-87
  ml-kem-512 ml-kem-768 ml-kem-1024 sha2 sha3 poseidon2 slh-dsa
  operation-response dispatch jwk jwk-multikey
)

for feature in "${features[@]}"; do
  if [[ "$feature" == "operation-response" || "$feature" == "dispatch" ]]; then
    # All-feature checks exclude disabled-provider test crates. Compile those
    # targets in this existing narrow pass so their imports cannot drift.
    cargo check --locked --offline -p reallyme-crypto --all-targets --no-default-features --features "$feature"
  else
    cargo check --locked --offline -p reallyme-crypto --no-default-features --features "$feature"
  fi
done

# Feature unification may expose a second missing gate that isolated checks
# cannot see. Keep the generated operation contract in this combination.
combined="$(IFS=,; printf '%s' "${features[*]}")"
cargo check --locked --offline -p reallyme-crypto --no-default-features --features "$combined"

cargo test --locked --offline -p reallyme-crypto --no-default-features \
  --features ed25519,sha2 --test ed25519_backendless_tests
cargo check --locked --offline -p reallyme-crypto-jwk-multikey --no-default-features
