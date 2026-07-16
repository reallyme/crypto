<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Crypto Vectors

This directory contains crypto conformance vectors used by tests.
Application-specific document, token, and container formats are not part of this vector set.

- `positive/`: inputs expected to validate or round-trip.
- `negative/`: malformed, tampered, downgraded, unsupported, or wrong-context inputs expected to fail closed with typed errors.

## Current Artifacts

- `p256.json`
- `ed25519.json`
- `secp256k1.json`
- `x25519.json`
- `ml_dsa_44.json`
- `ml_dsa_65.json`
- `ml_dsa_87.json`
- `mlkem512.json`
- `mlkem768.json`
- `mlkem1024.json`
- `aes128gcm.json`
- `aes192gcm.json`
- `aes256gcm.json`
- `concat_kdf.json`
- `chacha20poly1305.json`
- `hmac.json`
- `hashes.json`
- `manifest.json`

`manifest.json` also declares the runtime lane matrix for Rust native, Rust
WASM, TypeScript native noble, Swift native, and Kotlin/JVM native conformance.
Provider-gated lanes must remain explicit until their missing algorithms have
audited native providers and executable vector comparisons.

`manifest.json` declares shared fail-closed vectors under `negative_vectors`.
Those files pin cross-lane typed failure semantics for malformed, tampered, or
wrong-context inputs; lane-local tests may add more cases, but must not
contradict the shared negative vector contract.

## Adding Coverage

Every new primitive, backend, or security hardening change must add or reference:

- at least one positive vector;
- at least one negative/tampered vector;
- typed error assertions for the negative path;
- runtime-lane coverage for Rust native, Rust WASM, Swift, and Kotlin, or an
  explicit guard test explaining why a lane cannot execute that vector.

Vectors must not contain real user data, production secrets, private keys, or
regulated evidence.
