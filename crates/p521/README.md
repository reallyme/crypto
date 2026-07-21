<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-p521

NIST P-521 ECDSA and ECDH primitive for ReallyMe Crypto.

The public API uses compressed SEC1 public keys, raw 66-byte private scalars,
SHA-512 prehashing, and DER-encoded ECDSA signatures. Secret key material is
returned in zeroizing buffers.

Verification fails closed with a typed error. It does not return a boolean.
ECDH returns the raw shared-secret x-coordinate; protocol code must pass that
through the appropriate KDF before key use.

The `native` and `wasm` feature lanes both compile this crate's package-owned
Rust implementation. Swift and Kotlin provider selection remains in their SDK
facades rather than in Rust Cargo features.
