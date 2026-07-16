<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-p384

NIST P-384 ECDSA and ECDH primitive for ReallyMe Crypto.

The public API uses compressed SEC1 public keys, raw 48-byte private scalars,
SHA-384 prehashing, and DER-encoded ECDSA signatures. Secret key material is
returned in zeroizing buffers.

Verification fails closed with a typed error. It does not return a boolean.
ECDH returns the raw shared-secret x-coordinate; protocol code must pass that
through the appropriate KDF before key use.

This Rust primitive is native-lane only. Swift, Kotlin, and TypeScript package
facades expose provider-backed P-384 ECDH independently of this crate's pure
host-provider wasm lane.
