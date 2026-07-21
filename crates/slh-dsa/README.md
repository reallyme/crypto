<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-slh-dsa

SLH-DSA (FIPS 205) signature primitives for ReallyMe Crypto.

This package currently exposes `SLH-DSA-SHA2-128s`, the small-signature SHA-2
parameter set. It provides key generation, deterministic vector derivation from
the FIPS keygen seed components, detached signing, verification, and raw public
key encode/decode helpers.

The serialized secret key is the FIPS 205 `SK.seed || SK.prf || PK.seed ||
PK.root` form and is returned in a zeroizing owner. Callers that copy the secret
key across an FFI or package boundary are responsible for zeroizing their copy.

Backend feature lanes:

- `native`: RustCrypto `slh-dsa` implementation with zeroization enabled.
- `wasm`: the same package-owned RustCrypto implementation, with WASM-compatible
  entropy support.

Swift and Kotlin provider selection lives in their package facades, not in this
primitive crate.
