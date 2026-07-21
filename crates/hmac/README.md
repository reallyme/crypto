<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-hmac

Standalone HMAC authentication tags for ReallyMe Crypto.

This crate exposes HMAC-SHA-256 and HMAC-SHA-512 through typed key and tag
wrappers. It is intended for ratchet chain KDFs, transcript authentication, and
protocol code that needs raw HMAC rather than HKDF.

The public API rejects empty keys, caps key length at 4096 bytes to keep FFI
allocation behavior bounded, and verifies tags through the RustCrypto HMAC
implementation so same-length tag comparison is constant-time.

The Rust crate exposes `native` and `wasm` backend feature lanes. Swift and
Kotlin provider selection lives in their package facades, not in this primitive
crate.
