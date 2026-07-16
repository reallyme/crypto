<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-conformance-vectors

This crate generates and validates the shared conformance vectors for
ReallyMe Crypto. It covers the cryptographic surfaces owned by this workspace
and intentionally excludes application-specific document, token, and container
formats.

## Covered Surface

- P-256
- P-384
- P-521
- Ed25519
- secp256k1
- X25519
- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024
- AES-256-GCM
- ChaCha20-Poly1305
- XChaCha20-Poly1305
- HMAC-SHA-256
- HMAC-SHA-512
- SHA2-256
- SHA2-384
- SHA2-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
Post-quantum vectors are cross-checked with `@noble/post-quantum` 0.6.1.

## Generate

```sh
cargo run -p crypto-conformance-vectors --bin gen_vectors
```

The generator writes JSON files to the repository-level `vectors/` directory.

## Validate

```sh
cargo nextest run -p crypto-conformance-vectors
npm run --prefix crates/conformance/vectors verify:ts-native
swift test --package-path crates/conformance/vectors/platform/swift
cd crates/conformance/vectors/platform/kotlin && ./gradlew test
```

The Rust tests validate local invariants. The TypeScript verifier checks
classical, symmetric, hash, and post-quantum vectors against pinned noble
packages and Node native crypto. The Swift package verifies CryptoKit,
reallyme/CSecp256k1, and the ReallyMe Rust C ABI where those are the selected
providers. The Kotlin project verifies JCA/JCE and BouncyCastle coverage for
the JVM/Android lane.

## JWK interoperability status

ReallyMe intentionally uses an AKP public JWK representation for its
post-quantum algorithms: the exact algorithm identifier is stored in `alg`
and the unpadded base64url public-key bytes are stored in `pub`. This keeps
RFC 8037 `OKP` scoped to Ed25519/X25519 and avoids minting a ReallyMe-specific
`PQK` or hybrid-biased `PQX` key type. The conformance wall covers ML-DSA-44,
ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, and ML-KEM-1024 in both JWK and
JWK-to-Multikey directions.

SLH-DSA-SHA2-128s and X-Wing-768/1024 use the same AKP JWK convention. Their
JWK-to-Multikey vectors are omitted until the workspace Multicodec table assigns
public-key codec identifiers to them. No provisional numeric identifiers are
emitted because that would freeze an unreviewed wire contract. Their JWK
vectors remain independently testable.
