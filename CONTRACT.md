<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Crypto Contract

This file records the public package contract: names, formats, provider
decisions, and API constraints that package work must preserve.

## Canonical Contract

ReallyMe Crypto is not a set of mechanically generated Rust bindings. The
canonical contract is the combination of:

- protobuf enums and boundary messages in `proto/reallyme/crypto/v1/crypto.proto`;
- package algorithm identifiers shared by the Rust, Swift, Kotlin, and
  TypeScript facades;
- the typed Rust error taxonomy and protobuf `CryptoError` reason codes;
- `provider_manifest.json` and the generated matrix in `PROVIDER_POLICY.md`;
- shared positive and negative conformance vectors.

Rust remains the reference implementation and the shared implementation for
selected primitives, but each platform facade is a first-class SDK surface. A
facade may route an operation to an approved native provider only when that
provider satisfies the same public contract as the Rust/reference path.

Every provider route must implement identical input validation and
normalization, output encodings, typed failure semantics, and edge-case
behavior. A native or provider implementation is interchangeable only when
shared vectors, negative tests, and, where practical, differential tests against
the Rust/reference path prove the contract. For security-sensitive composition,
canonical serialization, deterministic signatures, post-quantum primitives,
memory-hard KDFs, and algorithms with ambiguous or provider-specific platform
behavior, the safer default is to keep execution in the Rust implementation and
expose it through FFI, JNI, or WASM.

## Sources Of Truth

- `proto/reallyme/crypto/v1/crypto.proto` is the cross-language algorithm,
  serialization, and non-PII error boundary contract.
- `vectors/` is the byte-level conformance contract for successful and
  rejected inputs.
- `provider_manifest.json` is the machine-readable provider-routing source of
  truth. `PROVIDER_POLICY.md` records the human-readable provider order for
  each package algorithm identifier, the per-lane provider and fallback policy
  (the generated backend matrix), and forbids silent fallback.
- `crates/crypto/core` owns the Rust algorithm identifiers and typed error
  taxonomy used by primitive, dispatch, and FFI code.

Do not regenerate vectors unless one of those contracts intentionally changes.
If the contract changes, update the proto, generated code, vectors, provider
policy, and contract tests in the same pass.

## Repository Shape

The SDK package surfaces live in this repository next to the Rust
implementations and shared vectors:

```text
reallyme/crypto
  crates/
    crypto/
      primitives/
      dispatch/
      ffi/
      protocols/
  packages/
    swift/
      Sources/ReallyMeCrypto/
      Tests/
    kotlin/
      src/main/kotlin/me/really/crypto/
      src/test/
    ts/
      src/
      test/
  proto/
    reallyme/crypto/v1/crypto.proto
  vectors/
```

The Swift manifest intentionally lives at repository root (`Package.swift`) so
SwiftPM consumers can import the package by URL while the source remains under
`packages/swift`.

## Package Facades

The package facades in `packages/swift`, `packages/kotlin`, and `packages/ts`
are first-class SDK surfaces. They must follow the existing
`ReallyMeSecp256k1` pattern:

- native-language ergonomic API;
- ReallyMe typed errors with no secret or user-provided bytes;
- exact byte contract from `vectors/`;
- malformed-input tests;
- provider catalog entry;
- no silent fallback to a different provider.

Algorithms outside a package facade's supported provider set must fail closed
with a typed `unsupportedAlgorithm` error when routed through generic package
APIs. The generic facades must keep explicit entry points for every algorithm
family tracked here: signatures, key agreement, KEM, AEAD, hash, MAC, KDF, key
wrap, and HPKE.

## TypeScript Sync Policy

The TypeScript facade is synchronous for the 0.2 line. That is a deliberate
contract decision:

- providers are pinned `@noble/*` packages and ReallyMe WASM/Rust where needed;
- WebCrypto is not part of the 0.2 facade because it would force async API
  shapes across the package;
- no third-party schema validator is used at the crypto boundary.

Validation remains hand-written and narrow: enum membership, byte lengths,
buffer shape, and provider result shape. Avoid adding dependencies such as Zod;
minimal dependency surface is part of the package security posture.

## Platform Key Residency

Kotlin/JVM and Kotlin/Android are separate provider environments. For `0.2.0`,
the Kotlin package uses BouncyCastle-backed behavior for algorithms where JCA
or Android provider behavior is inconsistent.

Swift exposes P-256 ECDH with Secure Enclave / Keychain residency through a
separate handle-backed API. The handle represents a permanent platform key; it
is not a serialized private key and it is not interchangeable with the raw-byte
ECDH APIs.

Android Keystore residency needs the same explicit key-handle treatment before
the Kotlin facade can select it. It is not implicit in the current Kotlin byte
API.

## Completion Criteria

An algorithm family is complete for the SDK only when the actual consumers that
need it can call it in every required lane and the repository has:

- a matrix entry;
- package facade API or typed unsupported-algorithm behavior;
- vectors;
- malformed-input tests;
- provider identity tests where the platform can expose provider identity;
- byte-for-byte cross-lane conformance.
