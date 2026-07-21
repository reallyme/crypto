<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Crypto Contract

This document defines the cross-package contract shared by every published
ReallyMe Crypto package. It covers structured operations, algorithm identity,
provider routing, errors, byte formats, and conformance requirements.

## Canonical Contract

ReallyMe Crypto is proto-first. The schema at
`crates/proto/proto/reallyme/crypto/v1/crypto.proto` is authoritative for:

- the executable `CryptoOperationRequest` and `CryptoOperationResponse`
  boundary;
- cross-language algorithm identifiers;
- typed result branches and non-PII wire errors;
- protobuf binary and generated ProtoJSON field names.

Generated bindings implement the transport boundary. They do not own
cryptographic semantics. All executable structured requests enter the same
Rust operation layer, which dispatches to one semantic owner for each operation
family.

Three additional artifacts complete the contract without competing with the
schema:

- `provider_manifest.json` selects the permitted provider for each SDK lane;
- `vectors/` fixes successful output and fail-closed behavior;
- native SDK facade types provide ergonomic, language-specific APIs over the
  same algorithms and errors.

The following evidence is checked together; none is an independent source of
competing wire semantics:

- protobuf enums and boundary messages;
- package algorithm identifiers;
- typed Rust error taxonomy;
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

- `crates/proto/proto/reallyme/crypto/v1/crypto.proto` is the canonical
  executable structured-operation and wire-identity contract.
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

The 0.3 schema treats assigned protobuf algorithm selectors as immutable. Every
`packageApi` algorithm in `provider_manifest.json` must have
exactly one typed protobuf selector, enforced by conformance tests. Family
enums use documented sparse subfamily bands, including classical curves in the
100-299 range, RSA in the 300-499 range, and post-quantum and hybrid algorithms
at 1000 and above. Adjacent strength or size variants normally advance by ten.
AES-GCM and AES-KW each independently assign their AES-128/192/256 variants
`100`, `110`, and `120` inside their separate family enums. Equal values across
different enums do not imply interchangeable semantics. These are ReallyMe
wire identifiers, not IANA COSE, JOSE, JWA, HPKE, TLS, or multicodec registry
values; adapters must translate by typed algorithm identity rather than pass
numeric values through. New names may consume an unused value in the
appropriate band, but an assigned number must never be renumbered or reused.
If an assignment is removed, both its number and name must be declared
`reserved` in the protobuf enum.

## Repository Shape

The workspace keeps schema, semantics, providers, transports, SDKs, and
evidence in separate directories:

```text
reallyme/crypto
  crates/
    proto/
      proto/reallyme/crypto/v1/crypto.proto
    crypto/
      src/
        operation_contract/
        operations/
        secret_material/
      core/
      dispatch/
      signer/
    ffi/
    wasm/
    <primitive crates>/
  packages/
    swift/
    kotlin/
    kotlin-android/
    ts/
  gen/
  vectors/
  scripts/
```

`crates/proto` owns generated wire types and strict decoding. `crates/crypto`
owns operation semantics. Primitive crates do not depend on SDK or transport
layers. `crates/ffi` and `crates/wasm` are validated adapters. The Swift
manifest remains at repository root so SwiftPM can import the package by URL;
its source stays under `packages/swift` with the other SDKs.

## Package Facades

The package facades in `packages/swift`, `packages/kotlin`,
`packages/kotlin-android`, and `packages/ts` are first-class SDK surfaces. Each
facade provides:

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

The TypeScript facade is synchronous. That is a deliberate contract decision:

- providers are pinned `@noble/*` packages and ReallyMe WASM/Rust where needed;
- WebCrypto is not part of the facade because it would force async API
  shapes across the package;
- no third-party schema validator is used at the crypto boundary.

Validation remains hand-written and narrow: enum membership, byte lengths,
buffer shape, and provider result shape. Avoid adding dependencies such as Zod;
minimal dependency surface is part of the package security posture.

## Platform Key Residency

Kotlin/JVM and Kotlin/Android are separate provider environments. The Kotlin
package uses BouncyCastle-backed behavior for algorithms where JCA or Android
provider behavior is inconsistent.

Swift exposes P-256 ECDH and P-256 ECDSA signing with Secure Enclave /
Keychain residency through separate handle-backed APIs. The handle represents a
permanent platform key; it is not a serialized private key and it is not
interchangeable with the raw-byte ECDH or deterministic ECDSA APIs.

The Android AAR exposes P-256 signing and ECDH through an explicit Android
Keystore handle API. It verifies TEE or StrongBox residency and never treats
that platform route as an implicit fallback from the Kotlin raw-byte APIs.

## Conformance Criteria

An algorithm family is complete for the SDK only when the actual consumers that
need it can call it in every required lane and the repository has:

- a matrix entry;
- package facade API or typed unsupported-algorithm behavior;
- vectors;
- malformed-input tests;
- provider identity tests where the platform can expose provider identity;
- byte-for-byte cross-lane conformance.
