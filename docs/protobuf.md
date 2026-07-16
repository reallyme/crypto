<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Protobuf

The importable wire/config contract lives at
[../crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto](../crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto).
Service, application, and storage protos can import that file when they need to
store or transmit crypto choices or non-secret error envelopes.

Use proto enums for API and storage boundaries, not string algorithm names.
Inside SDK and application code, use the native facade types for each language.
`CryptoError` is a non-PII boundary envelope. It is lossless at the wire layer:
the primitive, provider, and backend branches stay distinct, and the exact
`CryptoErrorReason` is preserved through protobuf bytes. Broad facade errors
remain convenience projections above this layer and must not be used when a
service, FFI/JNI/WASM boundary, or persisted message needs error pass-through.

The protobuf schema is one source of truth in the canonical Crypto contract,
not a generated mirror of the Rust package API. It defines cross-language
algorithm identifiers, wire-ready result shapes, and non-secret error
envelopes that native facades, Rust dispatch, FFI/JNI, WASM, and service
wrappers must all agree on.

## Generated Surfaces

| Language | Surface |
|---|---|
| Rust | `reallyme-crypto-proto` for `reallyme.crypto.v1` |
| Swift | `ReallyMeCryptoProto` plus `ReallyMeCryptoProtoAdapters` |
| Kotlin | generated `me.really.crypto.v1` types plus `me.really.crypto.proto.ReallyMeCryptoProtoAdapters` |
| TypeScript | `@reallyme/crypto/proto` |

## Boundary Rule

Convert at API, storage, and message boundaries:

```text
proto enum -> facade enum/string union -> crypto operation
crypto result -> facade type -> proto enum when persisted or transmitted
```

For protobuf-facing operations, use the Codec-style result helpers exposed by
each package lane. A successful operation returns status `result` plus
serialized result-message bytes. A structured crypto failure returns status
`crypto-error` plus serialized `CryptoError` bytes. Callers that need native
ergonomics may project that error to `ReallyMeCryptoError` /
`ReallyMeCryptoException`, but Connect wrappers should pass the structured
error bytes through unchanged.

The schema defines `CryptoService.Process`, `CryptoServiceProcessRequest`, and
`CryptoServiceProcessResponse`. The request carries a typed `CryptoOperation`
plus the operation-specific protobuf payload; the response carries the
`CryptoProtoResultEnvelope` unchanged. Connect implementations must apply the
same one-megabyte protobuf limit, recursion limit, unknown-field limit, provider
policy, and no-fallback behavior as the local process lane.

Rust also exposes a `proto-process` feature for service adapters that want a
single executable protobuf lane. `reallyme_crypto::proto_process::process_proto`
takes the numeric value of `CryptoOperation` plus serialized request protobuf
bytes and returns the
same result/error envelope shape used by the SDK proto helpers. The first
release-hardened implementation executes the dispatch-covered operations
directly: hash, AEAD seal/open, MAC authenticate/verify, signature key
generation/sign/verify, key-agreement shared-secret derivation, and KEM
generation/encapsulation/decapsulation. Operation ids for HKDF, generic KDF,
JWA Concat KDF, AES-KW, HPKE, RSA verify, BIP-340, and deterministic keypair
derivation are reserved and fail closed with structured
`PROVIDER_UNSUPPORTED_ALGORITHM` errors until their direct primitive adapters
are wired into this lane.

Algorithm adapters reject `UNSPECIFIED`, unrecognized algorithm values, and
private/reserved key-prefix values with typed unsupported-algorithm errors.
Error reasons have a different compatibility rule: `UNSPECIFIED` is invalid,
known codes must match their owning branch, and unknown codes are preserved
only when they fall inside that branch's reserved numeric range. This permits
lossless pass-through from newer peers without accepting a cross-branch code.

Provider routing is separate from protobuf serialization. A protobuf enum
selects the algorithm contract; `provider_manifest.json`, `PROVIDER_POLICY.md`,
typed errors, and vectors determine whether a lane may satisfy that contract
with a native provider or must call the Rust implementation through FFI, JNI,
or WASM.

The error envelope intentionally splits failures by owning subpart:

| Package | Envelope | Sub-errors |
|---|---|---|
| `reallyme.crypto.v1` | `CryptoError` | `CryptoPrimitiveError`, `CryptoProviderError`, `CryptoBackendError` |

## Data Lanes

ReallyMe Crypto exposes three boundary lanes. They are deliberately narrower
than the codec package because cryptographic outputs often carry secrets or
protocol-sensitive material.

### Raw Binary

Raw bytes are the primary lane for primitive operations. Single byte-string
results stay as `Uint8Array`, `[UInt8]`, `ByteArray`, or Rust byte slices and
owned byte containers. This includes signatures, hashes, ciphertexts, public
keys, shared secrets, wrapped keys, tags, nonces, and similar primitive
outputs.

Do not wrap a single byte-string result in protobuf only to make it look more
structured. The byte contract belongs to the primitive API.

### Protobuf Binary

Use protobuf bytes when a result has a fixed multi-field shape or crosses an
FFI, protocol, storage, RPC, or package boundary. `CryptoError`, operation
request/result messages, `CryptoKeyPair`, `CryptoKemEncapsulation`,
`CryptoHpkeSealedMessage`, `CryptoVerificationResult`, `JsonWebKey`, and
`JsonWebKeySet` follow this rule.

These messages should reference `CryptoAlgorithmIdentifier` instead of
free-form algorithm strings, and should map failures through `CryptoError`
instead of leaking provider exception text.

For verification results, `CRYPTO_VERIFICATION_STATUS_INVALID` means the
request was well-formed and processed, but the MAC, signature, proof, or
constant-time comparison did not verify. Malformed inputs, unsupported
algorithms, unavailable providers, and backend/internal failures use
`CRYPTO_VERIFICATION_STATUS_ERROR` with the structured `CryptoError` field.

### JSON Convenience

JSON is for public, human-facing, or app-facing metadata where JSON is already
the natural domain format. JWK, JWKS, provider summaries, and inspection
metadata can have JSON convenience shapes.

Do not add JSON convenience wrappers for shared secrets, private keys,
ciphertexts, signatures, or tags. Secret-bearing values should stay raw bytes or
protobuf bytes. JWK is the exception because it is a standards-defined JSON key
format, and this repository's protobuf `JsonWebKey` message intentionally
stores public key material only.

The rule of thumb is:

| Shape | Preferred lane |
|---|---|
| Single byte-string result | Raw binary |
| Multiple fields or typed boundary result | Protobuf binary |
| Human/app-facing public metadata | JSON convenience |
| Secret-bearing material | Raw binary or protobuf binary, not JSON |

## TypeScript Example

```ts
import {
  HashAlgorithm,
  hashAlgorithmFromProto,
  hashAlgorithmToProto,
} from "@reallyme/crypto/proto";

const facadeAlgorithm = hashAlgorithmFromProto(HashAlgorithm.SHA2_256);
const protoAlgorithm = hashAlgorithmToProto(facadeAlgorithm);
```

## When To Use Proto

Use the proto definitions when another protocol needs to refer to a crypto
choice: Connect APIs, durable configuration, stored keys, network messages, or
log-safe status records.

Do not force proto types into ordinary facade calls when the caller is already
inside one language package. The facade types are intentionally more ergonomic
there.
