<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Protobuf

The canonical structured wire contract lives at
[../crates/proto/proto/reallyme/crypto/v1/crypto.proto](../crates/proto/proto/reallyme/crypto/v1/crypto.proto).
It defines executable operation requests and responses, algorithm identifiers,
typed results, and non-secret error envelopes. Services and applications can
import the same schema for RPC, storage, or message boundaries.

Use proto enums for API and storage boundaries, not string algorithm names.
Inside SDK and application code, use the native facade types for each language.
`CryptoError` is a non-PII boundary envelope. It is lossless at the wire layer:
the primitive, provider, and backend branches stay distinct, and the exact
`CryptoErrorReason` is preserved through protobuf bytes. Broad facade errors
remain convenience projections above this layer and must not be used when a
service, FFI/JNI/WASM boundary, or persisted message needs error pass-through.

The protobuf schema is the source of truth for the structured wire contract;
it is not a generated mirror of the Rust package API. Native facades, Rust
dispatch, FFI/JNI, WASM, and service wrappers all converge on its generated
operation messages. Provider policy and conformance vectors determine which
lanes may execute each algorithm and what output they must produce.

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

For protobuf-facing operations, use the generated operation response helpers
exposed by each package lane. A successful operation returns
`CryptoOperationResponse.result` with one typed `CryptoOperationResult` branch.
A structured crypto failure returns `CryptoOperationResponse.error` with a
generated `CryptoError`. Callers that need native ergonomics may project that
error to `ReallyMeCryptoError` / `ReallyMeCryptoException`, but Connect wrappers
should pass the structured protobuf error through unchanged.

The schema defines messages only and intentionally declares no protobuf
service. `CryptoOperationRequest` carries one typed request in its `oneof`, and
`CryptoOperationResponse` carries either one typed generated result branch or a
structured `CryptoError`. Connect or RPC implementations wrap these messages
in their own transport schema and must
apply the same one-megabyte protobuf limit, recursion limit, strict
unknown-field policy, provider policy, and no-fallback behavior as the local
operation lane.

Platform-resident private keys use typed, opaque handles rather than raw
private-key bytes. A handle records its provider, purpose, algorithm, requested
security level, and actual security level; the requested level is never proof
that hardware residency was obtained. Attestation is a separate evidence
operation, and platform-key deletion is idempotent without echoing the
privacy-sensitive handle in its result. These are standalone provider-owned
messages rather than branches of the Rust-executable operation wrapper:
provider-specific Swift and Android SDK routes implement the matching handle
lifecycle directly and reject provider or purpose mismatches.

Rust exposes an `operation-response` feature for service adapters that want a
single executable protobuf lane.
`reallyme_crypto::operation_contract::process_operation_response` takes
serialized `CryptoOperationRequest` bytes and returns the same binary generated
response shape used by the SDK proto helpers. The ProtoJSON entrypoint accepts
only the generated representation of non-secret hash, verification,
key-generation, encapsulation, and sender-export requests, and returns that
binary response. Secret-bearing operations must use binary protobuf. The
operation contract executes hash, AEAD seal/open,
MAC authenticate/verify, signature key
generation/derivation/sign/verify, key-agreement key derivation and
shared-secret derivation, KEM generation/derivation/encapsulation/decapsulation,
versioned Argon2id derivation, HKDF-SHA256 derivation, modern-policy
PBKDF2-HMAC-SHA256/SHA512 derivation, KMAC256 derivation, fixed-size JWA Concat
KDF SHA-256 derivation, and AES-128/192/256
key wrap/unwrap, BIP-340 Schnorr signing, and RSA PKCS#1 v1.5/PSS
verification. It also executes HPKE Base-mode and PSK seal/open,
key-generation, deterministic key-derivation, and sender/receiver exporter
operations for suites admitted by provider policy. Registered but unavailable
HPKE combinations fail closed with a structured
`PROVIDER_UNSUPPORTED_ALGORITHM` error. Generic PBKDF2 requests enforce a public
work-factor range of 100,000 through 10,000,000 iterations before derivation.
Argon2id uses its dedicated operation branch and requires an explicit immutable
`kdf_version` profile selector instead of accepting caller-controlled memory,
time, or parallelism parameters. Ed25519 signature signing uses a
32-byte seed-only `secret_key` contract; 64-byte expanded
`seed || public_key` material is rejected as typed invalid-key input instead
of ignoring the public-key half. BIP-340 signing uses a dedicated request with
32-byte `message32`, 32-byte `secret_key`, and 32-byte `aux_rand32`; malformed
lengths fail with typed primitive length/key errors. BIP-340 key generation,
deterministic key derivation, and verification use the generic signature
requests with the BIP-340 algorithm selector. Their public keys are canonical
32-byte x-only secp256k1 keys. The generic signature-sign request deliberately
rejects BIP-340 because it cannot carry the required auxiliary randomness.
RSA verify supports the fixed protobuf suites
for PKCS#1 v1.5 over SHA-1/SHA-256/SHA-384/SHA-512 and PSS over matching
message/MGF1 hashes with salt length equal to the digest length. SHA-1 support
is explicit historical-document verification support, not a signing
recommendation. PSS uses RFC 8017 `emBits = modBits - 1`, including the
one-byte-shorter encoded message required when `modBits % 8 == 1`. Valid and
invalid-signature outcomes are result branches; malformed keys carry a typed
nested verification error, and non-RSA selectors return a typed
unsupported-algorithm response error.

Algorithm adapters reject `UNSPECIFIED`, unrecognized algorithm values, and
private/reserved key-prefix values with typed unsupported-algorithm errors.
Every public package algorithm has exactly one family-scoped protobuf selector.
The 0.3 schema treats assigned selectors as immutable and uses sparse bands:
classical curves occupy 100-299, RSA occupies the 300 range, symmetric and KDF
families use construction-specific 100-series bands, and post-quantum or
hybrid algorithms start at 1000. Adjacent strength or size variants normally
advance by ten. AES-GCM and AES-KW each use AES-128=`100`, AES-192=`110`, and
AES-256=`120` within their separate enums; equal cross-enum values carry no
shared meaning. With one deliberate exception, ReallyMe protobuf values are
not IANA COSE, JOSE, JWA, TLS, or multicodec registry numbers. `HpkeKemId`,
`HpkeKdfId`, and `HpkeAeadId` use the corresponding two-byte HPKE registry
values so the HPKE suite-domain-separation inputs remain exact and inspectable.
JOSE and COSE adapters must translate through typed algorithm identities and
must never pass unrelated ReallyMe values through as registry identifiers.
Error reasons follow a different wire-stability rule: `UNSPECIFIED` is invalid,
known codes must match their owning branch, and unknown codes are preserved
only when they fall inside that branch's reserved numeric range. This permits
lossless pass-through from newer peers without accepting a cross-branch code.

Provider routing is separate from protobuf serialization. A protobuf enum
selects the algorithm contract; `provider_manifest.json`, `PROVIDER_POLICY.md`,
typed errors, and vectors determine whether a lane may satisfy that contract
with a native provider or must call the Rust implementation through FFI, JNI,
or WASM.

## HPKE Support

The canonical `0.3.0` HPKE selector is `HpkeSuiteIdentifier`, containing one
`HpkeKemId`, `HpkeKdfId`, and `HpkeAeadId`. These enums cover every assigned
entry in the IANA HPKE KEM, KDF, and AEAD registries as of 2026-04-16.
Registration does not imply provider availability: each concrete triple is
checked against the provider capability policy and an unavailable or
unsupported combination fails closed without fallback.

The Rust native operation lane classifies these components as executable:

| Component | Executable identifiers |
|---|---|
| KEM | DHKEM P-256, P-384, P-521, secp256k1, X25519, and X448; ML-KEM-512/768/1024; MLKEM768-P256; MLKEM1024-P384; X-Wing |
| KDF | HKDF-SHA256, HKDF-SHA384, HKDF-SHA512, SHAKE256 |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, export-only |

Sealing and opening reject the export-only AEAD. Export operations reject the
SHAKE256 plus export-only combination because the selected backend's fixed
internal buffer cannot safely execute it. Every unsupported
component or combination returns a typed error before provider setup.

The stable Swift, Kotlin, Android, and TypeScript facades expose two portable
profiles:

| Profile | Swift | Kotlin/JVM and Android | TypeScript |
|---|---|---|---|
| `DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM` | Rust C ABI provider | BouncyCastle | Rust WASM provider |
| `DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305` | Rust C ABI provider | BouncyCastle | Rust WASM provider |

Swift requires the Rust C ABI provider explicitly. No SDK retries through a
different provider when its declared route is unavailable.

The MLS 192-bit hybrid profile is represented as the canonical triple
`MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`: KEM
`HPKE_KEM_ID_ML_KEM_1024_P384` (`0x0051`), KDF
`HPKE_KDF_ID_HKDF_SHA384`, and AEAD `HPKE_AEAD_ID_AES_256_GCM`.

Messages use `CryptoAlgorithmIdentifier.hpke_suite`; superseded field numbers
and names remain reserved against reuse. Live HPKE contexts,
traffic keys, nonces, and sequence state are deliberately not serializable; the
protobuf surface exposes single operations for key generation, deterministic
key derivation, Base-mode seal/open, sender/receiver export, and PSK seal/open.
HPKE seal requests do not carry a nonce because the HPKE key schedule derives
the 12-byte AEAD nonce internally.

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

### Proto-JSON Transport

Strict proto-JSON is supported for the same operation request/result messages
that are available as protobuf bytes. This is a transport and conformance lane,
not a separate crypto facade. It exists for Connect JSON clients, CLIs,
browser-facing adapters, fixtures, and cross-language tests that need
human-inspectable requests while preserving the protobuf schema: algorithms are
enum-backed, byte fields are base64-encoded, malformed JSON maps to typed
backend errors, and size limits are enforced before conversion to protobuf
bytes.

Proto-JSON can represent every operation envelope, including AEAD, MAC, KDF,
key-wrap, HPKE, KEM, and signature messages. That does not make JSON the
preferred representation for secret-bearing data. JSON parsers, logs,
middleware, browser developer tools, crash reporters, and managed runtimes make
extra copies that are harder to zeroize. Use proto-JSON for secret-bearing
requests only when an actual protocol boundary requires JSON; otherwise prefer
raw bytes or protobuf bytes.

Generated bindings retain the copy/clone behavior required by their protobuf
runtimes. Rust-owned byte fields are redacted from `Debug`, zeroized on drop,
and decoded through zeroizing temporary buffers. Swift, Kotlin/Java, and
TypeScript generated messages live in managed memory and cannot promise
deterministic destruction; keep secret-bearing messages short-lived, avoid
unnecessary copies, and move secret bytes into the package's explicit
best-effort-clearing APIs as soon as the boundary permits.

Buffa zero-copy owned views are a transport optimization, not a secret owner:
they retain immutable reference-counted wire bytes that cannot be wiped safely
when the final reference is not known. ReallyMe removes `Clone` and redacts
`Debug` for byte-bearing generated owned-view wrappers, but callers must not
retain secret-bearing requests in those views. Decode into the Rust owned
message when deterministic drop-time zeroization is required.

Do not add casual JSON convenience wrappers such as `hash_json(value)` or
stringly typed crypto APIs. If an application wants to hash a JSON document, it
must first choose and document a canonicalization scheme, such as JCS, and then
pass the resulting bytes into the byte-oriented hash API or the typed
`CryptoHashRequest` envelope.

See [proto-json.md](proto-json.md) for operation-family JSON examples.

JWK and JWKS remain the exception for JSON convenience because they are
standards-defined JSON key formats, and this repository's protobuf `JsonWebKey`
message intentionally stores public key material only.

The rule of thumb is:

| Shape | Preferred lane |
|---|---|
| Single byte-string result | Raw binary |
| Multiple fields or typed boundary result | Protobuf binary |
| Connect JSON / CLI / conformance request | Strict proto-JSON |
| Human/app-facing public metadata | JSON convenience |
| Secret-bearing material | Raw binary or protobuf binary; proto-JSON only when required by the protocol boundary |

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
