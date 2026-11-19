# Protobuf API

[`crypto.proto`](../crates/proto/proto/reallyme/crypto/v1/crypto.proto) defines
`CryptoOperationRequest`, `CryptoOperationResponse`, typed results, algorithm
identifiers and errors. It is not a generated mirror of the Rust package API.
The schema declares messages, not an RPC service; applications supply their
transport.

## Generated surfaces

| Language | Package |
| --- | --- |
| Rust | `reallyme-crypto-proto` |
| Swift | `ReallyMeCryptoProto`, `ReallyMeCryptoProtoAdapters` |
| Kotlin | `me.really.crypto.v1`, `me.really.crypto.proto.ReallyMeCryptoProtoAdapters` |
| TypeScript | `@reallyme/crypto/proto` |

Use native facade types for ordinary in-process calls. Use generated messages
when transmitting or storing a structured operation, key envelope or error.
Public JWK/JWKS JSON has its [own contract](jwk.md).

Rust `*OwnedView` handles own clearing storage and do not implement `Clone`.
Their `to_owned_message()` conversion returns a `Result`. Serialize public
metadata using its message or borrowed view; owned-handle serialization is denied.

## Calling operations

Enable Rust's `operation-response` feature and the required algorithms:

```rust
reallyme_crypto::operation_contract::process_operation_response(request_bytes)
```

The SDKs expose `processOperationResponse`; their provider must be initialized
as described in the package README. Input is binary `CryptoOperationRequest`.
Output is binary `CryptoOperationResponse` with either a typed `result` or an
`error`. Missing algorithms return `PROVIDER_UNSUPPORTED_ALGORITHM` without
fallback.

The binary boundary supports hashing, AEAD, MAC, signatures, key agreement,
KEMs, KDFs, key wrap and HPKE according to the selected provider/features.
Standalone schema messages do not automatically add an executable operation.
Platform-key handle messages use the SDK's platform APIs, not the Rust operation
wrapper.

The JSON entry point,
`reallyme_crypto::operation_contract::process_operation_response_json`, also
returns binary protobuf. It accepts only the non-secret request selectors in
[ProtoJSON examples](proto-json.md). Private keys, plaintext, passwords, PSKs
and shared secrets must use binary protobuf.

## Limits and decoding

- Standalone binary messages and operation requests: 1,048,576 bytes. Operation
  responses have an additional envelope allowance; use the exported
  `MAX_CRYPTO_OPERATION_RESPONSE_BYTES` or the C header's
  `RM_CRYPTO_OPERATION_RESPONSE_MAX_LEN` when allocating a response buffer.
- JSON input: 1,572,864 bytes; its decoded protobuf must still fit the binary
  limit.
- Recursion depth: 64.
- Executable requests reject unknown fields, unknown selectors and additional
  operation branches.

Use `reallyme_crypto_proto::wire::decode_protobuf` for standalone untrusted Rust
messages. A permissive decoder that discards unknown fields cannot establish
the same admission policy. `wire::merge_protobuf` clears the destination if a
merge fails.

Swift and Kotlin value-envelope byte adapters also cap input at one mebibyte.
Their general generated messages may retain unknown fields for schema evolution;
do not use unknown fields to carry executable security policy.

## Algorithms and field presence

Select an algorithm by its family-specific enum. `UNSPECIFIED`, wrong-family
choices and unknown modifiers are rejected. Recognizing an enum value does not
mean a build has its implementation. Key metadata identifies a key; it does
not supply a missing hash, signature encoding or operation.

ReallyMe enum values are not JOSE, COSE, TLS or multicodec registry values.
Translate by typed identity. `HpkeKemId`, `HpkeKdfId` and `HpkeAeadId` use HPKE
registry numbers. Assigned numbers and retired names remain reserved; see
[CONTRACT.md](../CONTRACT.md).

Optional fields and `oneof` branches preserve presence. For existing implicit
byte fields, omitted values become empty bytes: empty messages/AAD/context are
permitted where the operation defines them, while keys and signatures still
undergo their length checks. Empty HKDF salt follows RFC 5869's absent-salt
convention.

When extending the schema, use `optional` where absence differs from an explicit
default; do not add a parallel `has_*` flag. Changing an existing field's presence
changes generated API and default-value round trips even when the wire tag is
unchanged. Coordinate versions before sending new fields to strict receivers.

## Errors and verification

`CryptoError` preserves its primitive, provider or backend branch and
`CryptoErrorReason`. Pass the structured error through unchanged when another
service needs its exact reason; broad SDK exceptions are convenience projections.
Unknown future reason codes can pass through only within their branch's reserved
range. Native `CryptoError` construction requires a known, nonzero reason.

`CRYPTO_VERIFICATION_STATUS_INVALID` means a well-formed request failed to
verify. Malformed input, unavailable providers and backend errors use
`CRYPTO_VERIFICATION_STATUS_ERROR` with a structured error. Do not treat either
status as success.

## Operation-specific inputs

- Ed25519 signing takes a 32-byte seed, not a 64-byte expanded key.
- BIP-340 signing uses its dedicated request with 32-byte `message32`,
  `secret_key` and `aux_rand32`. Generic signature signing cannot carry the
  auxiliary input and rejects this algorithm.
- Generic PBKDF2 accepts SHA-256/SHA-512 and 100,000–10,000,000 iterations.
  Argon2id uses a dedicated immutable `kdf_version` profile.
- RSA verification supports the declared PKCS#1 v1.5 and PSS suites. PSS uses
  matching message/MGF1 hashes and digest-length salt. SHA-1 is for legacy
  verification only. Protocols remain responsible for their accepted profiles.

## HPKE Support

`HpkeSuiteIdentifier` contains a KEM, KDF and AEAD. With the full Rust native
profile, the executable component sets are:

| Component | Implementations |
| --- | --- |
| KEM | DHKEM P-256/P-384/P-521/secp256k1/X25519/X448; ML-KEM-512/768/1024; MLKEM768-P256; MLKEM1024-P384; X-Wing |
| KDF | HKDF-SHA256/SHA384/SHA512 and SHAKE256 |
| AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 and export-only |

Each triple still passes capability checks. Seal/open reject export-only;
export operations reject SHAKE256 with export-only. Disabled or unavailable
combinations return a typed error before setup.

The typed Swift, Kotlin, Android and TypeScript HPKE facades expose
P-256/HKDF-SHA256/AES-256-GCM and X25519/HKDF-SHA256/ChaCha20-Poly1305 through
Rust providers. Other Rust suites and MLS aliases are documented in the
[HPKE crate](../crates/hpke/README.md).

HPKE derivation requires at least 32 bytes of secret IKM and invokes the KEM's
`DeriveKeyPair` procedure. Callers must provide sufficient entropy; the length
check cannot establish it. Seal requests have no caller-supplied nonce.
Live contexts and their keys, nonces and sequence state are not serializable;
the wire API exposes individual operations. Deterministic encapsulation
randomness is test-only and is not a production request field.

## Secret storage

Keep sensitive messages short-lived and avoid logging or unnecessary cloning.
Rust generated secret owners clear their retained storage. Caller-owned inputs,
exported bytes, borrowed backing buffers and managed-runtime copies have
separate cleanup obligations. Read [memory ownership](../SECURITY.md).

## Generation

Normal Cargo builds use committed generated code. To regenerate locally, use
Buf 1.75.0 and Buffa 0.1.3:

```sh
cargo install reallyme-protoc-gen-buffa --version '=0.1.3' --locked
cargo install reallyme-protoc-gen-buffa-packaging --version '=0.1.3' --locked
npm ci --prefix packages/ts
bash scripts/install_local_proto_tools.sh
export PATH="$PWD/.build/crypto-proto-tools/bin:$PATH"
buf lint
node scripts/generate_protobuf.mjs
```

SDK generation also requires protoc 36.2, protoc-gen-swift 1.39.0 and
protoc-gen-es 2.17.0. The installer and generator check the local tools;
`--rust-only` skips SDK generation. Outputs go to `crates/proto/src/generated`,
`packages/ts/src/proto/generated` and `gen/`.

Review generated diffs, run the pinned protobuf compatibility check in CI and
[conformance tests](conformance.md). Do not edit generated files by hand.

## TypeScript example

```ts
import {
  HashAlgorithm,
  hashAlgorithmFromProto,
  hashAlgorithmToProto,
} from "@reallyme/crypto/proto";

const facadeAlgorithm = hashAlgorithmFromProto(HashAlgorithm.SHA2_256);
const protoAlgorithm = hashAlgorithmToProto(facadeAlgorithm);
```
