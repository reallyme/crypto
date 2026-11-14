# reallyme-crypto-proto

`reallyme-crypto-proto` contains the Rust Buffa bindings for the canonical
`reallyme.crypto.v1` structured wire contract. The package publishes operation
requests and responses, stable algorithm identifiers, typed results, and
non-PII error envelopes for API, storage, and message boundaries.

This crate defines messages only; it intentionally declares no protobuf service.
`CryptoOperationRequest` is the single executable adapter request and
`CryptoOperationResponse` is the primary generated binary response shape.
JSON is a generated ProtoJSON request convenience. Results remain one fully
typed binary protobuf operation response. The executable JSON adapter accepts
only hash, public-key verification, public-key encapsulation, and key-generation
requests whose JSON input carries no cryptographic secret.

Use `wire::decode_protobuf` for standalone untrusted binary messages. Unknown
fields are rejected while decoding the entire tree. Generated DTOs have no
unknown-field storage, so a typed value obtained from a permissive decoder
cannot establish the same guarantee. `wire::merge_protobuf` clears an existing
owner when a merge fails.

Operation requests can contain secrets and plaintext. Owned Rust messages
redact byte-bearing debug output and zeroize sensitive fields on drop. Callers
must keep messages short-lived and avoid cloning or logging payloads.
Secret-bearing executable requests are rejected on the ProtoJSON route before
value deserialization and must use binary protobuf.

The generated surface uses `SecretBytes` and `SecretString` for clearing field
storage. `CryptoKeyPair.secret_key` uses `PrivateBytes`, whose JSON policy
refuses export. Borrow fields by slice, or transfer a byte owner into a
`Zeroizing<Vec<u8>>`. Secret owned views retain a clearing backing allocation
and expose lifetime-bound borrows. Use an eager decoder for admission.

The examples target the 0.4.1 source release. Use a matching local
checkout until that version is available on crates.io.

```toml
[dependencies]
reallyme-crypto-proto = { version = "0.4.1", features = ["generated"] }
```

The `generated` feature includes Buffa protobuf bytes and strict ProtoJSON
support for the generated operation request/response contract. ProtoJSON is a
restricted request and conformance lane for JSON-only adapters and fixtures; it
is not a casual JSON crypto facade. Secret-bearing operations are binary-only.
See the repository's `docs/proto-json.md` for operation-family JSON examples.

For native error types without message codecs, select the minimal feature:

```toml
[dependencies]
reallyme-crypto-proto = { version = "0.4.1", default-features = false, features = ["error-types"] }
```

`error-types` depends only on `thiserror`. It exposes the schema-generated
`CryptoErrorReason`, wire-branch metadata, and the validated `CryptoError`
owner, without Buffa, serde, crypto-core, HPKE, or a cryptographic backend.
The full `generated` feature re-exports the same reason enum, rather than
creating another classification type. Normal Cargo builds use committed
outputs and do not require Buf.

The independent `contract-types` feature exposes immutable schema-owned scalar
constants under `contract_constants`. It has no dependencies, including no
Buffa, serde, or thiserror dependency. Values are compiled from committed Rust
output; applications cannot replace them through request configuration.
The `generated` feature includes these constants as well as `error-types`.

The protobuf source lives at
[`proto/reallyme/crypto/v1/crypto.proto`](proto/reallyme/crypto/v1/crypto.proto).
