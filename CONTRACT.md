# Crypto Contract

## Canonical Contract

The schema at
[`crypto.proto`](crates/proto/proto/reallyme/crypto/v1/crypto.proto) defines
`CryptoOperationRequest`, `CryptoOperationResponse`, algorithm identifiers,
result types and wire errors. Rust remains the reference implementation.

[`provider_manifest.json`](provider_manifest.json) records supported SDK
providers. [`PROVIDER_POLICY.md`](PROVIDER_POLICY.md) lists availability by
algorithm and platform. [`vectors/`](vectors/) contains the shared byte and
error fixtures.

Every provider route must implement identical input validation, output
encodings and typed failure semantics. A missing provider or unsupported
algorithm returns a typed error without trying a different provider.

## Structured operations

Enable Rust's `operation-response` feature to call
`reallyme_crypto::operation_contract::process_operation_response` with binary
protobuf. The response is binary `CryptoOperationResponse`, including when the
operation fails.

ProtoJSON accepts only non-secret request selectors and returns the same binary
response. Use binary protobuf for requests containing private keys, passwords,
plaintext, PSKs or shared secrets. See [the wire API](docs/protobuf.md) and
[JSON examples](docs/proto-json.md).

Assigned field numbers, enum numbers and retired names are immutable. Removed
assignments remain reserved. ReallyMe algorithm enum values are not JOSE,
COSE, TLS or multicodec identifiers; translate by typed identity. HPKE's KEM,
KDF and AEAD enums use their registry identifiers.

Absent optional fields and present-empty fields can have different meanings.
Unknown selectors, wrong-family selectors and unspecified algorithms are
rejected. Individual APIs define required lengths and validation order.

## Errors and memory

Rust operations use `CryptoError` and schema-defined `CryptoErrorReason`
values. SDK facades expose platform-specific typed errors; structured responses
retain their wire reason. C and scalar WASM status values are coarser projections.
Errors contain no caller bytes or backend exception text.

Keep secret-bearing messages short-lived. Clear caller-owned inputs and
exported secrets after use; copying a result creates another cleanup obligation.
See [memory ownership and limitations](SECURITY_MEMORY_MODEL.md).

## SDK differences

The TypeScript facade is synchronous. WebCrypto is not part of the facade.
Rust-backed operations require its
initialized package-owned WASM provider. Swift and Kotlin require their native
provider for the routes listed in the provider matrix.

Platform-resident P-256 keys use explicit Secure Enclave or Android Keystore
handles. These are separate APIs from raw private-key operations. Hardware
signatures need not reproduce deterministic software-signing bytes. The SDK
READMEs describe platform requirements and key lifecycle operations.

## Changing a contract

Update the schema, affected SDKs, provider manifest and positive/negative
vectors together. Preserve assigned wire identities and run the
[conformance checks](docs/conformance.md). Algorithm recognition alone does not
make an operation executable in every SDK or feature configuration.
