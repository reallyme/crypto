# Source layout

ReallyMe Crypto is a proto-first cryptography workspace. Use this map to find
an API, change its implementation or update an adapter.

| Path | Contents |
| --- | --- |
| `crates/proto/` | Schema, generated Rust types and bounded wire codecs |
| `crates/crypto/` | Rust facade and structured operation handlers |
| `crates/crypto/core/` | Shared algorithm identifiers and errors |
| `crates/crypto/dispatch/` | Provider selection and algorithm dispatch |
| `crates/crypto/signer/` | Stateful signer and verifier APIs |
| Other `crates/` members | Primitive and protocol implementations |
| `crates/ffi/`, `crates/wasm/` | C/JNI and WASM adapters |
| `packages/` | Swift, Kotlin, Android and TypeScript SDKs |
| `gen/` | Generated SDK protobuf bindings |
| `vectors/` | Shared and external conformance fixtures |
| `scripts/` | Generation, validation and packaging tools |

The root `Package.swift` points to the Swift sources under `packages/swift`.

Keep primitive crates independent of SDKs and transports. Put public structured
operations in the schema before implementing their adapters. Generated messages
carry data; operation handlers execute it. Update the matching route in
`provider_manifest.json` when changing provider support.

See [CONTRACT.md](../CONTRACT.md) for wire compatibility rules,
[protobuf generation](protobuf.md#generation) for binding commands, and
[conformance](conformance.md) for validation.
