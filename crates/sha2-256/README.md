# ReallyMe Crypto SHA-256

`digest` returns a zeroizing 32-byte SHA-256 digest.

`Sha2_256Hasher` supports `new`, fallible `update`, `processed_bytes` and
consuming `finalize`. A failed update leaves the transcript unchanged. Explicit
zeroization invalidates the context; drop clears retained state and input.
Callers own cleanup of their original input and exported digest copies.

The Rust `operation_contract::incremental_hash::IncrementalHash` adapter accepts
the schema-defined lifecycle messages and returns `CryptoHashResult`. Hash
state cannot be serialized, cloned or imported. Incremental hashing has no
Swift, Kotlin, TypeScript, C ABI or WASM entry point.
