# ReallyMe Crypto SHA3-256

The `digest` function returns the established fixed-size, cleanup-owned SHA3-256 digest.

`Sha3_256Hasher` provides `new`, checked `update`, `processed_bytes`, and consuming
`finalize` methods. Chunked input produces the same digest bytes as the one-shot
operation, including for empty input. A rejected update leaves the transcript
unchanged. Explicit zeroization invalidates the context; dropping an unfinished
context erases its retained state and buffered input.

The canonical lifecycle, algorithms, limits, and failure reasons are defined in
[`crypto.proto`](../proto/proto/reallyme/crypto/v1/crypto.proto). The umbrella
crate's `operation_contract::incremental_hash::IncrementalHash` adapter accepts generated protobuf
requests and returns the existing `CryptoHashResult`. Partial hash state remains
local and cannot be serialized, cloned, or imported. Callers retain responsibility
for cleanup of their original input and any exported digest copies.
