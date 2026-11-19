# Secret memory and ownership

Rust secret owners clear their retained storage on drop. Exporting bytes or
copying them into an SDK result transfers cleanup responsibility to the caller.
Zeroization does not guarantee removal of compiler, register, allocator, OS or
provider-internal copies.

## Rust and protobuf

Prefer secret owners and borrowed access over exporting raw byte arrays.
Clear an exported `Vec`, array or serialized request when no longer needed.
Never log keys, passwords, plaintext, shared secrets or request payloads.

Generated sensitive Rust protobuf owners clear retained storage when dropped
or explicitly cleared. Use guarded setters and `buffa::Message::clear`;
bytes moved out of fields become caller-owned. Clones have independent cleanup
obligations. Borrowed views retain their backing storage rather than erasing it.
Sensitive generated views fail serde `Serialize` with a fixed error.

Use binary protobuf for secret-bearing executable requests. The ProtoJSON
operation boundary rejects those request selectors before decoding their values.
This restriction does not erase caller-owned JSON strings or deserializer scratch
storage. See [the protobuf boundary](docs/protobuf.md).

## Managed-runtime best-effort cleanup helpers

Swift, Kotlin and JavaScript byte arrays are not guaranteed-zeroized storage.
Runtime compaction, copy-on-write, providers, codecs and debugging tools can
retain copies after the supplied array is cleared.

Clear caller-owned buffers promptly:

- Swift: `ReallyMeCryptoMemory.bestEffortClear(&bytes)`
- Kotlin/JVM and Android: `ReallyMeCryptoMemory.bestEffortClear(bytes)`
- TypeScript: `bestEffortClear(bytes)`

These helpers overwrite the supplied array only. For long-lived platform keys,
use the SDK's explicit Secure Enclave or Android Keystore APIs where supported.
Review their access-control policy; non-exportability alone does not require
user authorization for each operation.

Do not transport secrets as managed strings. Configure application logs,
diagnostics, crash uploads and process snapshots for the sensitivity of the
material being processed.

## FFI and WASM

Callers must keep foreign allocations valid, sized and unaliased for each call.
They own output cleanup and any copies made after return. Follow the
[C ABI rules](crates/ffi/README.md), including status checks and destroy paths.

For browser Argon2id, use a short-lived Worker: WebAssembly linear memory does
not shrink after a derivation. Discard the provider instance after a trap.
The [TypeScript README](packages/ts/README.md#browser-wasm-lifecycle) describes
loading and lifecycle requirements.

## Protocol and KDF requirements

Generic AEAD primitive and dispatch APIs treat `aad` as caller-provided bytes.
Applications must bind the required protocol context and cipher suite into AAD;
the primitive does not add them. Follow the protocol's nonce rules and use
separate derived keys for separate purposes.

Argon2id uses fixed versioned profiles: V1 requires 256 MiB with three passes
and one lane; V2 requires 512 MiB with three passes and one lane. Select a profile
that the target can execute. PBKDF2 public routes accept 100,000 through
10,000,000 iterations. The generic protobuf KDF branch does not execute
Argon2id; use its dedicated versioned API.

## Known portable Brainpool limitation

`primefield` 0.14.0 stages an unguarded padded coordinate array in
`MontyFieldElement::to_bytes`. A portable Brainpool ECDH result owner clears its
retained shared-secret bytes but cannot clear that intermediate array. This is
a library-owned buffer gap, separate from unavoidable compiler/register copies.
Do not treat this path as satisfying a requirement to clear every secret buffer.

The published dependency graph still uses the upstream implementation. The
[candidate patch manifest](patches/primefield/manifest.json) describes a separate
override; its presence does not mean the published package uses the repair.

## Validation

When changing secret ownership, run the relevant tests and
`node scripts/check_release_readiness.mjs`. The complete release commands are
in [conformance](docs/conformance.md#release-checks).
