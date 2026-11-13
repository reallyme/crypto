# Security Memory Model

## Scope

This document defines the memory-safety and secret-handling model for the
ReallyMe Crypto workspace.

Scope covers:

- Cryptographic family crates under `crates/`
- Protocol crates such as HPKE under `crates/hpke/`
- Shared typed error and boundary types under `crates/crypto/core/`
- Native Rust, WebAssembly, Swift, Kotlin/JVM, and Kotlin/Android runtime lanes
- FFI adapters that move cryptographic material across platform boundaries
- SDK packages under `packages/swift`, `packages/kotlin`,
  `packages/kotlin-android`, and `packages/ts`

Protocol crates may impose stricter rules. They must not weaken this model.

## Data Inventory

| Data class | Examples | Sensitivity | Required owner model |
| --- | --- | --- | --- |
| Root secrets | Long-lived root keys and derivation inputs | Critical | Fixed-size secret owner, `ZeroizeOnDrop`, no `Debug`/`Display` |
| Derived keys | AEAD keys, HKDF outputs, session keys, and domain-separated secrets | Critical | Fixed-size secret owner or `Zeroizing`, zeroized on drop |
| KDF inputs | Password bytes, passphrases, client secrets, salts where policy treats them as sensitive | High/Critical | Secret wrapper for caller-owned secret input; typed non-secret wrapper for salts |
| Plaintext | Decrypted sensitive payloads and protocol plaintext | High/Critical | Rust-owned values use `Zeroizing` or a destroyable owner; managed SDK byte arrays are caller-owned and best-effort clearable |
| Public crypto material | Public keys, nonces, salts, digests, ciphertext | Integrity-sensitive | Typed wrappers; not interchangeable with arbitrary bytes |
| Authentication artifacts | AEAD tags, signatures, proofs, transcript bindings | Integrity-sensitive | Typed wrappers and constant-time verification where applicable |
| Platform handles | Swift/Kotlin/WASM opaque handles to Rust-owned secrets | Critical | Explicit destroy/zeroize path where exposed; no managed string transport for secrets |

## Lifecycle Model

### 1. Ingest

- External bytes enter as untrusted input.
- Length and shape checks happen before parsing or allocation-heavy work.
- Buffer lengths, offsets, and capacities use checked arithmetic.
- Secret-bearing inputs are moved into explicit secret owner types as early as the API allows.

### 2. Operate

- Cryptographic operations run on bounded inputs with typed domain separation.
- Temporary secrets use `Zeroizing<T>` or an owner that implements `ZeroizeOnDrop`.
- Authentication failures return typed errors and must not expose backend exception text, raw input, or secret-bearing context.
- Comparisons of MACs, tags, signatures, and derived values use constant-time primitives when the value is security-sensitive.

### 3. Export

- Public outputs use typed wrappers.
- Secret outputs stay in secret owner types.
- FFI exports prefer opaque Rust-owned handles for long-lived plaintext and private material.
- If a platform lane copies sensitive bytes into Swift, Kotlin, TypeScript, JVM, Android, or browser-managed memory, the adapter must document the best-effort cleanup boundary and avoid overstating zeroization guarantees.

### 4. Clear / Drop

- Owner types zeroize on drop.
- Generated Rust protobuf byte/string fields clear their previous contents
  before replacement during merging. Failed merges clear partial output, and
  owner destruction clears retained allocation capacity. Caller-owned input
  buffers and managed-runtime codec copies remain the caller's responsibility.
- Temporary buffers are zeroized before returning where drop timing is not enough.
- FFI, JNI, WASM, and platform FFI adapters zeroize Rust-owned temporary inputs,
  plaintexts, shared secrets, derived keys, and secret-bearing output staging
  buffers after copying to the caller-owned result or before throwing from a
  native/provider error path.
- Managed-runtime cleanup helpers overwrite the caller-owned byte array view only; they cannot clear historical runtime, provider, protobuf, debugger, crash-report, or garbage-collector copies.
- Public SDK containers that carry private keys or shared secrets must redact
  string/debug output and must not compute object hash codes from secret bytes.
- Stateful protocol code must provide explicit session teardown when secrets can outlive a single call.
- Tests that inspect secret internals must keep that access local to the test crate and avoid logging raw values.

## Implemented Controls

| Control | Status | Evidence |
| --- | --- | --- |
| Workspace panic/unwrap/debug-print denies | Implemented | Root `Cargo.toml` workspace lints |
| Member lint inheritance | Implemented | Every member `Cargo.toml` has `[lints] workspace = true` |
| Typed domain errors | Implemented | `core/src/error.rs`, primitive-specific `ErrorReason` use |
| Zeroizing secret wrappers | Implemented for secret-bearing primitives | AES/KDF/HKDF key and secret owner types |
| Runtime lane separation | Implemented as feature lanes and package matrix entries | Rust `native`/`wasm` feature checks; Swift/Kotlin SDK lanes in `PROVIDER_POLICY.md` |
| Negative-vector policy | Implemented as workspace policy | `vectors/README.md`, `CONTRACT.md`, `PROVIDER_POLICY.md` |
| Managed-runtime best-effort cleanup helpers | Implemented for Swift, Kotlin, and TypeScript | `ReallyMeCryptoMemory.bestEffortClear`, `bestEffortClear(bytes)` |
| Dependency policy gate | Implemented | `deny.toml` |
| Dual MIT / Apache-2.0 licensing | Implemented | License headers on project-owned code and scripts; package metadata and `LICENSE` |

## Hardening Expectations

Every primitive must define:

- Allowed input sizes and maximum allocation sizes.
- Which values are secret, public, or integrity-sensitive.
- Which values must be domain-separated.
- Which errors are intentionally generic to avoid oracle behavior.
- Which runtime lanes are complete, guarded, or intentionally unavailable.
- Which negative vectors prove failure behavior.

## Primitive Security Notes

Engineering rules that apply across primitives and protocols:

### Cipher Suite Binding

- Protocol and message-format layers that compose AEAD MUST bind their cipher-suite identifier into AAD before calling generic AEAD primitives.
- Generic AEAD primitive and dispatch APIs treat `aad` as caller-provided bytes and do not mutate, prepend, or validate higher-level suite identifiers.
- Policy/verification code must reject decrypt if reconstructed protocol AAD does not match exactly.
- This prevents cross-suite confusion and downgrade-style misuse.

### HKDF Domain Separation

- Derive per-domain subkeys from root material using HKDF.
- Use explicit purpose tags and domain tags.
- Never reuse the same derived key across domains or purposes.

### Argon2id Policy

- Only fixed, code-pinned profiles are allowed (`kdf_version` mapping).
- Current profiles:
  - `V1` (kdf_version=1): 256 MiB, t=3, p=1
  - `V2` (kdf_version=2): 512 MiB, t=3, p=1
- The caller owns the complete Argon2 block matrix in a `Zeroizing<Vec<Block>>`;
  password-derived working memory is wiped before the allocation is released on
  success, typed failure, or unwind.
- Platform caps are enforced before use:
  - `MobileModern`: mem <= 512 MiB, t <= 4, p <= 4
  - `DesktopModern`: mem <= 2 GiB, t <= 6, p <= 4
- Argon2id is Rust on every lane (see `PROVIDER_POLICY.md`); it is never satisfied
  by a JCA/BouncyCastle or third-party native provider.

### PBKDF2 Work-Factor Policy

- Public PBKDF2 routes accept 100,000 through 10,000,000 iterations.
- Both bounds are validated before native, WASM, Swift, Kotlin, or TypeScript
  derivation so a compact untrusted request cannot select unbounded CPU work.
- The generic KDF protobuf branch intentionally does not execute Argon2id: its
  `iterations` field cannot represent the reviewed Argon2 `kdf_version`
  profiles. Dedicated versioned Argon2id APIs remain the supported route.

### FFI Secret Handling

- The preferred model for long-lived or high-volume plaintext, private material,
  shared secrets, passwords, and derived keys is a Rust-owned opaque handle with
  an explicit destroy path.
- Current SDK facade methods may return Swift `[UInt8]`, Kotlin `ByteArray`,
  and TypeScript `Uint8Array` values for ergonomic one-shot operations. Those
  arrays are managed-runtime copies. They are caller-owned and best-effort
  clearable, not guaranteed-zeroized storage.
- FFI/JNI/WASM adapters must zeroize Rust-owned temporary buffers after copying
  results to the platform lane. That cleanup does not erase platform-owned
  arrays, provider-internal copies, protobuf serialization buffers, or runtime
  copies made before the caller clears them.
- Executable ProtoJSON accepts only request selectors without caller-provided
  secret material. Secret-bearing selectors are rejected before serde value
  deserialization and must use the binary protobuf boundary.
- Generated protobuf `View` and `OwnedView` types that can retain sensitive or
  privacy-bearing bytes fail serde `Serialize` with a fixed error. ProtoJSON is
  produced only from owned messages at an explicit, policy-approved boundary;
  callers must not serialize or log views as a substitute for that boundary.
- Swift CryptoKit and Security.framework ECDH routes copy shared secrets through
  provider-managed `Data` or opaque shared-secret storage before the package
  creates caller-owned `[UInt8]` results. The Swift wrappers best-effort clear
  those owned arrays on validation failure, but provider-managed intermediates
  remain a managed-runtime residual risk.
- Do not pass secret-bearing values as managed strings. Avoid JSON paths for
  private keys, plaintext, passwords, shared secrets, and derived keys.
- New APIs that keep secret material alive beyond a single call should expose an
  explicit destroy/zeroize path rather than only returning managed byte arrays.

### Managed Runtime Cleanup

The SDKs expose narrow helpers for caller-owned arrays:

- Swift: `ReallyMeCryptoMemory.bestEffortClear(&bytes)`
- Kotlin/JVM and Kotlin/Android: `ReallyMeCryptoMemory.bestEffortClear(bytes)`
- TypeScript: `bestEffortClear(bytes)`

These helpers overwrite the supplied byte array view in place. The Swift helper
uses Darwin `memset_s` so the current-storage writes cannot be optimized away.
They are useful for clearing keys, passwords, plaintext, shared secrets, salts,
and derived keys as soon as application code no longer needs them. They do not
and cannot clear copies already made by ARC, JVM or Android garbage collectors,
JavaScript engines, WebAssembly marshalling, protobuf codecs, native providers,
crash reporters, debugger snapshots, swap, hibernation, or application logs.

## Residual Risks

The SHA-256/384/512 one-shot leaves keep compression state and the partial-block
buffer in clearing owners, then serialize state words through clearing byte
owners directly into the existing clearing digest owner. SHA-384 serializes only
its six output words; its two unused state words remain protected until drop.
The leaves use the resolved SHA-2 implementation's compression and block-buffer
padding, retaining its state-clearing features and exact FIPS 180-4 outputs.
Their public `into_bytes` methods retain the existing caller-owned array export
contract.

This path bypasses `digest` 0.11.3's `CtOutWrapper`, whose full-output temporary
has no clearing owner. That dependency behavior remains relevant to other users
of its fixed-output interface, but is no longer an intermediate-output gap in
these one-shot leaves. Clearing owners cover normal return and unwinding; the
leaf path has no fallible allocation or typed-error exit. Ownership regression
checks, native/WASM NIST known answers and padding-boundary comparisons verify
this contract without unsafe observations of released storage. Source-level
ownership does not establish erasure of every compiler or CPU copy.

HKDF extract and expand initialize their returned clearing owners before copying
or writing derived material. Expansion errors drop that protected destination;
there is no additional plain local output array to survive either exit path.
The RFC 5869 SHA-256 answers and existing SHA-384/SHA-3 answers retain their
exact output semantics. As with the other adapters, those owners do not erase
buffers internal to a dependency or establish erasure of every arithmetic
working value. Dependency implementation review remains distinct from the
ownership guarantees at these public interfaces.

1. Zeroization cannot remove all copies created by the OS, allocator, CPU, compiler, browser runtime, or platform managed runtimes.
2. FFI callers can copy or log sensitive bytes after receiving them; Rust-side controls cannot erase caller-owned copies.
3. Crash reporters, telemetry, swap, hibernation, and process snapshots remain deployment responsibilities.
4. Browser and mobile managed runtimes provide best-effort memory hygiene only.
5. Public-key and ciphertext wrappers prevent type confusion, but they do not by themselves prove authenticity.
6. The SDK packages in `packages/kotlin` and `packages/ts` hold secret bytes in garbage-collected arrays
   (`ByteArray`, `Uint8Array`). The JVM and JavaScript runtimes give no reliable way to zeroize or pin such memory:
   collectors copy and compact objects freely, so overwriting an array clears one copy at best. This is an accepted
   platform limitation, not an oversight. Deployments needing stronger key hygiene on those platforms must keep
   long-lived secrets in platform key stores (for example Android Keystore) or behind the Rust C ABI's owned buffers
   rather than in language-level arrays. The Swift package has the same property for Swift-managed arrays, with
   CryptoKit `SymmetricKey` and the Secure Enclave as the stronger alternatives.
7. Typed unsupported-algorithm behavior is a deliberate release control, not a
   memory-safety control. It prevents silent provider substitution, but callers
   still need to choose algorithms whose package lane is supported for their
   deployment.

## Mandatory Operational Controls

1. Disable raw request, plaintext, key, and error-context logging in applications that use this workspace.
2. Keep crash and diagnostic upload policies aligned with the sensitivity of plaintext and secret material.
3. Run the full workspace validation gate before merging crypto changes.
4. Require positive and negative vectors for every new primitive, backend, or security hardening change.
5. Treat FFI destroy/zeroize paths as part of the API contract, not cleanup polish.

## Validation

Run the [conformance validation](docs/conformance.md#full-release-wall), including
`node scripts/check_release_readiness.mjs`, before accepting changes to secret
ownership or boundary handling. Record skipped hardware tests and their scope
in release evidence.

### Random-output source ownership

The CSPRNG leaf fills a `Zeroizing<[u8; N]>` source and copies directly into the
returned clearing owner. The source guard clears on success, entropy failure
and unwinding, including partial writes by an injected entropy source. This
protects the named source allocation as well as the returned owner; it does not
claim erasure of every compiler or register copy. Native Clippy and test-source
compilation pass for this repair. Runtime test execution is deferred.

### X448 scalar import ownership

The X448 leaf validates borrowed scalar width before copying and immediately
places the named scalar copy in a clearing guard before constructing its
existing protected backend owner. Its owned-array constructor also clears the
Copy input parameter explicitly. Caller-owned inputs remain unchanged. This is
a local named-buffer repair, independent of the separately accepted upstream
prime-field serialization gap; it does not promise erasure of every compiler
or register copy. Runtime regression execution remains deferred.

### Key-format serialization intermediates

P-256 container import immediately guards its named serialized scalar before
validation and copying to the returned clearing owner. Trusted JWK
canonicalization now clears owned serde JSON strings, including object keys,
on successful output and failure. These call-site ownership repairs preserve
existing parsing, canonicalization and cryptographic bytes. They do not alter
the separately tracked upstream prime-field serialization limitation or claim
control over serializer/compiler-internal copies. Runtime regression execution
remains deferred.

### Argon2id and Concat KDF leaf outputs

Argon2id initializes its final derived-key owner before backend output begins;
partial output and the separately guarded memory matrix clear on failure.
Concat KDF guards every finalized SHA-256 output immediately and copies derived
bytes directly into its final clearing owner. Its arbitrary-byte AlgorithmID
owner clears on drop, redacts debugging, and gives every clone independent
clearing storage. These are source-level ownership guarantees, not claims about
erasing every compiler or register copy. They do not repair the separately
accepted upstream prime-field encoding temporary.

### X-Wing encapsulation coins

The local ML-KEM coins conversion in X-Wing immediately installs a clearing
owner around the distinct fixed-size byte array. The caller's coins owner cannot
clear this local copy. Its cleanup covers both successful encapsulation and
early exits without changing deterministic bytes or provider features.

### Wide SHA-3 finalization

SHA3-224, SHA3-384 and SHA3-512 initialize the final clearing digest owner before
calling the backend's direct-output finalization interface. No named unguarded
finalized array or second local byte array remains at these call sites.
SHA3-256 already uses this direct-output path. SHAKE256 retains caller-owned
output storage, including caller-sized generated clearing result owners, rather
than allocating an unbounded result from an untrusted requested length.

### Raw secp256k1 shared-secret ownership

The standalone raw shared-secret type now implements `Drop` and invokes its
existing zeroization method. A `ZeroizeOnDrop` marker alone previously provided
no cleanup implementation. Its final clearing owner is initialized before the
raw x-coordinate is copied, avoiding a separate plain local array. This repair
preserves the native API's scalar checks, uncompressed SEC1 encoding and exact
32-byte result. It does not change the accepted upstream encoding limitation.
