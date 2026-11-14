# Formal verification

Kani checks bounded properties of the production Rust source and of the
independent reference DER encoder. Tamarin checks symbolic protocol properties
under a network-adversary model. The conformance suites provide independent
evidence for the cryptographic primitives exercised by these boundaries.

## Rust implementation proofs

The production harnesses are compiled from the same source as the implementation
and are enabled only during verification. Each Kani result applies to the
source revision, dependency lockfile, target, and Cargo features of that run.

| Production code | Property | Scope |
| --- | --- | --- |
| [ProtoJSON request policy](../crates/proto/src/operation_request_wire.rs) | Only reviewed selectors can pass classification. The production JSON gate returns the typed policy error for `aeadOpen`, `hpkeOpen`, and `hpkePskOpen` before invoking the value decoder. A second top-level member is rejected when an allowed request contains a string with JSON delimiters. | All selector byte strings through 64 bytes, each open selector and `aeadSeal` followed by four arbitrary bytes, and a `hash` object with eight arbitrary unescaped string bytes followed by an optional fixed second member. A separate harness checks panic freedom for arbitrary requests through 12 bytes. The public transport tests cover whitespace, escaped and snake-case selectors, additional members, and the generated JSON decoder. |
| [Binary operation open failures](../crates/crypto/src/operation_contract/boundary/proof_tests.rs) | The AEAD, HPKE Base, and HPKE PSK handlers convert a reported authentication failure into the primitive error branch. The generated protobuf writer emits exactly the six-byte error envelope. | The native AES-128-GCM and P-256 HPKE request fixtures use symbolic 17-byte records and stub the operation owners to report authentication failure. The serialization harness verifies the generated size and write passes with a fixed sink. Rust and C ABI integration tests run the binary request decoder, dispatcher, and bounded response encoder with real providers. |
| [Restricted operation admission](../crates/crypto/src/operation_contract/boundary/restricted_dispatch_proof_tests.rs) | A malformed decoder result never reaches dispatch. Disabled AEAD open returns a typed unsupported error for every AEAD ID. Only the Ed25519 signature selector reaches its provider. A key-agreement selector in a signing request fails even when its numeric value matches the accepted signature ID. | The Ed25519-only native operation-response profile. The proof covers every signed 32-bit value in the AEAD, signature, key-agreement, and operation-family enum slots. Binary integration tests exercise the public decoder with an unknown operation tag, disabled routes, a wrong-family selector, and real Ed25519 signing. |
| [Restricted asymmetric provider registry](../crates/crypto/dispatch/src/provider/proof_tests.rs) | The policy query rejects unknown and unspecified operation and key IDs. All seven asymmetric registry entry points reject disabled or mismatched key types without defaulting to the available provider. | The Ed25519-only native dispatch profile, with all signed 32-bit operation and key IDs. Stubs assert that the rejected routes never enter the available primitive adapter. Primitive internals are covered by the conformance suites. |
| [HPKE component dispatch](../crates/hpke/src/dispatch.rs) | Unknown IDs return the typed unsupported-algorithm error. A registered ID routes to the implementation with the same ID if enabled and returns that error otherwise. Export-only AEAD is rejected by encryption dispatch. | All 65,536 numeric inputs in each of the KEM, KDF, and AEAD families, under the full native profile and a restricted P-256 profile with export-only enabled. The callbacks read the actual implementation types' associated IDs. The proofs compare dispatch with the registry and the build's declared support, and do not execute the implementations or exercise SDK provider routing. |
| [HPKE backend nonce and sequence state](hpke/aead_state_proof_tests.rs) | Each supported record AEAD derives the nonce prescribed by [RFC 9180 §5.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2), and distinct sequence numbers produce distinct nonces for the same base nonce. Sender and receiver pass the current nonce to the AEAD, advance once on success, preserve their state on an AEAD error, and reject records once exhausted. | All 64-bit sequence values and all 96-bit base nonces. Nonce proofs instantiate the real AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 types. One-step state proofs run the actual detached seal/open methods with a test AEAD that can succeed or fail, plus a second call at sequence exhaustion. They abstract the cipher, key schedule and KEM. |
| [AEAD plaintext handoff](../crates/crypto/core/src/authenticate_record.rs) | The shared open path splits the tag and gives the backend a mutable slice of a clearing buffer. Authentication failure cannot return that buffer, even if the backend has written candidate plaintext. Records with truncated tags never call the backend. | All four-byte ciphertexts, 16-byte tags, candidate output bytes, and subsets of output bytes written. The harness checks reachability of success and failure after both partial and complete writes. AES-128/192/256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305, and HPKE Base and PSK opens use this handoff. The proof assumes the backend reports authentication correctly. It covers Rust ownership and release, while cipher internals and physical erasure require separate evidence. |
| [C ABI AEAD output handoff](../crates/ffi/src/aead_proof_tests.rs) | The six scalar AEAD decrypt exports and both HPKE Base suites return `RM_CRYPTO_AUTHENTICATION_FAILED` with the caller's entire output buffer and length unchanged, including after a partial or complete backend write. | All four-byte ciphertexts with 16-byte tags, valid disjoint pointers, arbitrary six-byte initial output buffers, and all initial `size_t` values. The harnesses use the exported functions and real status mapping. They model normal return from the panic guard, successful overlap checks, and the error handoff from the separately verified Rust staging helper. Native tests exercise success and authentication failure against real ciphers with the full guard and overlap checks. |
| [Kotlin JNI AEAD handoff](../crates/ffi/src/kotlin_aead.rs) | An authentication error passes the typed failure status and an empty payload to the JNI result encoder, even when the provider has written bytes and supplied a plausible length. Success requires the expected output length. | All four-byte staging buffers and all produced length values. The harness observes the inputs to the JNI encoder. JVM tests inspect the actual status-only envelope for each JNI-backed AEAD and check that the decoder clears unexpected bytes on failure. |
| [WASM plaintext handoff](../crates/wasm/src/publish_plaintext.rs) | Authentication failure propagates the typed error without invoking the JavaScript array copy. | All four-byte ciphertexts, 16-byte tags, candidate output bytes, and subsets of backend writes. The harness uses the production Rust staging and release helpers. The scalar WASM AEAD and HPKE Base exports share the release helper. The JS host receives a numeric status on failure. |

[Formal Verification](../.github/workflows/formal-verification.yml) runs these
proofs for changes to the covered crates, dependencies, and verifier workflow.
Kani 0.68.0 supplies the compiler used for verification. From the repository root:

```sh
cargo install --locked kani-verifier@0.68.0
cargo kani setup
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-proto --features generated
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto --features operation-response --lib -Z stubbing --jobs 2 --output-format terse
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,native,ed25519 --lib -Z stubbing --jobs 2 --output-format terse
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto --no-default-features --features operation-response,native,ed25519 --lib -Z stubbing --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo test --locked -p reallyme-crypto --no-default-features --features operation-response,native,ed25519 --test restricted_operation_dispatch_tests
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-core
CARGO_NET_OFFLINE=true cargo kani -p crypto-ffi --lib -Z stubbing --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-wasm --lib --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features native
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm,aead-export-only
python3 formal/hpke/verify.py
git diff --exit-code -- Cargo.lock
```

The operation-response command uses release-style dependency assertions to
keep generated-message verification tractable. Kani still checks arithmetic,
memory safety, loop bounds, and the harness assertions.

The backend runner requires Python 3.12 or later. It verifies the crates.io
HPKE archive against the checksum in the workspace lockfile, resolves its
dependencies offline against that lockfile, and appends the harness in a
temporary directory to access the backend's private context state. The runner
builds that temporary source with only the features needed for verification.
The package's normal build continues to use Cargo's registry dependency.

The [reference DER encoder proofs](../docs/external-conformance-vectors.md#formal-methods-candidates)
run separately in the External Vector Audit workflow.

## SDK plaintext release

The supported scalar AEAD and HPKE Base SDK paths expose a typed error when
authentication fails. The published providers are trusted to report the
authentication outcome. The checks cover SDK-visible results and errors.
Provider internals, side channels, and physical memory erasure are outside
their scope.

| SDK boundary | Executable coverage |
| --- | --- |
| [Swift C ABI result handling](../packages/swift/Tests/ReallyMeCryptoTests/AeadPlaintextReleaseTests.swift) | Exhaustively checks all subsets of writes to four candidate plaintext bytes with representative produced lengths, including a valid length, negative lengths, and overflow-sized values. The status check precedes the copy for all Rust-backed AEAD and HPKE Base opens. Runtime tests also exercise real Rust and CryptoKit providers. |
| [Kotlin SDK and JNI](../packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoSymmetricTest.kt) | Exercises Bouncy Castle and JNI through all six AEAD routes with tampered ciphertext, tag, and AAD. Kotlin HPKE Base vectors exercise both Bouncy Castle suites. |
| [TypeScript and bundled WASM](../packages/ts/test/wasm-boundary.test.mjs) | Checks that the raw WASM export throws only the numeric failure status for all six scalar AEADs and that the SDK exposes only a typed error. Both HPKE Base suites have the same check in the [SDK vectors](../packages/ts/test/reallyme-crypto.test.mjs). |

## SDK provider availability

Swift, Kotlin, and TypeScript test unconfigured Rust routes through their public
facades. Each SDK reports its typed unsupported-algorithm error for AES-256-GCM-SIV
and for the binary and ProtoJSON operation transports. Kotlin runs these tests in
a fresh JVM so an earlier test cannot activate the native provider. Swift cases
also distinguish the error for a provider that failed to load, and TypeScript
checks that a separately configured provider cannot satisfy an explicit empty
configuration. See [Provider Selection](../docs/provider-selection.md).

## Symbolic HPKE model

The [HPKE Base model](tamarin/hpke_base.spthy) exercises a single seal/open
exchange using DHKEM, a symbolic key derivation function, and idealized
authenticated encryption. It keeps HPKE `info` and AEAD `aad` separate. The
secrecy lemma ties adversary knowledge of an honestly generated plaintext to
revelation of the recipient's static key. An existence lemma checks that an
honest round trip is possible. The model abstracts away curve and AEAD choices,
byte encodings, and multi-record state.

Run with Tamarin 1.12.0 and Maude on `PATH`:

```sh
tamarin-prover --prove --quit-on-warning formal/tamarin/hpke_base.spthy
```

The summary must report both `sanity_roundtrip_exists` and `plaintext_secrecy`
as verified. Tamarin can exit successfully with an incomplete proof, so check
the lemma results.

## Next targets for 0.5.0

| Target | Property and method |
| --- | --- |
| HPKE context binding | Model agreement on suite, recipient key, and `info`/`aad`. Check mismatched-context rejection with independent byte-level vectors for the key schedule. |
| Additional provider profiles | Repeat the provider reachability checks for reduced WASM and mixed signature/KEM profiles, including feature-specific dispatch differences. |
| Encoding and primitive equivalence | Start with ML-KEM coefficient encoding and decoding, strict ECDSA low-S handling, and X25519/X448 input and shared-secret checks. Use an independent Cryptol specification and SAW where a small fixed-size implementation can be connected reproducibly to the verified artifact. AES-KW, Keccak, and hybrid KEM composition are candidates after that integration is established. |
