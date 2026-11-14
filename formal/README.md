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
| [ProtoJSON request policy](../crates/proto/src/operation_request_wire.rs) | Only reviewed selectors can pass classification. An `aeadSeal` selector returns the typed policy error before scanning its value. A second top-level member is rejected when an allowed request contains a string with JSON delimiters. | All selector byte strings through 64 bytes, an `aeadSeal` prefix followed by four arbitrary bytes, and a `hash` object with eight arbitrary unescaped string bytes followed by an optional fixed second member. A separate harness checks panic freedom for arbitrary requests through 12 bytes. The schema parity and transport tests cover the complete selector list and the generated JSON decoder. |
| [HPKE component dispatch](../crates/hpke/src/dispatch.rs) | Unknown IDs return the typed unsupported-algorithm error. A registered ID routes to the implementation with the same ID if enabled and returns that error otherwise. Export-only AEAD is rejected by encryption dispatch. | All 65,536 numeric inputs in each of the KEM, KDF, and AEAD families, under the full native profile and a restricted P-256 profile with export-only enabled. The callbacks read the actual implementation types' associated IDs. The proofs compare dispatch with the registry and the build's declared support, and do not execute the implementations or exercise SDK provider routing. |
| [HPKE backend nonce and sequence state](hpke/aead_state_proof_tests.rs) | Each supported record AEAD derives the nonce prescribed by [RFC 9180 §5.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2), and distinct sequence numbers produce distinct nonces for the same base nonce. Sender and receiver pass the current nonce to the AEAD, advance once on success, preserve their state on an AEAD error, and reject records once exhausted. | All 64-bit sequence values and all 96-bit base nonces. Nonce proofs instantiate the real AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 types. One-step state proofs run the actual detached seal/open methods with a test AEAD that can succeed or fail, plus a second call at sequence exhaustion. They abstract the cipher, key schedule and KEM. |
| [AEAD plaintext handoff](../crates/crypto/core/src/authenticate_record.rs) | The shared open path splits the tag and gives the backend a mutable slice of a clearing buffer. Authentication failure cannot return that buffer, even if the backend has written candidate plaintext. Records with truncated tags never call the backend. | All four-byte ciphertexts, 16-byte tags, candidate output bytes, and subsets of output bytes written. The harness checks reachability of success and failure after both partial and complete writes. AES-128/192/256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305, and HPKE Base and PSK opens use this handoff. The proof assumes the backend reports authentication correctly. It covers Rust ownership and release, while cipher internals and physical erasure require separate evidence. |
| [C ABI AEAD output handoff](../crates/ffi/src/aead_proof_tests.rs) | The six scalar AEAD decrypt exports and both HPKE Base suites return `RM_CRYPTO_AUTHENTICATION_FAILED` with the caller's entire output buffer and length unchanged, including after a partial or complete backend write. | All four-byte ciphertexts with 16-byte tags, valid disjoint pointers, arbitrary six-byte initial output buffers, and all initial `size_t` values. The harnesses use the exported functions and real status mapping. They model normal return from the panic guard, successful overlap checks, and the error handoff from the separately verified Rust staging helper. Native tests exercise success and authentication failure against real ciphers with the full guard and overlap checks. |

[Formal Verification](../.github/workflows/formal-verification.yml) runs these
proofs for changes to the covered crates, dependencies, and verifier workflow.
Kani 0.68.0 supplies the compiler used for verification. From the repository root:

```sh
cargo install --locked kani-verifier@0.68.0
cargo kani setup
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-proto --features generated
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-core
CARGO_NET_OFFLINE=true cargo kani -p crypto-ffi --lib -Z stubbing --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features native
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm,aead-export-only
python3 formal/hpke/verify.py
git diff --exit-code -- Cargo.lock
```

The backend runner requires Python 3.12 or later. It verifies the crates.io
HPKE archive against the checksum in the workspace lockfile, resolves its
dependencies offline against that lockfile, and appends the harness in a
temporary directory to access the backend's private context state. The runner
builds that temporary source with only the features needed for verification.
The package's normal build continues to use Cargo's registry dependency.

The [reference DER encoder proofs](../docs/external-conformance-vectors.md#formal-methods-candidates)
run separately in the External Vector Audit workflow.

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
| Provider selection and operation dispatch | Extend Kani to Rust operation, algorithm, and key-family gates. Use the provider manifest and executable SDK conformance checks to cover missing-provider behavior in Swift, Kotlin and TypeScript. |
| HPKE context binding | Extend the symbolic model to cover context binding and use independent conformance vectors for the byte-level key schedule. |
| AEAD failure and secret ownership | Extend output-preservation coverage to provider-specific SDK paths. Review the zeroization obligations of each additional owner. |
| Encoding and primitive equivalence | Start with ML-KEM coefficient encoding and decoding, strict ECDSA low-S handling, and X25519/X448 input and shared-secret checks. Use an independent Cryptol specification and SAW where a small fixed-size implementation can be connected reproducibly to the verified artifact. AES-KW, Keccak, and hybrid KEM composition are candidates after that integration is established. |
