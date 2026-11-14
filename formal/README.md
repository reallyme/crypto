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
| [HPKE Base P-256 plaintext handoff](../crates/hpke/src/base_p256/crypt.rs) | The handoff uses a clearing buffer before the backend writes. A backend error produces a typed authentication failure even after the backend has overwritten the buffer. A successful authentication returns the backend's output in `P256BasePlaintext`. | Arbitrary four-byte records and backend output, with success and failure checked for reachability. Existing tests exercise the actual AES-128-GCM backend, including changed tags and maximum-sized records. The proof models the backend outcome and does not measure memory erasure. |

[Formal Verification](../.github/workflows/formal-verification.yml) runs these
proofs for changes to the covered crates, dependencies, and verifier workflow.
Kani 0.68.0 supplies the compiler used for verification. From the repository root:

```sh
cargo install --locked kani-verifier@0.68.0
cargo kani setup
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-proto --features generated
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
| AEAD failure and secret ownership | Extend the plaintext handoff proof beyond the HPKE Base P-256 profile. Verify ownership transfers at selected Rust and FFI boundaries and review the zeroization obligations of each owner. Physical erasure and side-channel behavior require separate evidence. |
| Encoding and primitive equivalence | Start with ML-KEM coefficient encoding and decoding, strict ECDSA low-S handling, and X25519/X448 input and shared-secret checks. Use an independent Cryptol specification and SAW where a small fixed-size implementation can be connected reproducibly to the verified artifact. AES-KW, Keccak, and hybrid KEM composition are candidates after that integration is established. |
