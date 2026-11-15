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
| [Mixed native and reduced WASM provider profiles](../crates/crypto/dispatch/src/provider/profile_proof_tests.rs) | Each policy admits only the reviewed operation and algorithm pairs. The mixed native build routes signing and decapsulation to their respective providers and prevents cross-family calls. The WASM profile rejects secp256k1 public-key reconstruction and does not use WASM implementations on a native target. | All recognized operation and algorithm pairs in the ML-DSA-65/ML-KEM-768 native profile and the secp256k1/ML-KEM-768 WASM profile. Kani checks the WASM policy on the host. [Integration tests](../crates/crypto/dispatch/tests/feature_lane_tests.rs) run the reduced profile on `wasm32`. |
| [HPKE component dispatch](../crates/hpke/src/dispatch.rs) | Unknown IDs return the typed unsupported-algorithm error. A registered ID routes to the implementation with the same ID if enabled and returns that error otherwise. Export-only AEAD is rejected by encryption dispatch. | All 65,536 numeric inputs in each of the KEM, KDF, and AEAD families, under the full native profile and a restricted P-256 profile with export-only enabled. The callbacks read the actual implementation types' associated IDs. The proofs compare dispatch with the registry and the build's declared support, and do not execute the implementations or exercise SDK provider routing. |
| [HPKE backend nonce and sequence state](hpke/aead_state_proof_tests.rs) | Each supported record AEAD derives the nonce prescribed by [RFC 9180 §5.2](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2). Distinct sequences produce distinct nonces for the same base nonce. Authentication failure preserves the receiver sequence and nonce for a valid retry. A successful call at the backend's last sequence exhausts the context. Further calls return `MessageLimitReached` before invoking the AEAD, preserve the output buffer and leave exhaustion set. | All 64-bit sequence values and all 96-bit base nonces. Nonce proofs instantiate the real AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 types. State proofs run the locked backend's detached seal/open methods with a test AEAD that writes before reporting success or failure. The retry harness covers a record sealed at any earlier or later sequence, followed by the expected record, including a retry at `u64::MAX`. The test AEAD treats nonce binding as exact. |
| [Public HPKE PSK record open](../crates/hpke/src/setup_receiver_proof_tests.rs) | A nonce mismatch returns only the typed authentication error, even after a complete candidate-plaintext write. The backend sequence proof establishes the nonce mismatch and retry behavior for records at earlier and later sequences. | Uses the public receiver, the production record adapter and staging buffer, and the locked backend. At sequence zero, the symbolic base nonce spans every possible expected nonce. The harness covers all four-byte ciphertext bodies and 16-byte tags with a mismatched nonce in the AEAD model. Setup and cipher internals are outside this proof. |
| [AEAD plaintext handoff](../crates/crypto/core/src/authenticate_record.rs) | The shared open path splits the tag and gives the backend a mutable slice of a clearing buffer. Authentication failure cannot return that buffer, even if the backend has written candidate plaintext. Records with truncated tags never call the backend. | All four-byte ciphertexts, 16-byte tags, candidate output bytes, and subsets of output bytes written. The harness checks reachability of success and failure after both partial and complete writes. AES-128/192/256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305, and HPKE Base and PSK opens use this handoff. The proof assumes the backend reports authentication correctly. It covers Rust ownership and release, while cipher internals and physical erasure require separate evidence. |
| [AEAD staging ownership](../crates/crypto/core/src/authenticate_record/proof_tests.rs) | Authentication failure sends the original staging allocation to the zeroizing destructor exactly once before returning. Success transfers the same allocation inside a `ZeroizeOnDrop` owner. | All four-byte ciphertext bodies, 16-byte tags, and complete candidate writes. The harness observes ownership at the discard call and runs the destructor. It checks cleanup routing and allocation identity. Physical erasure is outside the model. |
| [C ABI AEAD output handoff](../crates/ffi/src/aead_proof_tests.rs) | The six scalar AEAD decrypt exports and both HPKE Base suites return `RM_CRYPTO_AUTHENTICATION_FAILED` with the caller's entire output buffer and length unchanged, including after a partial or complete backend write. | All four-byte ciphertexts with 16-byte tags, valid disjoint pointers, arbitrary six-byte initial output buffers, and all initial `size_t` values. The harnesses use the exported functions and real status mapping. They model normal return from the panic guard, successful overlap checks, and the error handoff from the separately verified Rust staging helper. Native tests exercise success and authentication failure against real ciphers with the full guard and overlap checks. |
| [C ABI range validation](../crates/ffi/src/pointer_range_proof_tests.rs) | The guards reject nonempty null, oversized and wrapping extents. They accept exactly valid disjoint ranges, including adjacent or empty ranges. | All native-width address and length values. The oracle measures distance between start addresses. The proof covers arithmetic and overlap. Callers supply allocation provenance, initialization and lifetimes. Native tests exercise the per-call range registry and write boundaries. |
| [Kotlin JNI AEAD handoff](../crates/ffi/src/kotlin_aead.rs) | An authentication error passes the typed failure status and an empty payload to the JNI result encoder, even when the provider has written bytes and supplied a plausible length. Success requires the expected output length. | All four-byte staging buffers and all produced length values. The harness observes the inputs to the JNI encoder. JVM tests inspect the actual status-only envelope for each JNI-backed AEAD and check that the decoder clears unexpected bytes on failure. |
| [WASM plaintext handoff](../crates/wasm/src/publish_plaintext.rs) | Authentication failure propagates the typed error without invoking the JavaScript array copy. | All four-byte ciphertexts, 16-byte tags, candidate output bytes, and subsets of backend writes. The harness uses the production Rust staging and release helpers. The scalar WASM AEAD and HPKE Base exports share the release helper. The JS host receives a numeric status on failure. |
| [ML-KEM 12-bit polynomial encoding](hpke/ml_kem_encoding_proof_tests.rs) | The locked encoder packs 12-bit coefficients in FIPS 203 bit order. The decoder recovers the packed coefficients and reduces each modulo 3329, including noncanonical representations. | Every canonical pair of coefficients and every three-byte encoded chunk. The proof runner restricts the locked loops to one complete chunk and preserves their bodies, including the portable conditional reduction. The NIST vector runs exercise the unmodified full-polynomial implementation. |
| [Strict P-256](../crates/p256/src/native/verify_digest.rs) and [secp256k1 ECDSA](../crates/secp256k1/src/native/verify.rs) | The strict parser accepts exactly the nonzero low-S scalar range and emits the typed invalid-signature error outside that range. | All 256-bit S values with the independently valid scalar `r = 1` at the fixed-width parser, using the portable conditional-move implementation. DER decoding and signature verification use the existing conformance suites. |
| [P-256 JOSE normalization](../crates/p256/src/normalize_signature.rs) | The production normalizer preserves R and maps valid S to the smaller of S and the subgroup order minus S. The result is canonical and normalizing it again yields the same bytes. | All 256-bit S values with `r = 1`. The independent arithmetic oracle uses a two-word subtraction. The proof checks scalar normalization and the typed error for invalid S. |
| [X25519](../crates/x25519/src/native/derive.rs) and [X448](../crates/x448/src/agreement.rs) | Wrong-length key inputs are rejected. The output gates return only contributory X25519 and nonzero X448 shared secrets. | X25519 key lengths through 33 bytes and X448 key lengths through 57 bytes. The X25519 release proof spans every backend byte array and contribution flag, and the [locked backend harness](hpke/x25519_contributory_proof_tests.rs) checks the flag on canonical outputs. The [X448 import proof](../crates/x448/src/material.rs) checks canonical public coordinates against the low-order values 0, 1, and −1. These harnesses cover key admission and release after scalar multiplication. |
| [AES-KW lengths and key release](../crates/aes-kw/src/unwrap_key/proof_tests.rs) | Only accepted RFC 3394 semiblock lengths reach unwrap. Integrity failure reports a typed authentication error and releases no candidate key. Success transfers the original zeroizing allocation. | All native-width lengths at the shared validators, malformed wrapped inputs through 32 bytes, and all subsets of writes to 16 bytes of candidate key data. AES-128/192/256-KW share the wrapper. |
| [Locked AES-KW block schedule](hpke/aes_kw_schedule_proof_tests.rs) | The dependency presents the RFC 3394 inputs to the block cipher in the prescribed order, uses the big-endian round counter, and clears its buffer on integrity failure. | Two data semiblocks, arbitrary wrap and unwrap inputs, and arbitrary cipher returns at each of the 12 calls. Real AES is covered by the RFC and conformance tests. |
| [Portable Keccak round](hpke/keccak_round_proof_tests.rs) | The locked software backend's Keccak-p[1600, 1] matches the FIPS 202 coordinate specification. Its entire 24-constant table matches the FIPS LFSR. | Every 1600-bit input state for the final round. The lockfile selects the dependency used by the SHA3-256 wrapper. Existing digest and XOF vectors exercise the full permutation and sponge. |

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
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-core -Z stubbing
CARGO_NET_OFFLINE=true cargo kani -p crypto-ffi --lib -Z stubbing --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-wasm --lib --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features native
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm,aead-export-only
python3 formal/hpke/verify.py
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,wasm,secp256k1,ml-kem-768 --lib
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-dispatch --no-default-features --features proto,native,ml-dsa-65,ml-kem-768 --lib -Z stubbing
RUSTFLAGS="--cfg miri" python3 -B formal/hpke/verify.py module-lattice
RUSTFLAGS="--cfg miri" CARGO_NET_OFFLINE=true CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo kani -p reallyme-crypto-p256 -p reallyme-crypto-secp256k1 --no-default-features --features native --lib
python3 -B formal/hpke/verify.py x25519-dalek
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-x25519 -p reallyme-crypto-x448 --no-default-features --features native --lib -Z stubbing
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-aes-kw --no-default-features --features native --lib
python3 -B formal/hpke/verify.py aes-kw
python3 -B formal/hpke/verify.py keccak
git diff --exit-code -- Cargo.lock
```

The operation-response command uses release-style dependency assertions to
keep generated-message verification tractable. Kani still checks arithmetic,
memory safety, loop bounds, and the harness assertions.

The locked package runner requires Python 3.12 or later. It checks the crates.io
archive against the workspace lockfile, resolves dependencies offline against
that lockfile, and appends the harness in a temporary directory to access
private state. Each verification build uses an isolated target directory and
enables only the features used by its harnesses. The `miri` configuration
selects the dependency's portable conditional moves for functional
verification with Kani.

The [reference DER encoder proofs](../docs/external-conformance-vectors.md#formal-methods-candidates)
run separately in the External Vector Audit workflow.

## Time limits and incomplete proofs

Formal Verification gives each Kani category its own 30-minute job with up to
two harnesses in parallel and a 15-minute limit per harness. The workflow
retains the original Kani status check and requires every matrix job to
succeed. A timeout fails the category. The independent vector job has a
10-minute execution limit. The Tamarin proof step has eight minutes in a
12-minute job and requires a verified verdict for every expected lemma.
The reference encoder job has a 20-minute limit and a 10-minute limit per
harness.

In concurrent local runs, the locked X25519 contribution proof took about
9 minutes 39 seconds and the X448 canonical import harness took about 9
minutes 27 seconds. The PQ Tamarin model took about 2 minutes 39 seconds.
These are local observations. The first hosted runs will establish CI
baselines. To investigate a Kani timeout, run the named harness separately
with `--harness` and a measured time limit. Record the target, feature set,
verifier version, and elapsed time with any budget change.

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

The [HPKE model](tamarin/hpke.spthy) covers single-record Base and PSK modes.
When a modeled ciphertext opens successfully, sealing and opening agree on
suite, recipient public key, mode, encapsulation, `info`, AAD, PSK identifier,
and plaintext. The model provisions two distinct identifiers for one PSK and
verifies reachability of the alternate identifier. This exercises identifier
binding while holding the PSK bytes fixed.

HPKE exports immediately after setup. In the model a matching sender and
receiver export binds the setup inputs, including `info` and the PSK identifier,
the separate `exporter_context`, and the requested output length. Base and PSK
round-trip and export witnesses establish reachability. Plaintext secrecy
continues to hold under ideal DH, labeled derivation, and authenticated
encryption. Export equality is symbolic and assumes ideal derivation. The
model abstracts byte encodings, concrete cipher properties, multi-record state,
and sender authentication in Base mode. [RFC 9180 §§5.1–5.3][RFC9180].

The [backend schedule audit](hpke/check_schedule_vectors.py) verifies the
registry archive against `Cargo.lock` and the independent CFRG corpus against
[its recorded checksum](../vectors/external/provenance.json). In a temporary
copy it observes the production receiver's KEM shared secret, key-schedule
context, extraction secret, traffic key, base nonce, and exporter secret.
Twelve vectors cover Base and PSK across five record suites plus X25519
export-only. Each checks three exporter outputs. The export-only vectors
omit the record nonce, so that comparison applies to the five record suites.
The observer compares bytes in place and reports only the field name on failure.

The [public HPKE audit](../tools/external-vector-audit/tests/rfc9180_hpke.rs)
checks Base sender and receiver export bytes, including three distinct exporter
contexts and a test that changing the requested length changes the output
prefix. Open tests use ten sequence-zero records and require typed
authentication failure for fifty-five one-input substitutions, including five
PSK identifier changes that retain the original PSK and ciphertext.

## HPKE record sequences

The backend audit checks 2,720 consecutive records across 25 encrypting rows.
Each of the ten RFC 9180 Base and PSK rows runs through sequence 256. Each of
the five PQ Base rows and ten PQ PSK rows runs through sequence 9. One sender
and receiver stay live for each row. The audit compares the reference nonce
bytes with the values passed to the AEAD, reproduces each
ciphertext with deterministic sender setup, and recovers the expected
plaintext. Before opening each original record, the receiver rejects that
record with one flipped tag bit and uses the same expected nonce for the retry.

The public RFC audit runs all 1,285 PSK records through the typed sender and
receiver contexts. It checks the ciphertext and requires typed authentication
errors for a bad tag, a replay of the previous record, and either of the next
two records presented early. The 3,835 ordering checks keep the misplaced
records' ciphertext and AAD intact. After the rejections, the original record
still opens at its expected sequence.

The RFC audit also establishes two PSK contexts per suite with distinct
published encapsulation inputs and the same recipient, PSK, PSK identifier,
and `info`. Both senders seal the same plaintext with the same AAD at each
sequence through 256. The audit reproduces the published PSK ciphertexts
and requires a typed authentication error when either context's record is
offered to the other receiver. Both receivers then open their own records.

## Post-quantum HPKE

The same backend audit checks five Base-mode rows from the pinned [IETF PQ HPKE
draft-05 corpus][PQHPKE]. The suites cover ML-KEM-512, ML-KEM-768, ML-KEM-1024,
and X-Wing with HKDF-SHA256 and SHAKE256. The audit checks the KEM shared secret,
traffic key, base nonce, exporter secret, and all five published exports per
suite. The PQ corpus supplies no expected schedule-context or extraction-secret
bytes. The ML-KEM-512 audit compiles the workspace's KEM adapter in the same
temporary build as the locked backend.

The [public PQ audit](../tools/external-vector-audit/tests/hpke_pq.rs) reproduces
each encapsulation and sequence-zero record, opens the record, and checks all
five export outputs from each side. Changing only the ML-KEM ciphertext leaves
receiver export available with different bytes and makes the unchanged record
return a typed authentication error. Both X-Wing schedules have the same check
with the X25519 component set to zero. A truncated encapsulation returns the
typed malformed-ciphertext error before receiver export or open can succeed.

The backend audit compares actual KEM rejection bytes with
[FIPS 203 Algorithm 18][FIPS203]. The independent SHAKE256 calculation
matches 15 NIST ACVP modified-ciphertext rows and differs from the known
shared secrets of 15 valid controls. The locked ML-KEM implementation also
matches the expected bytes for all 30 NIST cases from the expanded test keys.
The HPKE KEMs match the independent rejection calculation for two same-length
substitutions per ML-KEM size. For both X-Wing rows, the
audit changes only ML-KEM bytes. OpenSSL derives the independent X25519
contribution and the [X-Wing combiner specification][XWING] supplies the
expected final bytes. The genuine encapsulations remain positive controls.

The [PSK corpus](../vectors/external/hpke/hpke_pq_draft05_psk_test_vectors.json)
adds two encapsulations for each of those five suites. A test driver builds
the pinned [IETF reference implementation][PQREFERENCE] with its own lockfile.
It reuses the published recipient and record inputs, derives a deterministic
second encapsulation input, and computes both PSK schedules and record streams
in that implementation. The driver checks the matching published Base row
before generating each pair and opens both PSK streams with the reference
receiver. The backend audit checks the generated shared secrets, traffic keys,
base nonces, exporter secrets, 100 records, and 50 export outputs.

The public PSK audit reproduces both ciphertext streams and swaps the intact
records at each sequence with the original AAD. In all 100 cross-context opens,
the other receiver must return the typed authentication error. Each receiver
then opens its own record at the same sequence. The reference implementation
supports PSK mode and the draft's Appendix A publishes the Base vectors.

All ten PSK rows also use their original sequence-zero record to check
`info` and PSK identifier binding. Each test changes one bit in one field
and keeps the PSK bytes, encapsulation, and AAD fixed. Both substitutions
complete setup and return the typed authentication error at open.

The [PQ Tamarin model](tamarin/hpke_pq.spthy) treats a structurally valid but
rejected ML-KEM ciphertext as deriving a fallback secret. For X-Wing, this
secret becomes the ML-KEM input to the combiner. The model gives the adversary
the X25519 contribution, covering even the non-contributory case. Malformed
encapsulations establish no context. A correctly sized input that triggers
implicit rejection establishes a context that can export and cannot
authenticate a record, even when the PSK has been disclosed.

The model covers Base and PSK mode at sequence zero. For the same sealed
record, recipient, suite, encapsulation, and AAD, successful PSK open binds
`info` and the PSK identifier. Two identifiers can select the same PSK bytes.
For a fixed rejected encapsulation, changing either field changes the
candidate record key. Witness traces exercise both substitutions and show
that the original record is rejected after fallback. Successful X-Wing
open also binds the full encapsulation for the same recipient. The model
assumes an uncompromised recipient and ideal primitives. It abstracts
byte-level validity checks, rejection timing, and the computational
security of the combiner.

The formal verification workflow uses Tamarin 1.12.0 and Maude 3.5.1. Run with
both tools and OpenSSL on `PATH` and the locked Rust dependencies cached.

```sh
bash formal/tamarin/verify.sh
python3 -B formal/hpke/check_schedule_vectors.py
cargo test --locked -p external-vector-audit --no-default-features --features native --test rfc9180_hpke --test hpke_pq -- --ignored
```

The symbolic verifier requires all nine classical and fifteen PQ lemmas to be present and verified.

[RFC9180]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
[PQHPKE]: https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#appendix-A
[PQREFERENCE]: https://github.com/hpkewg/hpke-pq/tree/6433c8fce0b8b749dfc86c1095081a88698ccfab/reference-implementation
[FIPS203]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
[XWING]: https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10#section-5.3

## Further verification

Kani covers Rust implementation boundaries and selected primitive logic.
Tamarin covers symbolic protocol behavior. Independent vectors connect
those checks to the concrete provider implementations. Further work on
Keccak's full permutation, AES-KW at larger lengths, Montgomery ladder
arithmetic, and concrete hybrid KEM security would require separate
equivalence or security arguments. Cryptol and SAW are candidates for
primitive equivalence once the pinned release artifact can be exported
reproducibly to a supported format. Miri can complement the FFI proofs by
executing targeted Rust tests with provenance checks. Architecture-specific
timing and physical memory erasure require their own evidence.
