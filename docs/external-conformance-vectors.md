# External Conformance Vectors

ReallyMe Crypto vendors selected third-party conformance vectors under
[vectors/external](../vectors/external). These vectors are audit evidence for
the public primitive boundaries; they do not replace the repository's
cross-language vectors in [vectors](../vectors).

The two external sources are intentionally tested separately:

- [NIST ACVP](https://pages.nist.gov/ACVP/) vectors are compliance-oriented
  known-answer tests for algorithms with matching public ReallyMe boundaries.
- [CCTV](https://c2sp.org/CCTV) vectors are adversarial and edge-case suites
  for the subset of algorithms covered by the C2SP CCTV project.

Raw upstream files stay intact. Provenance, source URLs, pinned commits,
retrieval dates, license notes, and SHA-256 hashes are recorded in
[vectors/external/provenance.json](../vectors/external/provenance.json).
Executable adapters live in separate files under
[tools/external-vector-audit/tests](../tools/external-vector-audit/tests).

### Reference encoder independence

Some adapters must turn raw upstream fields (ECDSA `r`/`s`, SEC1 `qx`/`qy`, RSA
`n`/`e`) into DER or SEC1 byte forms before handing them to the public
primitives. That encoding is done by the **intentionally independent** reference
encoder in [tools/external-vector-audit/src/refenc.rs](../tools/external-vector-audit/src/refenc.rs),
which deliberately does **not** reuse the production encoders: an oracle that
shared the library's own encoder could not detect a bug in it, because both
sides would agree on the same wrong bytes. The reference encoder's edge cases
(DER minimal-integer form, the `0x80` high-bit sign prefix, multi-byte length
prefixes) are pinned by unit tests and by bounded `#[cfg(kani)]` proofs in that
same module.

## NIST ACVP Coverage

| Algorithm family | ACVP status |
|---|---|
| AES-GCM | Covered by [AES-GCM ACVP](../vectors/external/nist-acvp/aead/aes-gcm/internalProjection.json). |
| AES-GCM-SIV | Vendored [ACVP sample](../vectors/external/nist-acvp/aead/aes-gcm-siv/internalProjection.json) is status-only because the pinned sample is AES-128-GCM-SIV while ReallyMe exposes AES-256-GCM-SIV. |
| AES-KW | Covered by [AES-KW ACVP](../vectors/external/nist-acvp/key-wrap/aes-kw/internalProjection.json). |
| ChaCha20-Poly1305 and XChaCha20-Poly1305 | No current vendored ACVP route. |
| SHA-2 | Covered by [SHA2-256](../vectors/external/nist-acvp/hash/sha2-256/internalProjection.json), [SHA2-384](../vectors/external/nist-acvp/hash/sha2-384/internalProjection.json), and [SHA2-512](../vectors/external/nist-acvp/hash/sha2-512/internalProjection.json). |
| SHA-3 and SHAKE | Covered by [SHA3-224](../vectors/external/nist-acvp/hash/sha3-224/internalProjection.json), [SHA3-256](../vectors/external/nist-acvp/hash/sha3-256/internalProjection.json), [SHA3-384](../vectors/external/nist-acvp/hash/sha3-384/internalProjection.json), [SHA3-512](../vectors/external/nist-acvp/hash/sha3-512/internalProjection.json), and [SHAKE-256](../vectors/external/nist-acvp/hash/shake-256/internalProjection.json). |
| HMAC-SHA2 | Covered by [HMAC-SHA2 ACVP](../vectors/external/nist-acvp/mac). HMAC-SHA3 is vendored but status-only because ReallyMe's public MAC surface currently exposes HMAC-SHA2. |
| HKDF | Covered where [KDA-HKDF ACVP](../vectors/external/nist-acvp/kdf/hkdf-sp800-56cr2/internalProjection.json) maps to raw HKDF-SHA2-256/384. |
| KMAC256 KDF | Vendored [KMAC256 ACVP](../vectors/external/nist-acvp/mac/kmac-256/internalProjection.json) is status-only because the current sample has no byte-aligned non-XOF cases for the public boundary. |
| PBKDF2-HMAC-SHA2 | Vendored [PBKDF ACVP](../vectors/external/nist-acvp/kdf/pbkdf/internalProjection.json) is status-only because the current sample uses SHA2-224 rather than the public SHA2-256/SHA2-512 profiles. |
| JWA Concat KDF | Vendored [ANSI X9.63 ACVP](../vectors/external/nist-acvp/kdf/ansix963/internalProjection.json) is status-only because ReallyMe exposes the JOSE/JWA Concat KDF profile rather than raw `sharedInfo`. |
| Argon2id | No NIST ACVP suite for this public boundary. |
| Ed25519 | Covered by [EdDSA ACVP signature verification](../vectors/external/nist-acvp/signature/eddsa-sigver/internalProjection.json). |
| ECDSA P-256/P-384/P-521 | Covered by [ECDSA ACVP signature verification](../vectors/external/nist-acvp/signature). |
| secp256k1 ECDSA and BIP-340 Schnorr | No current vendored ACVP route for these public boundaries. |
| RSA verification | Covered by [RSA PKCS#1 v1.5/SHA-256 ACVP signature verification](../vectors/external/nist-acvp/signature/rsa-sigver/internalProjection.json). RSA-PSS samples are status-only for currently unsupported hash/profile combinations. |
| ML-DSA-44/65/87 | Covered by [ML-DSA ACVP keygen](../vectors/external/nist-acvp/ml-dsa/keygen/internalProjection.json) and the public-boundary subset of [ML-DSA ACVP signature verification](../vectors/external/nist-acvp/ml-dsa/sigver/internalProjection.json). |
| SLH-DSA-SHA2-128s | Vendored [SLH-DSA ACVP signature verification](../vectors/external/nist-acvp/slh-dsa/sigver/internalProjection.json) checks public-boundary rejections and independent positive known answers at the backend's internal FIPS 205 interface. The pinned sample has no positive empty-context external case, so these backend checks do not establish positive public-boundary conformance. |
| X25519 | Covered by [X25519 ACVP shared-secret computation](../vectors/external/nist-acvp/agreement/xecdh-ssc/internalProjection.json). |
| X448 and P-curve ECDH | No current vendored ACVP route for these public boundaries. |
| ML-KEM-512/768/1024 | Covered by [ML-KEM ACVP keygen](../vectors/external/nist-acvp/ml-kem/keygen/internalProjection.json) and [encapsulation](../vectors/external/nist-acvp/ml-kem/encap-decap/internalProjection.json). |
| X-Wing-768 and HPKE | No current vendored ACVP route for these public protocol boundaries. |
| Key and wire envelopes | Not ACVP algorithm suites. |

## CCTV Coverage

The CCTV table is organized by upstream suite instead of by every ReallyMe
algorithm. A CCTV suite is imported as executable evidence only when it maps to
a public ReallyMe primitive boundary without adding a new audit-only key,
protocol, or internal-math API.

| CCTV suite | ReallyMe applicability | Status |
|---|---|---|
| [Ed25519](../vectors/external/cctv/ed25519/ed25519vectors.json) | Applies to the Ed25519 signature-verification boundary. | Executed by default for strict-verification edge cases. |
| [RFC6979](../vectors/external/cctv/rfc6979/README.md) | Applies to deterministic P-256 ECDSA signing. | Executed by default for rejection-sampling coverage. The vendored CCTV corpus does not provide equivalent P-384 or P-521 suites. |
| [ML-DSA accumulated](../vectors/external/cctv/ml-dsa/accumulated/README.md) | Applies to ML-DSA-44/65/87 through public sign/verify and accumulated-hash boundaries. | Executes 100-iteration hashes by default. Ignored 10,000-iteration hashes run only through the deliberate deep-audit command. |
| [ML-DSA benchmark](../vectors/external/cctv/ml-dsa/benchmark) | Applies to ML-DSA-44/65/87 public sign/verify routes. | Executed by default for benchmark-message sign/verify checks. |
| [ML-KEM modulus](../vectors/external/cctv/ml-kem/modulus) | Applies to ML-KEM-512/768/1024 encapsulation-key validation. | Executes a representative invalid-key subset by default. The full corpus is ignored and reserved for the deliberate deep-audit command. |
| [ML-KEM unlucky sample](../vectors/external/cctv/ml-kem/unluckysample) | Partially applicable shape-wise, but the pinned vectors do not match the final-FIPS public deterministic backend output. | Status-only. The adapter verifies that the raw upstream fields remain present for final-FIPS review. |
| [ML-KEM strcmp](../vectors/external/cctv/ml-kem/strcmp) | Not currently executable because it requires full decapsulation-key encodings that ReallyMe does not expose at the public ML-KEM boundary. | Status-only. |
| [ML-KEM accumulated hashes](../vectors/external/cctv/ml-kem/README.md) | Not currently executable because the CCTV accumulated process requires full decapsulation-key encodings and decapsulation outputs that ReallyMe does not expose at the public ML-KEM boundary. | Status-only. |
| [ML-KEM intermediate](../vectors/external/cctv/ml-kem/intermediate) | Not currently executable because it traces internal polynomial and transform operations that are intentionally outside the public API. | Status-only. |
| [RSA keygen](../vectors/external/cctv/keygen/README.md) | Not applicable to the current RSA boundary because ReallyMe exposes signature verification, not deterministic candidate-fed RSA key generation. | Status-only. |
| [age file encryption][cctv-age] | Not applicable to the current public primitive API because it is an age protocol/file-format suite, not raw X25519 or AEAD conformance. | Not vendored after applicability review. |
| [cocktail-dkg][cctv-cocktail-dkg] | Not applicable to the current public primitive API because it is a distributed key-generation protocol suite, not standalone Ed25519, ECDSA, or Schnorr conformance. | Not vendored. |
| [jq255][cctv-jq255] | Not applicable because ReallyMe does not expose jq255e or jq255s. | Not vendored. |

[cctv-age]: https://github.com/C2SP/CCTV/tree/1e3d2860d46e94e777e1b17c7a6f2436387e3ecc/age
[cctv-cocktail-dkg]: https://github.com/C2SP/CCTV/tree/1e3d2860d46e94e777e1b17c7a6f2436387e3ecc/cocktail-dkg
[cctv-jq255]: https://github.com/C2SP/CCTV/tree/1e3d2860d46e94e777e1b17c7a6f2436387e3ecc/jq255

## Wycheproof and Supplementary Coverage

The Google/C2SP [Wycheproof](https://github.com/C2SP/wycheproof) project is the
highest-value adversarial source for the primitives ACVP compliance vectors
under-exercise (malleability, non-canonical encodings, low-order points). The
following public corpora are vendored through
[scripts/vendor_external_vectors.mjs](../scripts/vendor_external_vectors.mjs)
(see [Vendoring supplementary corpora](#vendoring-supplementary-corpora)) and
executed by dedicated adapters. These adapters are `#[ignore]` and fail closed
when their corpus has not been vendored, so they never pass vacuously.

| Corpus | ReallyMe boundary | Adapter |
|---|---|---|
| Wycheproof ChaCha20-Poly1305 | AEAD seal/open (the primary AEAD that had no external KAT) | [wycheproof_chacha20_poly1305.rs](../tools/external-vector-audit/tests/wycheproof_chacha20_poly1305.rs) |
| Wycheproof secp256k1 ECDSA (SHA-256) | `verify_secp256k1` (ACVP does not cover secp256k1) | [wycheproof_ecdsa_secp256k1.rs](../tools/external-vector-audit/tests/wycheproof_ecdsa_secp256k1.rs) |
| Wycheproof X25519 | `derive_x25519_shared_secret` adversarial edge cases | [wycheproof_xdh_x25519.rs](../tools/external-vector-audit/tests/wycheproof_xdh_x25519.rs) |
| Wycheproof X448 | `derive_x448_shared_secret` (previously no external route) | [wycheproof_xdh_x448.rs](../tools/external-vector-audit/tests/wycheproof_xdh_x448.rs) |
| Wycheproof P-256/384/521 ECDH (`ecpoint`) | `derive_p{256,384,521}_shared_secret` | [wycheproof_ecdh_pcurves.rs](../tools/external-vector-audit/tests/wycheproof_ecdh_pcurves.rs) |
| BIP-340 `test-vectors.csv` | `verify_bip340_schnorr` positive and negative cases for the 32-byte message API; four variable-length extension rows must be rejected | [bip340_schnorr.rs](../tools/external-vector-audit/tests/bip340_schnorr.rs) |
| RFC 8032 `sign.input` | `sign_ed25519` deterministic **signature generation** | [rfc8032_ed25519_siggen.rs](../tools/external-vector-audit/tests/rfc8032_ed25519_siggen.rs) |
| X-Wing CFRG draft `spec/test-vectors.json` | `generate_x_wing_768_keypair_derand` / `x_wing_768_encapsulate_derand` / `x_wing_768_decapsulate` full KAT | [xwing768_kat.rs](../tools/external-vector-audit/tests/xwing768_kat.rs) |
| HPKE RFC 9180 `test-vectors.json` | Base seal and export, Base and PSK opens, and typed rejection of suite, recipient key, `info`, AAD, and PSK identifier substitutions. The [backend schedule audit](../formal/hpke/check_schedule_vectors.py) also compares intermediate and exporter bytes | [rfc9180_hpke.rs](../tools/external-vector-audit/tests/rfc9180_hpke.rs) |
| [IETF PQ HPKE draft-05](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#appendix-A) | ML-KEM-512/768/1024 and X-Wing Base seal, open, sender and receiver exports, and typed rejection of truncated and same-length substituted encapsulations. The backend audit compares the published intermediate schedule bytes | [hpke_pq.rs](../tools/external-vector-audit/tests/hpke_pq.rs) |
| [PQ HPKE PSK reference fixtures](../vectors/external/hpke/hpke_pq_draft05_psk_test_vectors.json) | Paired ML-KEM-512/768/1024 and X-Wing PSK contexts reproduce both ciphertext streams, reject records from the other context, and open their own records at the same sequence. All ten rows reject one-input substitutions of the PSK identifier or `info`. The backend audit checks schedule and exporter bytes | [hpke_pq.rs](../tools/external-vector-audit/tests/hpke_pq.rs) |
| PBKDF2 RFC 6070-derived (brycx corpus) | `derive_key` for both public PRFs (SHA-256, SHA-512) | [pbkdf2_rfc6070.rs](../tools/external-vector-audit/tests/pbkdf2_rfc6070.rs) |

**Argon2id** has no executable external route: the public boundary derives only
through code-pinned cost profiles (`DeriveKeyRequest` takes a profile, not
arbitrary `m`/`t`/`p`), so the RFC 9106 vectors — which fix their own small
parameters — cannot be reproduced against it. The pinned backend is checked
against the independent RFC 9106 section 5.3 Argon2id known answer in the
Argon2id primitive tests; the fixed public profile remains status-only.
The NIST ACVP PBKDF sample is likewise status-only (SHA-224 only); the brycx
corpus above is the executable PBKDF2 route for the SHA-256/SHA-512 boundary.

Wycheproof `acceptable` cases (legal-but-discouraged, e.g. malleable or
non-canonical) are skipped rather than asserted in a fixed direction, since a
hardened implementation may legitimately accept or reject them.

Several adapters encode a **deliberate ReallyMe policy** so a documented
difference reads as a positive check rather than a spurious mismatch: the
secp256k1 ECDSA adapter expects high-S "valid" signatures to be rejected
(low-S / BIP-62); the P-curve ECDH adapter expects an all-zero shared secret to
be rejected and normalizes Wycheproof's variable-width private scalar to the
fixed field width. Running the adapters against the real corpora is what
surfaces these divergences — each was found by a first-run failure, not by
inspection.

The Ed25519 adapter closes a specific gap: ACVP EdDSA only covers verification,
but Ed25519 signing is deterministic, so a broken nonce/hash path can still
verify while producing a wrong signature. Asserting the produced signature bytes
against a known answer catches that class of bug.

The single-shot HPKE adapters exercise sequence-zero open and seal, Base-mode
export, and RFC 9180 PSK open. The RFC adapter also runs later records through
the public PSK contexts and checks retry after a bad tag, duplicate delivery,
early delivery, or a record from a second context with the same PSK. The locked
backend audit uses evolving sender and receiver contexts to compare every published
record nonce through sequence 256 for the selected RFC rows and sequence 9
for the selected draft-05 rows. See the [record sequence checks](../formal/README.md#hpke-record-sequences).

## Formal Methods Candidates

External vectors prove behavior for selected public inputs and adversarial
cases; they do not prove the full implementation. Formal work complements ACVP
and CCTV where no external suite exists, where a suite is status-only because it
targets internals, or where a small fixed-size component is easier to specify
exhaustively than to cover with examples.

**Kani (adopted first).** The reference DER encoder in
[refenc.rs](../tools/external-vector-audit/src/refenc.rs) carries bounded
`#[cfg(kani)]` proofs of its length-prefix round-tripping and minimal-integer /
sign-prefix rules. Kani was adopted first because it is Rust-native (no separate
specification language), proves the "no panic" and round-trip invariants
directly, and gates cleanly in the audit workflow. It runs only in the
[External Vector Audit](../.github/workflows/external-vectors-audit.yml)
workflow. The [formal verification inventory](../formal/README.md) covers
production Rust proofs and the symbolic HPKE model.

**Cryptol + SAW (deferred).** Broader equivalence work could compare a
fixed-size production function to an independent Cryptol specification
after validating release artifact export for the pinned Rust toolchain.
The [formal verification inventory](../formal/README.md) records the
existing Kani equivalence scopes for AES-KW block scheduling, a portable
Keccak round, and 12-bit ML-KEM coefficient packing.

## CI Gating

The committed corpora have different validation costs. Practical adapters run
with the normal code checks; larger exhaustive sweeps run separately:

| Check | Where it runs |
|---|---|
| Executable default adapters (`acvp_*`, `cctv_*` non-ignored) | Every PR, via `cargo nextest run --workspace` in [rust-ci.yml](../.github/workflows/rust-ci.yml). |
| Provenance structure, completeness, and commit-pinning (`external_vector_provenance_declares_sources`, `every_external_corpus_file_has_provenance`, `external_vector_urls_are_pinned_to_commits`, `external_vector_coverage_tracks_supported_families`) | Every PR, via the workspace test run. The completeness check also runs in the vector-specific integrity job. |
| Committed corpus hashes and CCTV markers | Vector integrity checks. |
| Re-download and byte-for-byte comparison of the upstream corpora, and byte-for-byte regeneration of the derived HPKE PSK corpus | Vector changes and the scheduled integrity check. |
| Wycheproof / BIP-340 / RFC 8032 / X-Wing / HPKE / PBKDF2 adapters | Normal code checks against the committed corpora. |
| Exhaustive ACVP/CCTV sweeps and bounded reference DER encoder proofs | Separate scheduled or explicitly requested checks. |

The pinned SHA-256 provenance check is what turns the manifest from
documentation into an enforced invariant: it is cheap enough to run on every
vector-touching PR, so a corrupted, drifted, or tampered vendored file is caught
without waiting for a manual audit.

### Vendoring supplementary corpora

The supplementary corpora are committed with reviewed upstream commit IDs.
The [vendoring script](../scripts/vendor_external_vectors.mjs) requires a full
commit SHA and records the fetched bytes and SHA-256 in `provenance.json`.
For example, to reproduce the PQ HPKE draft-05 corpus from its pinned commit:

```sh
HPKE_PQ_REF=6433c8fce0b8b749dfc86c1095081a88698ccfab \
  node scripts/vendor_external_vectors.mjs hpke_pq
```

The adapters consume committed corpora and do not require a source-ref input.
The provenance check re-downloads each file from the commit recorded in
`provenance.json`, applies its declared transformation where required
(currently RFC 8032 gzip decompression), and compares it with the committed
bytes without rewriting either file:

```sh
node scripts/vendor_external_vectors.mjs --check
```

### Reproducing the PQ HPKE PSK fixtures

The PSK corpus uses the independent draft-05 reference implementation and its
locked dependencies. Its source archive and output checksums are recorded
under `derived_files` in [provenance.json](../vectors/external/provenance.json).
Run the generator with the pinned archive to check the recorded output.

```sh
curl -fsSL https://codeload.github.com/hpkewg/hpke-pq/tar.gz/6433c8fce0b8b749dfc86c1095081a88698ccfab \
  -o /tmp/hpke-pq-draft05.tar.gz
python3 -B formal/hpke/generate_psk_vectors.py --check /tmp/hpke-pq-draft05.tar.gz
```

The generator verifies the archive checksum before extraction and uses Cargo
with the reference lockfile. Add `--offline` when the dependencies are cached.
The regular backend audit verifies the recorded fixture digest and runs the
vector tests from the local corpora.

## Running The External Tests

Run the practical external-vector subset:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

Run only the NIST ACVP adapters:

```sh
cargo test -p external-vector-audit --no-default-features --features native acvp_
```

Run only the default CCTV adapters:

```sh
cargo test -p external-vector-audit --no-default-features --features native cctv_
```

Run the deliberately slow CCTV deep audit command:

```sh
node scripts/run_external_cctv_deep_audit.mjs
```

That command runs only intentionally ignored CCTV-heavy checks: the ML-DSA
10,000-iteration accumulated hashes and the full ML-KEM modulus corpus. It is
not part of the normal release wall or default external-vector subset.

Run only the ML-DSA 10,000-iteration audit directly:

```sh
cargo test -p external-vector-audit --no-default-features --features native --test cctv_ml_dsa cctv_ml_dsa_accumulated_10k_vectors_match_public_api -- --ignored
```

Run only the full CCTV ML-KEM modulus audit directly:

```sh
cargo test -p external-vector-audit --no-default-features --features native --test cctv_ml_kem_modulus -- --ignored
```

Run raw-file shape and provenance integrity checks:

```sh
cargo test -p crypto-conformance-vectors --test vectors_tests --all-features external_vector_tests::cctv::all_vendored_cctv_files_have_expected_markers -- --ignored
cargo test -p crypto-conformance-vectors --test vectors_tests --all-features external_vector_tests::provenance::external_vector_files_match_pinned_sha256 -- --ignored
```

## ML-KEM CCTV Boundary

CCTV has ML-KEM `strcmp`, accumulated, and intermediate suites beyond the
modulus negative vectors. These are valuable, but they do not currently map to
ReallyMe's public primitive boundary.

The `strcmp` and accumulated suites require full ML-KEM decapsulation-key
encodings. ReallyMe's public ML-KEM keygen route intentionally accepts and
derives from the 64-byte FIPS `d || z` seed boundary, and it does not export
full decapsulation keys through the public API. The intermediate suite traces
low-level polynomial and transform operations that are intentionally not public
ReallyMe API surface.

We could add an audit-only backend adapter that exposes full ML-KEM keys or
internal math traces only to the external-vector harness. That should be an
explicit security/API decision, not an incidental testing shortcut, because it
would create a second boundary with different key-material handling and review
requirements.
