# External conformance vectors

Raw corpora live in [`vectors/external`](../vectors/external). Their source
URLs, pinned commits, licenses and SHA-256 hashes are recorded in
[`provenance.json`](../vectors/external/provenance.json). Keep those files,
including upstream READMEs, byte-for-byte intact. Put adapters in
[`tools/external-vector-audit/tests`](../tools/external-vector-audit/tests).

## Running tests

From the repository root:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

RFC 9180 and PQ HPKE Base/PSK adapters run as ordinary native workspace tests.
Supplementary ignored adapters can be selected explicitly:

```sh
cargo test -p external-vector-audit --no-default-features --features native --test wycheproof_ecdh_pcurves -- --ignored
cargo test -p external-vector-audit --no-default-features --features native --test xwing768_kat -- --ignored
```

Run the expensive CCTV sweeps separately:

```sh
node scripts/run_external_cctv_deep_audit.mjs
```

That command runs the ML-DSA 10,000-iteration accumulated tests and full ML-KEM
modulus corpus. The default subset uses 100 ML-DSA iterations and a representative
invalid-key subset.

## Coverage and limits

| Corpus | Executed boundaries |
| --- | --- |
| NIST ACVP | Matching public AES-GCM, AES-KW, SHA-2/SHA-3/SHAKE, HMAC-SHA2, HKDF, Ed25519/ECDSA verification, RSA verification, ML-DSA, X25519 and ML-KEM cases |
| CCTV | Ed25519 edge cases, P-256 RFC 6979 rejection sampling, ML-DSA accumulated/benchmark cases and ML-KEM modulus validation |
| Wycheproof | ChaCha20-Poly1305, secp256k1 ECDSA, X25519, X448 and NIST-curve ECDH |
| Supplementary | BIP-340, RFC 8032 signing, X-Wing draft KATs, RFC 9180 HPKE, PQ HPKE draft-05 Base/PSK and PBKDF2-HMAC-SHA256/SHA512 |

Vendoring is not execution. The following pinned samples do not establish
positive conformance at the corresponding public API:

- ACVP AES-GCM-SIV uses AES-128; this package exposes AES-256-GCM-SIV.
- HMAC-SHA3, PBKDF/SHA-224 and ANSI X9.63 samples do not match the public
  HMAC-SHA2, PBKDF2-SHA256/SHA512 and JWA Concat KDF profiles.
- The KMAC256 sample lacks matching byte-aligned non-XOF cases.
- The SLH-DSA sample has no positive empty-context external case. Internal
  backend positives do not establish public-boundary positive coverage.
- Argon2id's fixed public cost profiles cannot reproduce RFC 9106's smaller
  parameters. The backend has a separate RFC 9106 known-answer test.
- CCTV ML-KEM unlucky-sample vectors do not match the selected final-FIPS
  deterministic output. Its `strcmp`, accumulated and intermediate suites
  require key encodings or internal operations outside the public API.
- CCTV RSA candidate-fed key generation is not an exposed API.

Wycheproof `acceptable` cases are skipped. The adapters apply package policies:
secp256k1 high-S signatures are rejected, and ECDH input scalars are normalized
to the API's required width. Consult the adapter when comparing results with
another implementation.

## Reference encoder

Signature adapters use [`refenc.rs`](../tools/external-vector-audit/src/refenc.rs)
for DER and SEC1 construction, separately from production encoders. Its tests
and bounded Kani proofs run in the
[manual formal workflow](../.github/workflows/formal-verification.yml).
See [formal verification](../formal/README.md) for assumptions and commands.

## Updating corpora

Refresh supplementary files only after reviewing the upstream commit. The
vendoring script requires a full commit SHA. To reproduce the pinned PQ HPKE
corpus, for example:

```sh
HPKE_PQ_REF=6433c8fce0b8b749dfc86c1095081a88698ccfab node scripts/vendor_external_vectors.mjs hpke_pq
```

Check recorded source bytes without rewriting them:

```sh
node scripts/vendor_external_vectors.mjs --check
```

The check downloads the pinned sources and applies only declared transformations.
For a local-only digest check, run the named provenance test:

```sh
cargo test -p crypto-conformance-vectors --test vectors_tests --all-features external_vector_tests::provenance::external_vector_files_match_pinned_sha256 -- --ignored
```

## Reproducing the PQ HPKE PSK fixtures

The derived PSK corpus uses the pinned draft-05 reference implementation and
its lockfile. Source and output checksums are in `provenance.json`:

```sh
curl -fsSL https://codeload.github.com/hpkewg/hpke-pq/tar.gz/6433c8fce0b8b749dfc86c1095081a88698ccfab -o /tmp/hpke-pq-draft05.tar.gz
python3 -B formal/hpke/generate_psk_vectors.py --check /tmp/hpke-pq-draft05.tar.gz
```

Add `--offline` when its dependencies are cached. The generator verifies the
archive checksum before extraction.
