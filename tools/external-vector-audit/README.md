<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# External Vector Audit

This package is a manual audit runner for raw upstream vectors stored under
`vectors/external`. It is intentionally separate from the default test matrix:
the upstream corpora are large, and some suites are useful as periodic
third-party proof rather than every-commit feedback.

The coverage tables, CI gating, and public-boundary notes are documented in
[`docs/external-conformance-vectors.md`](../../docs/external-conformance-vectors.md).

Run the practical subset from the repository root with:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

Run the deliberately slow CCTV deep-audit command from the repository root with:

```sh
node scripts/run_external_cctv_deep_audit.mjs
```

DER and SEC1 byte construction for the signature adapters is delegated to the
intentionally independent reference encoder in [`src/refenc.rs`](src/refenc.rs)
— deliberately *not* the production encoders, so an encoding regression in
production surfaces as a mismatch instead of being masked. Its edge cases are
pinned by unit tests and bounded `#[cfg(kani)]` proofs in that module.

Beyond ACVP and CCTV, supplementary adversarial and known-answer corpora
(Google/C2SP Wycheproof ChaCha20-Poly1305, secp256k1 ECDSA, X25519, X448, and
P-256/384/521 ECDH; the BIP-340 Schnorr CSV; the RFC 8032 Ed25519 `sign.input`
signature-generation corpus; the X-Wing-768 CFRG draft KAT; and the HPKE RFC 9180
base-mode KAT) are vendored on demand by
[`scripts/vendor_external_vectors.mjs`](../../scripts/vendor_external_vectors.mjs)
and executed by the `wycheproof_*`, `bip340_schnorr`, and `rfc8032_ed25519_siggen`
adapters. Those adapters are `#[ignore]` and fail closed until their corpus is
vendored. Some encode a deliberate ReallyMe policy so a documented difference
reads as a positive check: the secp256k1 ECDSA adapter expects high-S "valid"
signatures to be rejected (low-S / BIP-62), and the P-curve ECDH adapter expects
an all-zero shared secret to be rejected.

The [`External Vector Audit`](../../.github/workflows/external-vectors-audit.yml)
workflow runs the cheap SHA-256/marker integrity sweep on vector-touching PRs and
the heavy ACVP/CCTV sweeps and Kani proofs on manual dispatch or a weekly
schedule. The slower supplementary adapters run only on a deliberate manual
dispatch with the reviewed source refs; they do not run on the weekly schedule.

The tests execute ReallyMe primitive crates directly. When an upstream vector
uses a private/internal representation that is not part of the public primitive
boundary, the adapter records that as an explicit unsupported proof route rather
than importing internal backend types.

Executable ACVP proof routes currently cover AES-GCM, AES-KW, HMAC-SHA2,
KDA-HKDF cases that map directly to raw HKDF-SHA2-256/384, SHA2-256/384/512,
SHA3-224/256/384/512, SHAKE-256, X25519, ML-KEM keygen and encapsulation for
512/768/1024, ML-DSA keygen for 44/65/87, the public-boundary ML-DSA signature
verification subset for 44/65/87, Ed25519 signature verification, P-256
ECDSA/SHA-256 signature verification, P-384 ECDSA/SHA-384 signature
verification, P-521 ECDSA/SHA-512 signature verification, and RSA
PKCS#1 v1.5/SHA-256 signature verification.

The raw NIST ACVP files and exact source URLs are listed in
`vectors/external/provenance.json`, including the pinned upstream commit and
SHA-256 hash of each checked-in file.

Executable CCTV proof routes are kept in separate `cctv_*` test files. They
currently cover Ed25519 strict-verification edge cases, the RFC6979 P-256
rejection-sampling signing vector, ML-DSA accumulated 100-iteration hashes,
ignored ML-DSA accumulated 10,000-iteration hashes for deliberate audits,
benchmark-message signing checks for 44/65/87, and the practical subset of
CCTV modulus-check negative encapsulation-key vectors across ML-KEM-512/768/1024
with an ignored full-corpus variant for deliberate audits. CCTV unlucky XOF
vectors are vendored and shape-checked, but the pinned corpus is documented by
upstream as FIPS 203 `ipd`/draft-oriented and does not match the final-FIPS
RustCrypto backend used by ReallyMe. CCTV `strcmp` vectors are also vendored
and shape-checked, but they use full ML-KEM decapsulation-key encodings while
ReallyMe's public primitive boundary intentionally accepts the 64-byte FIPS
`d || z` seed. CCTV intermediate traces are vendored and shape-checked as
internal math traces rather than public-boundary conformance claims. CCTV
ML-KEM accumulated hashes are vendored in the upstream README, but those hashes
also include the full `ML-KEM.KeyGen` decapsulation-key encoding and therefore
require a boundary ReallyMe does not expose today. CCTV RSA keygen candidate
streams are status-only because ReallyMe exposes RSA signature verification,
not deterministic candidate-fed RSA key generation.

Vendored ACVP files that are present but not executable against the current
public primitive boundary are checked explicitly: the pinned AES-GCM-SIV sample
contains AES-128-GCM-SIV vectors while ReallyMe exposes AES-256-GCM-SIV; the
ANSI X9.63 KDF file uses raw `sharedInfo` while ReallyMe exposes the JOSE/JWA
Concat KDF profile; the HMAC-SHA3 sample is vendored but ReallyMe's public MAC
enum exposes HMAC-SHA2 only; and the current KMAC and PBKDF samples do not
expose a matching byte-oriented public route. The KMAC sample has no
byte-aligned non-XOF cases, and the PBKDF sample uses SHA2-224 while ReallyMe exposes
PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-512. The pinned RSA-PSS samples use
SHA3/SHAKE or older SHA1/SHA2-224 profiles that are outside the current RSA
public verifier suites. The pinned SLH-DSA signature
verification input sample is vendored and parsed, but its only
SLH-DSA-SHA2-128s external/pure/empty-context case for the current public
boundary is negative, so the audit records rejection behavior rather than
claiming positive SLH-DSA ACVP conformance from that sample.
