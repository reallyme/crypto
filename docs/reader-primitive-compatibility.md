# Reader primitive compatibility

This matrix covers cryptographic primitives for ISO/IEC 18013-5:2021 and the
pinned edition-2 DIS. Protocol encoding, certificate acceptance, trust paths,
revocation, replay, request binding and session-counter policy remain in the
reader. The new interfaces are opt-in Rust APIs; existing default features,
algorithm identifiers, SDK routes and signature policies retain their behavior.

The source package versions remain **0.3.17**. The additional interfaces described
here are unreleased changes and require a coordinated package release before
registry consumers can select them. Published 0.3.17 packages do not contain
these new features.

The reviewed lockfile resolves the relevant implementation packages as follows:

| Package | Version |
| --- | --- |
| `reallyme-crypto`, `reallyme-crypto-hpke`, existing ReallyMe primitive leaves | 0.3.17 (additional interfaces unreleased) |
| `reallyme-codec` and its selected Rust leaves | 0.3.4 |
| `der` (strict codec parser) | 0.8.3 |
| `hpke` | 0.15.1 |
| `p256`, `p384`, `p521`, `bp256`, `bp384` | 0.14.0 |
| `primefield` / `primeorder` / `elliptic-curve` | 0.14.0 / 0.14.0 / 0.14.3 |
| `ed448-goldilocks` (curve arithmetic only) | 0.14.0-pre.15 |
| `shake` / `crypto-bigint` | 0.1.0 / 0.7.10 |
| `ecdsa` | 0.17.0 |
| `sha2` / its `digest` dependency | 0.11.1 / 0.11.3 |
| `sha1` (identifier feature only) | 0.11.0 |
| `secrecy` / `zeroize` | 0.10.3 / 1.9.1 |
| `openssl` / `openssl-sys` | 0.10.82 / 0.9.118 |
| `openssl-src` (private provider build tool only) | 400.0.2+4.0.3 |

## Source baseline

The licensed sources were reviewed in place. No licensed text or CDDL is
reproduced here. SHA-256 identifies each reviewed edition:

| Edition | SHA-256 |
| --- | --- |
| ISO/IEC 18013-5:2021 | `bfb9bf437656c628f2c201a35fc4873abf41d7f0314ae410d1f1b437a8e8fc5e` |
| Edition-2 DIS, cover 2026 / main text 2025 | `8dc30c5a399ded7b4274c1aebb7624eeab02aaf8f55d0c225734b8aae140fb77` |

The DIS is a pinned draft, without a claim that it is final or the latest draft.
Its certificate-validation text is in 12.8.3; references elsewhere to 12.8.4
are retained as a source discrepancy, rather than interpreted as a new clause.

## Clause-to-interface matrix

| Requirement | Rust interface and feature | Evidence |
| --- | --- | --- |
| 2021 9.1.2.4, 9.1.5.2 table 22; DIS 12.3.4, 12.4.6, 12.5.4, 12.7.2 table 17: NIST ECDSA/ECDH | `reallyme_crypto::ecdsa_explicit::{EcdsaKey, verify, validate_public_key}`; `ecdsa-explicit` | `ecdsa_explicit_tests`: independent key, raw agreement, signature, prehash and high-S known answers for each curve and hash |
| Same clauses: Brainpool ECDSA/ECDH | Same interface; portable `brainpool`, optional native `brainpool-openssl` provider | Same tests execute all four curves natively and in WASM when selected; absent-feature tests require `UnsupportedCurve` |
| Same clauses: X25519/X448 raw agreement | Existing `reallyme-crypto-x25519` / `reallyme-crypto-x448` leaves, `native` / `wasm` | Existing RFC 7748 and invalid/low-order-point tests |
| Same clauses: ordinary Ed25519 | Existing `reallyme-crypto-ed25519` leaf | Existing seed/signature known answers and strict verification tests |
| Same clauses: ordinary Ed448 | `reallyme_crypto::ed448::{Ed448Key, verify, sign_with_provider}`; portable `ed448`, optional native `ed448-openssl` verifier | `ed448_tests`: RFC 8032 ordinary key/signature answers, protected generation/import, opaque signing, rejected context/prehash variants, canonical scalar/point and cleanup tests; independent native verifier |
| DIS 12.6.4 tables 21–23, 12.7.1: optional document-response encryption | `crypto_hpke::base_p256::{P256RecipientKey, seal, open}`; `base-p256-aes128gcm` | RFC 9180 A.3.1 retained unchanged; separate independently calculated empty-AAD answer; bounds, context, mode, suite, key, encoding, tampering and RNG tests |
| 2021 9.1.1.5; DIS 12.2.5: ordinary session encryption | Existing raw ECDH leaves, `crypto_hkdf::derive`, `crypto_aes256_gcm::{encrypt, decrypt_zeroizing}` | Existing agreement, RFC 5869 and NIST AES-GCM vectors; this cipher remains AES-256-GCM |
| SHA-256/384/512, certificate thumbprints, HMAC-SHA256 verification | Existing `crypto_sha2_256::digest`, `crypto_sha2::{digest_sha2_384, digest_sha2_512}`, `crypto_hmac::verify` | 1,668 NIST byte-aligned SHA-2 AFT answers, million-byte answers, differential padding and clearing-owner regressions; existing HMAC vectors |
| DIS 12.8 and Annex B: certificate/CRL ECDSA verification | `ecdsa_explicit::verify` with explicit `EcdsaHash`, `EcdsaInput`, `EcdsaEncoding` | All 21 issuer-curve/hash primitive combinations; exact-byte mutation, encoding-confusion, digest-length and high-S cases |
| Annex B; RFC 5280 4.2.1.2 method (1): subject key identifier | `key_identifier::subject_key_identifier_sha1`; separate `key-identifier-sha1` feature | Fourteen independent identifiers across seven curves; compressed/uncompressed payloads, retained SEC1 prefixes, BIT STRING framing, unused-bit octet and full-SPKI wrong-span comparisons |
| Reader signing without private-key export | `ecdsa_explicit::{OpaqueEcdsaSigner, sign_with_provider}` | Non-exporting test provider executes signing and returns stable typed provider failures; returned signatures are checked against the associated public key |

These APIs expose primitives. The caller selects the permitted certificate
profile and interprets validated OIDs; a successful primitive operation does
not perform those acceptance checks.

The curve-aware conversion functions remain crypto interfaces. Strict DER
syntax is decoded by published `reallyme-codec` 0.3.4 with defaults disabled
and only its `der` feature enabled. Crypto retains scalar widths, nonzero and
subgroup-order checks, signature verification and high-S policy. Existing
conversion functions and typed errors remain available. Tests enable the
parser dependency's BER feature separately to verify that feature unification
does not relax the DER boundary.

Related group and RSA operations are separate primitive contracts; their
presence does not select a reader protocol or expand ISO algorithm policy:

| Operation | Rust interface and feature | Evidence |
| --- | --- | --- |
| Supplied-base operations in seven EC and three RFC 5114 DH domains | `prime_groups::{PrimeGroup, GroupScalar, GroupElement}`; `prime-groups` | Nine native/WASM tests cover independent parameters, multiplication, agreement, linear combinations, field mapping, exact encodings, invalid domains/subgroups, bounded entropy failure and protected owners |
| Exact-width RSA public representative and modulus complement | `crypto_rsa::{rsa_public_representatives, RsaPublicKeyDerEncoding, RsaPublicRepresentatives}`; existing RSA leaf, with no backend feature required | Eighty-four independent integer answers, SPKI/PKCS#1 keys, 1024–8192-bit boundaries, typed width/range/key failures and ownership compile-fail tests |

RSA representatives expose `s^e mod n` and its modulus complement in protected
owners. They do not interpret padding, validate a signature scheme or establish
trust. The caller must select and validate its protocol's complete signature
format. Existing RSA verification interfaces retain their contracts.

## Curve, hash and encoding contracts

| Curve | Scalar / raw shared secret bytes | Uncompressed SEC1 public bytes | ISO COSE message hash | Provider |
| --- | --- | --- | --- | --- |
| P-256 | 32 / 32 | 65 | SHA-256 | Portable Rust |
| P-384 | 48 / 48 | 97 | SHA-384 | Portable Rust |
| P-521 | 66 / 66 | 133 | SHA-512 | Portable Rust |
| brainpoolP256r1 | 32 / 32 | 65 | SHA-256 | Portable Rust; optional native provider |
| brainpoolP320r1 | 40 / 40 | 81 | SHA-384 | Portable Rust; optional native provider |
| brainpoolP384r1 | 48 / 48 | 97 | SHA-384 | Portable Rust; optional native provider |
| brainpoolP512r1 | 64 / 64 | 129 | SHA-512 | Portable Rust; optional native provider |

The ECDSA/ECDH private owner validates the scalar and binds its uncompressed
public key at import. Raw ECDH preserves the fixed-width big-endian
x-coordinate, including leading zeros. The X25519/X448 leaves retain RFC 7748
little-endian encodings and their curve-specific validation rules.

ISO COSE message restrictions in the table are caller policy. Certificate and
CRL verification select SHA-256, SHA-384 or SHA-512 explicitly from the validated
signature OID, independently of issuer-curve size. The corresponding ECDSA OIDs
are `1.2.840.10045.4.3.2`, `.3` and `.4`. The API accepts exact message bytes
to hash once, or an exact-length prehash to consume without another hash.
Each of the seven issuer curves supports all three explicit hashes. Independent
certificate and CRL answers cover all 42 curve/hash/structure combinations.

`EcdsaEncoding::Der` requires strict DER and valid nonzero scalars below the
curve order. `FixedWidth` requires big-endian `r || s` with two full-width
scalars. No format is inferred from length. `der_to_fixed` and `fixed_to_der`
preserve high-S values and leading zeros. Verification accepts valid high-S
signatures; callers retain any stronger canonicalization policy. Existing
P-256 low-S APIs retain their existing contracts.

The legacy key-identifier operation hashes the extracted subjectPublicKey BIT
STRING payload as received. Its SEC1 point prefix remains part of that payload.
Compressed and uncompressed representations of the same point have different
method-(1) identifiers. ASN.1 framing removal and validation belong to the
codec/trust boundary; this API does not normalize points.

Portable ECDSA signing is deterministic RFC 6979 using the backend curve's
nonce-HMAC digest. The supplied message hash stays explicit. The optional
native Brainpool provider uses randomized ECDSA. The portable Brainpool
implementation uses the existing field and complete point-arithmetic engines;
the 320-bit and 512-bit curves instantiate the RFC 5639 domain parameters.
The 320-bit curve retains 40-byte wire scalars and coordinates while using
384-bit integer storage internally.

Ordinary Ed448 uses RFC 8032 with empty context and no external prehash.
`Ed448Key` imports a 57-byte seed or generates one with fallible entropy,
binds its public key and signs without private export. All seed expansion,
nonce and challenge outputs enter clearing owners directly. Constant-time
integer reduction precedes construction of private scalars; secret bytes do
not enter the arithmetic dependency's byte-decoding or signing adapters.
Explicit destruction invalidates the owner even though an all-zero seed is a
valid RFC 8032 seed. Portable verification checks canonical points and scalars,
rejects small-order public keys and uses the RFC cofactored verification
equation. Contextual Ed448 and Ed448ph are separate variants and are rejected
by this ordinary-signature interface.

The portable Ed448 adapter reuses the curve arithmetic already selected by the
X448 leaf. Its signing adapter is local and ownership-focused; it does not
enable the dependency's signing feature. This source review and known-answer
validation do not constitute an independent audit of the complete current
arithmetic dependency.

## Bounded HPKE contract

The feature `base-p256-aes128gcm` enables only KEM `0x0010`, KDF `0x0001` and
AEAD `0x0001` plus the protected interface's dependencies. Existing generic
HPKE APIs remain available for other suites, modes and AAD contracts.

The bounded interface always creates a fresh single-record Base context and
uses empty AAD. The caller's `info` bytes are passed unchanged. For the pinned
DIS profile, the reader supplies its untagged encoded SessionTranscript with
EncryptionParametersBytes in the second slot. Transcript hashing, tagging,
CBOR parsing, labels and reader role decisions are outside this interface.

Recipient import requires a valid 32-byte big-endian P-256 scalar. Its owner
exposes the associated 65-byte uncompressed public key and no private export.
Both recipient public keys and `enc` require a valid 65-byte encoding beginning
with `0x04`. `P256BaseSealed` exposes `enc` and ciphertext separately. The
ciphertext has a trailing 16-byte AES-GCM tag.

Local bounds are 65,530 bytes of `info`, 16,777,216 bytes of plaintext, and
16,777,232 bytes of ciphertext. AAD is empty. Bounds and checked length
arithmetic precede sensitive copies. Buffers use fallible reservation; private
bytes enter a secrecy owner and plaintext enters clearing storage before
decryption. An authentication failure returns no plaintext. Each call creates
and drops its own backend context and ephemeral state.
Authenticated output uses `P256BasePlaintext`, a clearing owner with borrowed
byte access and no `Debug`, `Clone`, serialization or raw ownership export.

Successful Base-mode decryption authenticates a record under the recipient
key and supplied context. Sender authentication, issuer/device trust and
document/request binding require the reader's separate validation.

## Narrow feature recipes

Commands below target this source tree with defaults disabled:

```sh
cargo test -p reallyme-crypto --no-default-features --features prime-groups --test prime_groups
cargo test -p reallyme-crypto-rsa --no-default-features --tests
cargo test -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm --lib
cargo test -p reallyme-crypto --no-default-features --features brainpool,ed448,key-identifier-sha1 --lib --test ecdsa_explicit_tests --test ed448_tests --test key_identifier_tests
cargo test -p reallyme-crypto --no-default-features --features brainpool-openssl,ed448-openssl,key-identifier-sha1 --test ecdsa_explicit_tests --test ed448_tests --test key_identifier_tests
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test --release -p reallyme-crypto-hpke --target wasm32-unknown-unknown --no-default-features --features base-p256-aes128gcm --lib
```

The separate existing leaves provide hashes (`reallyme-crypto-sha2-256`,
`reallyme-crypto-sha2`), HMAC (`reallyme-crypto-hmac`), HKDF
(`reallyme-crypto-hkdf`) and session AEAD (`reallyme-crypto-aes256-gcm`). Select
their existing runtime features directly; the broad umbrella defaults are
unnecessary. HKDF's unlabelled `derive` interface preserves caller-supplied
salt and info; protocol-specific labels belong to the reader.

`brainpool-openssl` and `ed448-openssl` are excluded from defaults. Selecting
all features includes these providers. Native targets require an explicitly
linked OpenSSL installation for the target architecture; no automatic bundled
build is selected. The runtime release policy accepts OpenSSL 3.5.9 or later
in the 3.5 family, 4.0.3 or later in the 4.0 family, and 4.1.x. Older,
unsupported and unreviewed release families fail closed. This policy includes
the generic EC signing correction for CVE-2026-54872; it does not replace
ongoing dependency advisory review.

The private `optional-provider-build` tool builds the registry-checksummed
`openssl-src` **400.0.2+4.0.3** source package (OpenSSL **4.0.3**) for an explicit
target. It does not process private keys and is not a published dependency:

```sh
IPHONEOS_DEPLOYMENT_TARGET=16.0 cargo run --locked -p optional-provider-build -- --target aarch64-apple-ios --out-dir /tmp/crypto-provider-ios
IPHONEOS_DEPLOYMENT_TARGET=16.0 OPENSSL_DIR=/tmp/crypto-provider-ios/install OPENSSL_STATIC=1 cargo check --locked -p reallyme-crypto --target aarch64-apple-ios --no-default-features --features brainpool-openssl,ed448-openssl,key-identifier-sha1
```

Cross builds also require the target's compiler/SDK configuration. Use the
application's minimum iOS deployment target or Android API level when building
the C library and Rust code. CI provisions the same pinned source before native
tests. The exposed provider uses EC and Ed448 operations only; the optional
provider does not select OpenSSL for the existing symmetric primitives.

`brainpool` and `ed448` provide portable native and WASM implementations without
OpenSSL. Native `brainpool-openssl` and `ed448-openssl` explicitly select their
native providers; an unavailable or rejected selected provider fails closed.
WASM uses the portable implementation when these features are selected because
the native dependency is target-excluded. No runtime fallback changes an
explicit native provider selection.

## Validation scope

| Environment | Evidence | Limits |
| --- | --- | --- |
| Native ARM64 macOS, Rust 1.100.0 | 920 native and 990 all-feature workspace tests passed, with 17 existing skips per profile, including the additional prime-group and RSA representative interfaces; strict Clippy, API compatibility and independent known answers; optional provider execution with pinned OpenSSL 4.0.3 | Primitive behavior does not establish reader trust or protocol acceptance |
| Rust 1.96.0 | All-feature workspace compilation | Minimum-version compile evidence |
| WASM, Node test runner | 58 current-checkpoint functions execute across reader primitives, prime groups, RSA representatives, P-256 conversions and HPKE; separate SHA-2 NIST execution also passed; HPKE includes the maximum 16 MiB record | These tests do not establish browser-specific application integration |
| iOS 27.0.1 physical device, ARM64; Rust 1.100.0 | 100 test functions execute: all seven ECDSA/ECDH curves, ordinary Ed448, identifiers, HPKE, SHA-2 NIST answers and existing Ed25519/X25519/X448/HMAC/HKDF/AES-GCM suites | Rust engines execute inside signed isolated test applications; SDK facade routing is separate |
| iOS 26.5 simulator, ARM64; Rust 1.100.0 | Portable reader, HPKE and SHA-2 suites execute | Simulator evidence supplements physical-device execution |
| `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` | All three portable target configurations compile; optional pinned OpenSSL 4.0.3 provider compilation also checked | x86-64 simulator execution was not performed |
| Android 17 / API 37 physical device, ARM64; Rust 1.100.0 | Same 100 test functions execute, including all three direct RFC 5869 SHA-256 answers | Rust engine execution; application integration and SDK routing remain separate |
| Android 16 / API 36 emulator, ARM64; Rust 1.100.0 | Same 100 test functions execute | Emulator evidence supplements physical-device execution |
| `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android` | All four portable targets compile with NDK 29.0.14206865 and API 24 link configuration; optional pinned OpenSSL 4.0.3 provider compilation also checked | Runtime execution covers ARM64; other architectures have compilation evidence |

The additional `prime-groups` and RSA representative interfaces have native
and WASM execution evidence and compilation checks for all seven mobile targets.
The physical-device evidence above predates these additions and the codec 0.3.4
integration; no additional device execution is claimed for those changes.

The existing Swift, Kotlin and TypeScript facade suites remain regression
evidence for their existing provider routes. These additions expose Rust APIs;
they do not add facade routes or advertise the new primitives through those SDKs.

## Ownership and delivery limits

New private-key owners and raw shared secrets use secrecy storage, clear on
drop and offer no implicit private export. Plaintext and entropy buffers are
zeroizing owners. Borrowed source buffers remain the caller's cleanup
responsibility. Backend and compiler copies have the limitations described in
`SECURITY_MEMORY_MODEL.md`. HKDF expansion writes directly into its clearing
output owner, including error exits, while preserving existing error variants
and exact caller-supplied salt and info bytes.

Portable Brainpool has a separate dependency-level serialization cleanup gap.
In `primefield` 0.14.0, `MontyFieldElement::to_bytes` stages an unguarded padded
coordinate array before copying into the returned representation. The ECDH
shared-secret owner clears its retained bytes but cannot clear that discarded
source array. This is a source-level buffer finding, beyond compiler/register
copy limitations. Complete coordinate-serialization cleanup requires a reviewed
dependency repair or a supported direct-output interface; it is not established
by the current outer owners or known-answer tests. The upstream encoding
implementation remains in use, and this limitation is temporarily accepted.
Practical disclosure and incorrect cryptographic results have not been
demonstrated. This acceptance does not close the intermediate-buffer cleanup
requirement in CR-DIS-03 for providers using that serialization path.

All seven ECDSA/ECDH curves, ordinary Ed448, key identifiers and bounded HPKE
have portable native and WASM execution coverage. Existing native providers
remain optional and separately tested. New Rust capabilities do not add
Swift/Kotlin/TypeScript facade routes or change existing serialized identifiers.

The three SHA-2 one-shot leaves now use the existing block compression and
padding engines with protected state, padding buffers and output owners.
They bypass the dependency's unguarded fixed-output temporary; no dependency
patch or change to FIPS SHA-2 output semantics is required. The upstream
fixed-output wrapper itself remains unchanged for unrelated users. The
ownership repair and its regression evidence are documented separately in
`SECURITY_MEMORY_MODEL.md`.

Parameter tests cover field widths, reduction, inversion, square roots and
full multiplicative orders for both scalar fields and the 320-bit base field.
For the private 512-bit base-field metadata, generator 2 has verified quadratic
nonresidue and square-root properties; a complete multiplicative-order
certificate remains an outstanding review item. The executed ECDSA/ECDH paths
use the verified square-root property. This evidence does not claim a complete
formal proof or an independent audit of the arithmetic implementation.

A coordinated versioned package release remains a delivery step. Full reader
conformance also requires protocol and trust-layer work outside these
primitives. Proof-system selection remains a separate contract.

Primary primitive references: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html),
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html),
[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html),
[RFC 5639](https://www.rfc-editor.org/rfc/rfc5639.html),
[RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html),
[RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html),
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), and
[Standards for Efficient Cryptography 2 (SEC 2)](https://www.secg.org/sec2-v2.pdf).
Provider release policy references the
[OpenSSL generic EC signing advisory](https://openssl-library.org/news/vulnerabilities/#CVE-2026-54872)
and [supported release list](https://openssl-library.org/source/).
