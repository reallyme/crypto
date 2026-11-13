# Reader primitive compatibility

This document maps the cryptographic primitives for ISO/IEC 18013-5:2021 and
the pinned edition-2 DIS to the current **0.4.0 source API and schema**.
Protocol encoding, certificate acceptance, trust paths, revocation, replay,
request binding and session-counter policy remain in the reader.

The 0.4.0 error migration is a deliberate Rust source API change. Primitive
bytes, existing algorithm identifiers, signature policies and provider choices
retain their contracts; callers using former nested error variants must migrate
to the canonical error reasons described below. Standalone schema adapters are
opt-in and do not add executable root operation branches or SDK provider routes.

All 44 Rust packages under `crates/` have source version **0.4.0**: 41 are
registry-publishable, while the FFI, WASM and conformance-vector packages remain
`publish = false`. The complete package list appears below. No 0.4.0 package
release is claimed. Existing 0.3.17 registry packages and tags remain unchanged;
the Swift, Kotlin and TypeScript source artifact versions remain **0.3.17**.
No SDK publication is claimed by this checkpoint, and those version pins do not
advertise the new Rust contracts.

The two deprecated X25519/secp256k1 key-generation names also return canonical
`Result` values in 0.4.0, replacing their historical infallible entropy path.
The [fallible-generation migration note](0.4-entropy-error-migration.md) describes
the caller adjustment; successful key bytes and selected providers are unchanged.

Current 0.4.0 parity, negative-input, lifecycle and ownership regression sources
are **unexecuted**. Earlier native, WASM and mobile runtime evidence is retained
in the historical validation section with its source scope. It is not evidence
that the 0.4.0 migration has passed runtime regression testing.

The compiler inventory and original migration checks are scoped to
`e0368ca60ab68eb710b6cf5cf5a46b66fdbaf4c4`. The subsequent private RSA ownership
repair and sparse-feature checks are recorded separately below, without
relabeling the original compiler capture. The completed
[schema-contract reconciliation](schema-contract-reconciliation.md) records
3,617 declaration/exposure records and 3,511 export edges, with no unresolved
supported product items and 47 explicit private-tooling records. This establishes
source correspondence within its stated scope, not universal wire callability
or runtime conformance.

The reviewed lockfile resolves the relevant implementation packages as follows:

| Package | Locked version |
| --- | --- |
| ReallyMe Crypto Rust packages listed below | 0.4.0 source versions; unreleased |
| `reallyme-codec` and its selected Rust leaves | 0.3.4 |
| `der` (strict codec parser) | 0.8.3 |
| `hpke` | 0.15.1 |
| `p256`, `p384`, `p521`, `bp256`, `bp384`, `k256` | 0.14.0 |
| `primefield` / `primeorder` / `elliptic-curve` | 0.14.0 / 0.14.0 / 0.14.3 |
| `ed448-goldilocks` (curve arithmetic only) | 0.14.0-pre.15 |
| `shake` / `crypto-bigint` | 0.1.0 / 0.7.10 |
| `sha3` selected by the SHA-3 digest leaves | 0.12.0 |
| `ecdsa` | 0.17.0 |
| `sha2` / its `digest` dependency | 0.11.1 / 0.11.3 |
| `sha1` (identifier feature only) | 0.11.0 |
| `secrecy` / `zeroize` | 0.10.3 / 1.9.1 |
| `buffa` / `thiserror` | 0.9.2 / 2.0.21 |
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

## Clause-to-schema, API, feature and test matrix

Schema names below are in `reallyme.crypto.v1`. A schema identity alone does
not prove implementation support. Standalone requests require the named native
adapter and its selected features; they do not imply a generic executable wire
route. The test column identifies source coverage. Current 0.4.0 execution is
pending for every row; the historical engine results are scoped separately.

| Request / source clauses | Schema contract | Native API / adapter | Narrow features | Test sources and scope |
| --- | --- | --- | --- | --- |
| CR-DIS-01: 2021 9.1.2.4, 9.1.5.2 table 22; DIS 12.3.4, 12.4.6, 12.5.4, 12.7.2 table 17; seven NIST/Brainpool ECDSA and ECDH curves | `CryptoEcdsaKeyGenerateRequest`, `CryptoEcdsaKeyImportRequest`, `CryptoEcdsaPublicKey`, `CryptoEcdsaKeyDescriptor`, `CryptoEcdsaInput`, `CryptoEcdsaSignRequest`, `CryptoEcdsaVerifyRequest`, `CryptoEcdsaAgreementRequest`; clearing signature/agreement results | `ecdsa_explicit::{EcdsaKey, verify, validate_public_key, sign_with_provider}` and `ecdsa_explicit::contract`; protected software generation/import and injected opaque signing | `ecdsa-explicit`; add `brainpool` for all four portable Brainpool curves, or optional native `brainpool-openssl`; add `operation-response` for these schema adapters | `ecdsa_explicit_tests` retains independent key/agreement/signature/prehash/high-S answers for every curve and hash; `ecdsa_native_contract_tests` adds borrowed-byte, presence, enum, provider, ownership and adapter parity sources |
| CR-DIS-01: X25519 raw agreement | Existing `CryptoKeyAgreementDeriveKeyPairRequest` and `CryptoKeyAgreementDeriveSharedSecretRequest/Result`; standalone generation request below | Existing X25519 leaf and `operations::key_agreement` / operation-contract adapter | X25519 leaf `native` or `wasm`; root `x25519` plus its existing execution/operation features when using dispatch | Existing RFC 7748 and invalid/low-order-point sources; generation consistency is covered separately |
| CR-DIS-01 and CR-DIS-03: existing raw key-agreement generation for X25519/P-256/P-384/P-521 | `CryptoKeyAgreementGenerateKeyPairRequest.algorithm` requires the existing KeyAgreement branch; result is existing `CryptoKeyPair` | `key_agreement_contract::generate_key_pair` calls `operations::key_agreement::generate_key_pair`, retaining `KeyAgreementKeyGeneration` policy | Root `operation-response`, selected `x25519` / `p256` / `p384` / `p521`, and existing `native` or target-appropriate `wasm` runtime; disabled algorithms fail typed unsupported | `key_agreement_generation_contract_tests`: every identity and selected/disabled lane, wrong families/modifiers, wire identity, clearing owners and generated-key reconstruction through root/direct leaves; unexecuted |
| CR-DIS-01: X448 raw agreement | `CryptoX448PrivateKeyInput`, `CryptoX448PublicKey`, `CryptoX448KeyDescriptor`, `CryptoX448AgreementRequest`, `CryptoNativeAgreementResult`; empty native generation/public-key requests | `crypto_x448::{X448PrivateKey, X448PublicKey, derive_x448_shared_secret}` and `crypto_x448::contract` | Leaf `native` or `wasm`; add leaf `proto` for the standalone adapter | Existing RFC 7748/point/width tests and `contract_tests`; the local scalar guard repair has unexecuted ownership regressions |
| CR-DIS-01: ordinary Ed25519 | Existing signature generation/derivation/sign/verify requests and results with explicit Ed25519 identity | Existing Ed25519 leaf and signature operation adapters | Leaf `native` or `wasm`; existing root `ed25519` route and operation features as selected | Existing seed/signature answers, strict verification and root operation-contract sources |
| CR-DIS-01: ordinary Ed448 | `CryptoEd448SupportRequest`, `CryptoEd448KeyImportRequest`, `CryptoEd448PublicKey`, `CryptoEd448KeyDescriptor`, `CryptoEd448OrdinarySignRequest`, `CryptoEd448OrdinaryVerifyRequest`; empty generation/public-key requests | `ed448::{Ed448Key, require_support, verify, sign_with_provider}` and `ed448::contract` | Portable `ed448`; optional native verifier `ed448-openssl`; add `operation-response` for schema adapters | `ed448_tests` retains all eight ordinary empty-context RFC 8032 cases, protected generation/import, canonical encodings and rejected context/prehash variants; `ed448_native_contract_tests` adds adapter, capability, failure and ownership sources |
| CR-DIS-02: DIS 12.6.4 tables 21–23 and 12.7.1; optional single-record Base/P-256/HKDF-SHA256/AES-128-GCM | `CryptoHpkeP256BaseRecipientGenerateRequest`, `CryptoHpkeP256BaseRecipientImportRequest`, `CryptoHpkeP256BasePublicKey`, `CryptoHpkeP256BaseCapabilities`, seal/open requests and separate sealed/plaintext results | `crypto_hpke::base_p256::{P256RecipientKey, seal, seal_with_rng, open}`; `proto_protocol::{P256BaseRecipientGenerateInputs, P256BaseRecipientImportInputs, P256BaseSealInputs, P256BaseOpenInputs}` | Leaf `base-p256-aes128gcm`; add leaf `proto` for schema adapters; no umbrella runtime defaults or OpenSSL required | Existing `base_p256::tests` retain unchanged RFC 9180 A.3.1 and independent empty-AAD answers, maximum record, malformed inputs, context/tampering and entropy failure; new `proto_recipient_lifecycle_tests`, `proto_seal_rng_tests` and `proto_protocol_tests` are unexecuted |
| CR-DIS-03: 2021 9.1.1.5; DIS 12.2.5; mandatory ordinary session encryption | Existing raw agreement requests, `CryptoHkdfDeriveRequest/Result`, standalone `CryptoHkdfNativeDeriveRequest/Result` with `CryptoHkdfDeriveInputs`, `CryptoAeadSealRequest/Result`, `CryptoAeadOpenRequest/Result` | Existing raw ECDH; `crypto_hkdf::derive` and `proto_native::HkdfNativeDeriveInputs<N>::{derive, derive_result}`; `crypto_aes256_gcm::{encrypt, decrypt_zeroizing}` | Select agreement, HKDF and AES-256-GCM leaves with defaults disabled; leaf runtime features; HKDF `proto` only when using its standalone adapter | Existing agreement, RFC 5869 and NIST AES-GCM vectors; `proto_options_tests`, `proto_native_tests`, `proto_native_wire_tests`, AEAD nonce/operation and exact-context regression sources; ordinary session cipher remains AES-256-GCM |
| CR-DIS-03: SHA-256/384/512, certificate thumbprints and HMAC-SHA256 verification | Existing `CryptoHashRequest/Result`, `CryptoMacVerifyRequest` and canonical error envelopes | `crypto_sha2_256::digest`, `crypto_sha2::{digest_sha2_384, digest_sha2_512}`, `crypto_hmac::verify` | Select SHA-2 and HMAC leaves with their existing `native` / `wasm` features; no SHA-1 signature/MAC feature | Historical 1,668 NIST byte-aligned SHA-2 AFT answers plus long/padding/ownership cases; existing HMAC vectors; current migrated tests are unexecuted |
| CR-DIS-03 and CR-DIS-04: exact entropy request domain and protected outputs | `CryptoRandomBytesRequest.output_length` is a `uint64` octet count; existing `CryptoRandomBytesResult` and purpose identity | `crypto_csprng::proto_helpers::RandomBytesRequest::{fill, generate, to_result}` with an explicitly borrowed native `SecureRandom` | Leaf `proto`, with existing platform/runtime requirements; no schema-selected provider or implicit RNG | `proto_helpers_tests`: metadata above uint32 on 64-bit targets without large allocation, checked 32-bit rejection, zero fill versus const-generic rules, exact ProtoJSON uint64 values and failures; unexecuted |
| CR-DIS-03 and CR-DIS-04: protected ownership, narrow providers, deterministic errors, evidence and delivery | Schema `CryptoErrorReason` and error envelopes; `CryptoNativeKeyCapabilities`; provider/material policy query outputs; descriptor-owned dimensions and limits | Shared `crypto_core::CryptoError`; total owner-local conversions and explicit provider/entropy traits; no private-state serialization | Optional root `operation-response`, leaf `proto` / core `protobuf` only for selected adapters; minimal schema constants remain backend-free | Identity/reason parity, invalid selectors, retained unknown fields, optional presence, ownership and provider-failure sources; current native/WASM/mobile compilation and runtime status below |
| CR-DIS-05: DIS 12.8, certificate-validation text 12.8.3 and normative Annex B; certificate/CRL ECDSA | `CryptoEcdsaInput` explicit message/prehash branches, `CryptoEcdsaSignOptions`, `CryptoEcdsaVerifyRequest`; `CryptoEcdsaSignatureTranscodeRequest` and `CryptoEcdsaPublicKeyValidationRequest` | `ecdsa_explicit::verify`, `der_to_fixed`, `fixed_to_der`; `contract::verify` and `format_contract::{transcode_signature, validate_public_key}` | `ecdsa-explicit`, selected Brainpool feature, `operation-response` for adapters | Existing 21 issuer-curve/hash combinations and 42 certificate/CRL answers; exact TBS mutation, digest width, encoding confusion, leading-zero/high-S cases; new P-256/adapter sources unexecuted |
| CR-DIS-05: Annex B / RFC 5280 4.2.1.2 method (1); legacy subject key identifier only | `CryptoSubjectKeyIdentifierRequest` / `CryptoSubjectKeyIdentifierResult` | `key_identifier::subject_key_identifier_sha1` and `key_identifier::contract::derive` | Separate `key-identifier-sha1`; add `operation-response` for schema adapter | Existing fourteen independent identifiers across seven curves, wrong-span/prefix/framing cases; `key_identifier_contract_tests` adds exact-byte, wire, bounds, modifier and clearing-owner sources |

These APIs expose primitives. The caller selects the permitted certificate
profile and interprets validated OIDs; a successful primitive operation does
not perform those acceptance checks.

The curve-aware conversion functions remain crypto interfaces. Strict DER
syntax is decoded by published `reallyme-codec` 0.3.4 with defaults disabled
and only its `der` feature enabled. Crypto retains scalar widths, nonzero and
subgroup-order checks, signature verification and high-S policy. Existing
conversion function names remain available; their 0.4 errors use the canonical
schema reason contract below. Tests enable the
parser dependency's BER feature separately to verify that feature unification
does not relax the DER boundary.

## Canonical 0.4 error and ownership boundary

`crypto_core::CryptoError` is the shared validated `thiserror` type. It contains
one known, nonzero schema `CryptoErrorReason`; the generated constants and
`reason()` replace former leaf-specific nested variants. Area names such as
`EcdsaError`, `Ed448Error`, `HpkeError` and `P256BaseError` are aliases of this
same type. The zero sentinel and unknown numeric reasons cannot construct a
native failure. No error carries caller bytes, arbitrary strings or dependency
diagnostic text.

An unsupported or disabled algorithm uses `CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM`
(200); an unsupported selected backend is a distinct reason (201). Invalid
signature (120), MAC/equality verification failure (121), authenticated-decryption
failure (122) and backend failure remain distinct. Exact failure precedence is
owned by the selected API, including its validation before a provider call.
Structured protobuf errors preserve the reason. Existing C/WASM numeric statuses
remain coarse projections with unchanged numeric values.

Sensitive generated transport owners clear their retained byte and unknown-field
storage on drop and through guarded mutation paths. Bytes moved from public
fields become caller-owned; direct replacement of a public vector also requires
the caller to clear its old storage. Prefer guarded setters and `Message::clear`.
Their required transport `Clone` does not make a native private key or live
HPKE context cloneable: copied transport buffers have independent
cleanup obligations. Explicit generated cleanup is `buffa::Message::clear`, not
an assumed `Zeroize` implementation. Native secret owners retain their own
`Zeroize`/`ZeroizeOnDrop` or secrecy contracts. A present empty message and an
absent input are distinct; unknown modifiers cannot silently change a primitive.

The completed [current API reconciliation](schema-contract-reconciliation.md)
links the compiler-visible API and all 2,670 frozen declarations to explicit
source/schema or native-representation dispositions. Standalone native adapters,
root execution routes, protected owners, borrowed storage and injected providers
remain distinct; an enum or DTO declaration alone does not make an API wire-callable.

## Related group and RSA contracts

Related group and RSA operations are separate primitive contracts; their
presence does not select a reader protocol or expand ISO algorithm policy:

| Operation | Rust interface and feature | Evidence |
| --- | --- | --- |
| Supplied-base operations in seven EC and three RFC 5114 DH domains | `prime_groups::{PrimeGroup, GroupScalar, GroupElement}`; `prime-groups`; standalone scalar/element/domain/multiplication/reduction requests through `prime_groups::contract` with `operation-response` | Historical nine-function native/WASM execution; current `prime_groups` and `prime_group_native_contract_tests` sources cover independent parameters, exact encodings, subgroups, bounded entropy and protected owners; migrated execution pending |
| Exact-width RSA public representative and modulus complement | `crypto_rsa::{rsa_public_representatives, RsaPublicKeyDerEncoding, RsaPublicRepresentatives}`; existing RSA leaf, with no backend feature required; standalone `CryptoRsaPublicRepresentativesRequest/Result` adapters with leaf `proto` | Historical eighty-four independent integer answers; current SPKI/PKCS#1, 1024–8192-bit, typed width/range/key and ownership sources remain unexecuted after migration |
| Raw secp256k1 ECDH with exact scalar and peer encoding | `CryptoSecp256k1AgreementRequest` → `crypto_secp256k1::proto::derive_shared_secret` → existing `CryptoNativeAgreementResult`; leaf `proto` plus `native` or `wasm` | Six existing published scalar×G coordinate answers, including a leading-zero x-coordinate; exact invalid scalar/uncompressed SEC1 cases and actual-drop ownership regressions; unexecuted |
| SHAKE256 variable-width expansion | `CryptoShake256ExpandRequest(input, uint64 output_length)` → `crypto_sha3::proto::expand_into`; caller may supply `CryptoShake256ExpandResult.output` as its final clearing destination; leaf `proto` | Eight unchanged vendored NIST AFT cases, zero/arbitrary widths, mismatch without output mutation, exact uint64 ProtoJSON and clearing-owner sources; unexecuted |

RSA representatives expose `s^e mod n` and its modulus complement in protected
owners. They do not interpret padding, validate a signature scheme or establish
trust. The caller must select and validate its protocol's complete signature
format. Existing RSA verification interfaces retain their contracts.

Raw secp256k1 agreement remains a distinct primitive from the seven explicit
NIST/Brainpool curves and from a complete HPKE suite. It requires a 32-byte
scalar and exactly 65-byte uncompressed SEC1 peer key, returning the 32-byte
big-endian raw x-coordinate. Compressed, hybrid, infinity and off-curve encodings
retain the native rejection policy. Its native secret now has an actual
`Drop` implementation calling `Zeroize`; a marker alone previously did not
clear its plain array. Final storage is initialized before the raw-byte copy.

SHAKE256 retains the native zero-length and arbitrary-width borrowed-output
domain. The adapter checks `uint64`→`usize`, exact destination length and unknown
modifiers before mutation. It does not allocate the requested output; callers
choose resource bounds and supply existing clearing storage. RNG request lengths
likewise preserve native 64-bit size semantics with checked 32-bit rejection.
Borrowed fill, const-generic protected generation and explicit injected entropy
remain distinct; a serialized output is not accepted as fresh randomness.

The standalone HKDF request binds its explicit output length to native `N`
through `HkdfNativeDeriveInputs<N>`. Its `derive` returns the existing protected
`HkdfOutput<N>`; `derive_result` copies fallibly into the final clearing schema
result only after native success. SHA-256, SHA-384 and optional SHA3-256 retain
their existing admitted widths, limits and typed errors. Salt absence versus
present-empty and exact `info` bytes are preserved. Existing root execution
profiles remain 16/24/32/48/64 bytes; representing other admitted native widths
does not add root operations or providers.

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

The standalone native key-agreement generation contract retains its existing
exportable `CryptoKeyPair` result and encoding: X25519 public bytes are 32 octets,
while its NIST public keys use the leaves' compressed SEC1 representation.
This differs from the explicit ECDSA owner interface's uncompressed public-key
contract described by the curve table. The adapter preserves the supplied KeyAgreement identity and
never routes generation through a signature or multikey policy.

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

Commands below illustrate consumer profiles for the 0.4.0 source tree, with
defaults disabled. Completed compilation checks and their exact scope are
recorded in the validation table; these recipes are not a runtime report:

```sh
cargo check --locked -p reallyme-crypto --no-default-features --features brainpool,ed448,key-identifier-sha1
cargo check --locked -p reallyme-crypto --no-default-features --features brainpool,ed448,key-identifier-sha1,operation-response
cargo check --locked -p reallyme-crypto --target wasm32-unknown-unknown --no-default-features --features brainpool,ed448,key-identifier-sha1,operation-response
cargo check --locked -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm
cargo check --locked -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm,proto
cargo check --locked -p reallyme-crypto-hpke --target wasm32-unknown-unknown --no-default-features --features base-p256-aes128gcm,proto
cargo check --locked -p reallyme-crypto-x448 --no-default-features --features native,proto
cargo check --locked -p reallyme-crypto --no-default-features --features prime-groups,operation-response
cargo check --locked -p reallyme-crypto-rsa --no-default-features --features proto
cargo check --locked -p reallyme-crypto --no-default-features --features native,x25519,operation-response
cargo check --locked -p reallyme-crypto-secp256k1 --no-default-features --features native,proto
cargo check --locked -p reallyme-crypto-sha3 --no-default-features --features proto
cargo check --locked -p reallyme-crypto-csprng --no-default-features --features proto
```

Use the root `wasm` or the selected leaf's `wasm` feature where its execution
lane requires it. Portable explicit ECDSA/Brainpool and Ed448 features compile
independently of the root `native`/`wasm` umbrellas. `operation-response` forwards
metadata features only to already selected leaves. HPKE's fixed profile selects
its concrete backend components without selecting every HPKE suite; leaf `proto`
adds the standalone schema boundary. Metadata-only `proto`/identity support does
not make an unselected algorithm executable.

Relevant runtime commands, not executed for this migration, include:

```sh
cargo test --locked -p reallyme-crypto --no-default-features --features brainpool,ed448,key-identifier-sha1,operation-response --test ecdsa_explicit_tests --test ed448_tests --test key_identifier_tests --test ecdsa_native_contract_tests --test ed448_native_contract_tests --test key_identifier_contract_tests
cargo test --locked -p reallyme-crypto-hpke --no-default-features --features base-p256-aes128gcm,proto --lib --test proto_recipient_lifecycle_tests --test proto_seal_rng_tests
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test --locked --release -p reallyme-crypto-hpke --target wasm32-unknown-unknown --no-default-features --features base-p256-aes128gcm,proto --lib --test proto_recipient_lifecycle_tests --test proto_seal_rng_tests
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

## Current 0.4.0 validation status

No runtime test execution is claimed for the schema/error/API migration. New
parity, malformed-input, optional-presence, provider-failure and cleanup tests
are source coverage until executed against the final 0.4.0 tree.

| Gate | Migration checkpoint `e0368ca60ab68eb710b6cf5cf5a46b66fdbaf4c4` |
| --- | --- |
| Native workspace Clippy, all targets/all features, warnings denied | Passed |
| Full WASM workspace check, all targets/all features, warnings denied | Passed for `wasm32-unknown-unknown`, excluding native FFI and the two private native maintenance tools |
| Strict Rustdoc/compiler capture, warnings denied | Passed: 45 native and 42 WASM targets; 3,617 declaration/exposure records and 3,511 export edges captured, with no missing compiler roots |
| Semantic reconciliation of current compiler-visible API against schema contracts | Complete within the [documented scope](schema-contract-reconciliation.md): no unresolved supported product items; 47 explicit private-tooling records; native APIs are not universally wire-callable |
| Narrow WASM reader all-target check, warnings denied | Passed for the portable reader profile |
| Narrow HKDF and HMAC all-target checks, warnings denied | Passed: HKDF `proto,sha3` on WASM, HKDF `proto` without SHA3 on native, and native HMAC |
| Seven mobile library target compiles, warnings denied | Passed: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android` |
| Buf lint/breaking against the pinned published baseline, TypeScript build, hardening idempotence, maintenance freshness, Actionlint and static CI policy | Passed |
| Dependency policy | Offline Cargo Deny passed; registry versions, sources and checksums unchanged |
| Native/WASM runtime known answers, negative cases, ownership/conformance and property/fuzz checks | Not executed for this migration |
| Swift, Kotlin and TypeScript facade/device tests | No new migration runtime evidence or provider routes claimed |
| Versioned package publication | 0.4.0 unpublished; SDK artifact versions and existing published packages remain 0.3.17 |

Compilation and generated-code checks establish their specific source and
schema properties. They do not replace execution of cryptographic known
answers, negative cases, cleanup paths or platform integration.

### Subsequent RSA and feature review

Implementation commit `e22f15e82e1e26fa625787234e28581c9eded9f6` guards RSA
finalized hash arrays and the message/PSS/MGF1 digest vectors. MGF1 retains its
clearing owner while borrowing each block. These private changes preserve the
public Rust API, exact byte concatenation and independent hash/salt selection;
allocation failure uses the existing typed backend error. The schema, generated
code, package manifests, lockfiles and Rust toolchain pins are unchanged.

Three disabled-provider test files also now use the canonical 0.4 errors without
stale imports or retired variants. The existing backendless CI step compiles
all targets for isolated `operation-response` and `dispatch` profiles. Its
combined graph includes `dispatch`. The existing RSA WASM invocation includes
library tests so the new ownership regressions are discoverable there. No new
workflow or job is introduced.

| Follow-up check | Result for the reviewed implementation |
| --- | --- |
| Native workspace Clippy, all targets/all features | Passed with warnings denied |
| Declared Rust 1.96.0 minimum, all-feature workspace check | Passed; active development toolchain remains 1.100.0 |
| Exact CI WASM workspace profile, defaults disabled | Passed with warnings denied |
| RSA WASM all-target checks with and without `proto` | Passed with warnings denied; test sources compiled, not executed |
| Bare root, isolated `operation-response` and `dispatch`, and exact combined backendless CI profile | Passed with warnings denied; isolated profiles include all targets |
| Seven mobile reader-library targets listed above | Passed with warnings denied; no installation or device execution |

The compiler inventory remains bound to its original checkpoint; these private
implementation and test/CI repairs do not constitute a new compiler-graph
capture. All runtime, known-answer, ownership, SDK and device regression
execution remains outstanding. Published packages and artifact versions remain
unchanged.

## Historical runtime and compilation evidence

The following results belong to **pre-migration, 0.3.17-versioned source
checkpoints**. They are retained as primitive-engine regression history, not
relabelled as 0.4.0 results. The later checkpoint incorporated prime groups,
RSA representatives and Codec 0.3.4 before the canonical schema/error migration.
The physical-device checkpoint predates those additions and that codec
integration. Neither checkpoint validates subsequent ownership or schema changes.

| Environment / pre-migration checkpoint | Recorded result | Scope |
| --- | --- | --- |
| Native ARM64 macOS, Rust 1.100.0; later checkpoint with Codec 0.3.4 | 920 native and 990 all-feature workspace tests passed, with 17 existing skips per profile; strict Clippy, API compatibility and independent answers; optional provider ran with pinned OpenSSL 4.0.3 | Historical primitive/default-profile regression only; 0.4.0 deliberately changes the Rust error API |
| Rust 1.96.0; later checkpoint | All-feature workspace compilation | Historical minimum-version compilation |
| WASM / Node runner; later checkpoint | 58 functions across reader primitives, prime groups, RSA representatives, P-256 conversions and HPKE; separate SHA-2 NIST execution passed; HPKE included the 16 MiB maximum record | Historical runner execution; no browser integration claim |
| iOS 27.0.1 physical ARM64 device, Rust 1.100.0; earlier checkpoint | 100 functions covering seven ECDSA/ECDH curves, ordinary Ed448, identifiers, HPKE, SHA-2 NIST and existing Ed25519/X25519/X448/HMAC/HKDF/AES-GCM suites | Rust engines in signed isolated applications; predates group/RSA/Codec additions and the 0.4.0 migration; SDK routing separate |
| iOS 26.5 ARM64 simulator; earlier checkpoint | Portable reader, HPKE and SHA-2 execution | Historical simulator evidence only |
| Android 17 / API 37 physical ARM64 device and Android 16 / API 36 ARM64 emulator, Rust 1.100.0; earlier checkpoint | Same 100 functions, including all three direct RFC 5869 SHA-256 answers | Historical ARM64 Rust engine execution; predates group/RSA/Codec additions and the 0.4.0 migration |
| `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`; later checkpoint | All three portable configurations compiled; optional pinned OpenSSL 4.0.3 compilation checked | Historical compilation; no x86-64 simulator runtime execution |
| `aarch64-linux-android`, `armv7-linux-androideabi`, `i686-linux-android`, `x86_64-linux-android`; later checkpoint | All four portable configurations compiled with NDK 29.0.14206865 and API 24 link settings; optional pinned OpenSSL 4.0.3 compilation checked | Historical compilation; recorded Android runtime execution covers ARM64 only |

Earlier Swift, Kotlin and TypeScript facade suites remain evidence only for
their tested source and existing provider routes. Regenerating schema bindings
or compiling Rust targets does not establish new SDK route coverage. No device
installation, execution or new mobile evidence is part of this migration record.

## Ownership and delivery limits

`EcdsaKey`, `Ed448Key` and `P256RecipientKey` use protected storage, clear on
drop and offer no implicit private export. Existing X448 and other legacy leaf
accessors retain their established explicit byte-access contracts; the schema
adapters do not create new private-key result fields. Plaintext and entropy
buffers are zeroizing owners. Borrowed source buffers remain the caller's cleanup
responsibility. Backend and compiler copies have the limitations described in
`SECURITY_MEMORY_MODEL.md`. HKDF expansion writes directly into its clearing
output owner, including error exits, while retaining exact caller-supplied salt
and info bytes and propagating canonical 0.4 errors.

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

The historical checkpoints exercised all seven ECDSA/ECDH curves, ordinary
Ed448, key identifiers and bounded HPKE in portable native and WASM lanes.
Optional native providers were tested separately at those checkpoints. Current
0.4.0 runtime and mobile compilation status remains as stated above. The new
standalone Rust contracts do not add SDK provider routes or renumber existing
serialized identifiers.

JSON cleanup has a separate ownership boundary. Generated sensitive transport
owners and trusted JWK values clear buffers and strings under their control.
When a deserializer transfers an owned string, the visitor guards it; borrowed
input and escaped-string scratch retained inside serde or another deserializer
remain under that implementation's control. Call-site owners cannot erase
those internal copies. Managed-runtime, allocator, compiler and register copies
have the distinct limits in [SECURITY_MEMORY_MODEL.md](../SECURITY_MEMORY_MODEL.md).
This does not close the accepted primefield source-buffer finding above.

Borrowed/shared Buffa views retain caller- or dependency-owned backing storage.
Hardening normal owned decode paths does not validate arbitrary hand-constructed
or manually altered malformed view state. These remain caller/upstream ownership
and representation limits; no exploit or upstream repair is claimed here.

SHA3-224/384/512 now finalize directly into their final clearing owners, matching
the existing SHA3-256 path. The three HMAC authentication helpers immediately
guard finalized tag storage with private clearing owners; verification, tag
bytes and public APIs are unchanged. These changes and the secp256k1 native drop
repair have unexecuted ownership regressions and remain separate from the earlier
SHA-2 finding and the accepted primefield serialization gap.

The three SHA-2 one-shot leaves now use the existing block compression and
padding engines with protected state, padding buffers and output owners.
They bypass the dependency's unguarded fixed-output temporary; no dependency
patch or change to FIPS SHA-2 output semantics is required. That earlier leaf
finding is separate from unchanged fixed-output wrappers used by other consumers. The upstream
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

## Remaining requirements and delivery

The CR-DIS-01/02/05 primitive APIs and named schema adapters are represented
above, with the public surface reconciled at the recorded checkpoint in the
[schema-contract report](schema-contract-reconciliation.md). The subsequent
private RSA review has its own compilation results above. Passed Clippy,
full/narrow WASM, HKDF/HMAC, seven mobile-library and strict Rustdoc checks
establish compilation, not runtime behavior. Newly added parity, known-answer,
negative-input, ownership and conformance sources remain unexecuted. Applicable
runtime, property/fuzz, SDK and platform validation remain release requirements;
no new device execution is claimed.

The accepted primefield serialization temporary leaves the corresponding
CR-DIS-03 intermediate-cleanup requirement open for affected providers. The
BP512 full-order certificate and deserializer-internal memory limits remain
separate audit limits; no local dependency fork or arithmetic replacement is
claimed. Earlier defect requests retain their separate tracking rather than
being closed by schema coverage or this compatibility matrix.

Coordinated 0.4.0 package delivery remains pending and publication requires its
own repository authorization. Full reader conformance still requires protocol
and trust-layer validation outside these primitives. ZKP transport does not
select a proof system; proof-system implementation, network/status processing,
RICAL policy and reader CBOR remain separate contracts.

## Exact source package versions

All entries below are source manifests, not evidence of publication. The three
non-publishable packages retain version alignment for local builds/artifacts.
The workspace also contains two private maintenance tools at version 0.0.0;
they are not among these 44 version-aligned packages. The fuzz workspace is
likewise not a release package.

| Rust package | Source version | Registry publication enabled |
| --- | --- | --- |
| `crypto-conformance-vectors` | 0.4.0 | No |
| `crypto-ffi` | 0.4.0 | No |
| `reallyme-crypto` | 0.4.0 | Yes |
| `reallyme-crypto-aes-kw` | 0.4.0 | Yes |
| `reallyme-crypto-aes256-gcm` | 0.4.0 | Yes |
| `reallyme-crypto-aes256-gcm-siv` | 0.4.0 | Yes |
| `reallyme-crypto-argon2id` | 0.4.0 | Yes |
| `reallyme-crypto-chacha20-poly1305` | 0.4.0 | Yes |
| `reallyme-crypto-concat-kdf` | 0.4.0 | Yes |
| `reallyme-crypto-constant-time` | 0.4.0 | Yes |
| `reallyme-crypto-core` | 0.4.0 | Yes |
| `reallyme-crypto-csprng` | 0.4.0 | Yes |
| `reallyme-crypto-dispatch` | 0.4.0 | Yes |
| `reallyme-crypto-ed25519` | 0.4.0 | Yes |
| `reallyme-crypto-hkdf` | 0.4.0 | Yes |
| `reallyme-crypto-hmac` | 0.4.0 | Yes |
| `reallyme-crypto-hpke` | 0.4.0 | Yes |
| `reallyme-crypto-jwk` | 0.4.0 | Yes |
| `reallyme-crypto-jwk-multikey` | 0.4.0 | Yes |
| `reallyme-crypto-kmac` | 0.4.0 | Yes |
| `reallyme-crypto-ml-dsa-44` | 0.4.0 | Yes |
| `reallyme-crypto-ml-dsa-65` | 0.4.0 | Yes |
| `reallyme-crypto-ml-dsa-87` | 0.4.0 | Yes |
| `reallyme-crypto-ml-kem-1024` | 0.4.0 | Yes |
| `reallyme-crypto-ml-kem-512` | 0.4.0 | Yes |
| `reallyme-crypto-ml-kem-768` | 0.4.0 | Yes |
| `reallyme-crypto-p256` | 0.4.0 | Yes |
| `reallyme-crypto-p384` | 0.4.0 | Yes |
| `reallyme-crypto-p521` | 0.4.0 | Yes |
| `reallyme-crypto-pbkdf2` | 0.4.0 | Yes |
| `reallyme-crypto-poseidon2` | 0.4.0 | Yes |
| `reallyme-crypto-proto` | 0.4.0 | Yes |
| `reallyme-crypto-rsa` | 0.4.0 | Yes |
| `reallyme-crypto-secp256k1` | 0.4.0 | Yes |
| `reallyme-crypto-sha2` | 0.4.0 | Yes |
| `reallyme-crypto-sha2-256` | 0.4.0 | Yes |
| `reallyme-crypto-sha3` | 0.4.0 | Yes |
| `reallyme-crypto-sha3-256` | 0.4.0 | Yes |
| `reallyme-crypto-signer` | 0.4.0 | Yes |
| `reallyme-crypto-slh-dsa` | 0.4.0 | Yes |
| `reallyme-crypto-wasm` | 0.4.0 | No |
| `reallyme-crypto-x-wing` | 0.4.0 | Yes |
| `reallyme-crypto-x25519` | 0.4.0 | Yes |
| `reallyme-crypto-x448` | 0.4.0 | Yes |

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
