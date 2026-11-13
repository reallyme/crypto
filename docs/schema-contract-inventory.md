# Protobuf contract inventory

Snapshot: 2026-11-13, local commit `853abd1c58df84647b761506e146c7b07288c2bb`. No migration is included in this snapshot.

The local ignored `AGENTS.md` now requires schema-first public operations,
enums, reasons, request/result/options/policy structures, one total tested enum
conversion, one schema reason per error variant, reserved retired identifiers,
and successful Buf lint/breaking checks. Existing callers and protected secret
owners remain unchanged while this inventory is reviewed.

## Scope and evidence

The export inventory uses Rust 1.100.0 rustdoc JSON for all 45 workspace library
targets on the native host, and the 42 applicable library targets on
`wasm32-unknown-unknown`, with all features and hidden public items included.
The native inventory includes the C/JNI ABI. The two private build/audit tools
are identified separately. The WASM pass excludes those tools and the native
FFI crate. These are compiler/documentation builds, not executed tests or mobile
device runs.

The canonical schema contains 23 enums, 83 messages, and 33 `CryptoErrorReason`
values including `UNSPECIFIED`. Its SHA-256 is
`b007317444d9e0f24c22afc28f743e711d3b6b74e105ae8c751d6e2f27e33501`.
The source/package version remains 0.3.17; unpublished local additions are not
claimed to be available in the registry package.

The declaration ledger contains **2,670 source declarations**, including
public variants, fields, methods, associated items, and constants. It merges
aliases of a declaration instead of counting each alias as a different
vocabulary. It excludes generator-produced message implementations, derived
trait boilerplate, and upstream dependency declarations. A separate ledger
records **1,230 re-export declarations** and another records **21 explicit
`From`/`TryFrom` implementations**. Conversion helper functions also appear in
the main ledger and in the locations below.

| File | Contents |
|---|---|
| [Complete declaration inventory](schema-contract-inventory.csv) | Every inspected handwritten public declaration, public paths, source/line, category, closest schema counterpart, fields/variants/value, and observed lanes. |
| [Export inventory](schema-contract-exports.csv) | Public aliases and re-exports, including umbrella and leaf package surfaces. |
| [Conversion inventory](schema-contract-conversions.csv) | Explicit conversion trait implementations; helper conversion tables are described below. |
| [Error inventory](schema-contract-errors.csv) | Every inventoried error/reason variant, existing mapping location, and mapping gaps. |
| [Source-only cross-check](schema-contract-source-only.csv) | All 15 `pub` candidates missing from compiler-visible Rust exports, with their disposition. |

A schema correspondence in the ledger is an association, not proof of identical
parameter domains, ownership, or behavior. `native-representation` identifies
Rust owners and borrowing helpers for schema-backed bytes/operations; it does
not grant an exception to the schema-first rule. Their validation constraints,
public constructors and lifecycle methods remain part of the parity review.
`extended-contract` means that a related schema operation exists but cannot
express all of the native API. `unrepresented` means no operation or structure
correspondence was established. Namespace containers, conformance-only APIs,
and private tooling are explicitly distinguished from product contract gaps.

The source-only cross-check finds seven JavaScript binding exports (four AES
entrypoints and three conformance-only deterministic ML-KEM entrypoints) that
are not Rust root re-exports. Two more candidates are alternate implementations
of already inventoried APIs. The remaining six candidates are two inaccessible
HPKE constants, two private portable-curve markers, generated package metadata,
and a private audit-tool proof fixture. They are not omitted public Rust API
gaps. The JavaScript exports still require schema parity at their binding
boundary.

## Declaration categories

These counts include fields, variants and methods; they are not counts of
independent vocabularies.

| Category | Declaration rows |
|---|---:|
| `adapter` | 221 |
| `conformance-only` | 36 |
| `conversion` | 15 |
| `duplicate-errors` | 321 |
| `duplicate-vocabulary` | 185 |
| `extended-contract` | 304 |
| `namespace` | 175 |
| `native-representation` | 632 |
| `rust-only-constant` | 309 |
| `tooling` | 47 |
| `unrepresented` | 425 |

## Algorithm, suite, curve and encoding identity

| Area | Independently maintained Rust vocabulary | Existing schema or missing contract |
|---|---|---|
| Core asymmetric identity | `Algorithm` | Operation-agnostic key identity is projected separately to `SignatureAlgorithm`, `KeyAgreementAlgorithm`, and `KemAlgorithm`; suite-only identifiers do not fit this enum. |
| Symmetric and digest identity | `AeadAlgorithm`, `HashAlgorithm`, `MacAlgorithm` | Schema enums exist; AEAD/hash have hand-written bridges, while MAC is matched inside the operation adapter. |
| KDF identity and profiles | Core `KdfAlgorithm`, `KdfProfile`, `HkdfHash`; leaf `HkdfSuite`, `Pbkdf2Prf`, `Argon2Profile`, `Argon2KdfVersion` | `KdfAlgorithm` and `Argon2idKdfVersion` cover only part of these concepts. Native HKDF-SHA3-256 has no schema KDF selector. |
| Key-wrap identity | Core `KeyWrapAlgorithm`, `KeyWrapOperation` | Schema has key-wrap suites and separate wrap/unwrap requests; Rust maintains another vocabulary. |
| RSA identity/options | `RsaHash`, `RsaPublicKeyDerEncoding`, `RsaPssParams` | DER encoding is schema-defined, but the leaf enum is separate. Schema RSA suites fix message/MGF1 hash and salt length; native PSS accepts independent parameters. |
| Explicit ECDSA | `EcdsaCurve`, `EcdsaHash`, `EcdsaInput`, `EcdsaEncoding`, `EcdsaKey`, `OpaqueEcdsaSigner` | Missing explicit seven-curve/hash cross-product, message/prehash mode, DER versus fixed signature encoding, software/opaque key source and lifecycle contracts. Existing signature selectors cover fixed suites only. |
| Ordinary Ed448 | `Ed448Operation`, `Ed448Key`, `OpaqueEd448Signer` | No Ed448 signature selector, software/opaque key-source options, or matching operation inputs/results. |
| Prime groups | `PrimeGroup`, `GroupScalar`, `GroupElement` | All ten group identities and scalar/group arithmetic, parameter inspection, encoding and field-map operations are absent. |
| HPKE component identity | Native `HpkeKemId`, `HpkeKdfId`, `HpkeAeadId`, `HpkeSuite`, `HpkeComponentSupport` | Schema has component enums and suite triple; native registry constants, named suites, support tables and support states are maintained separately. |
| Family/operation identity | `OperationFamily`, `PlatformKeyOperation`, `ProviderOperation`, `SignatureOperation`, `RngOutputKind` | Multiple independent operation vocabularies; constant-time and RNG operation families are missing from executable messages. |
| Public-key formats and JWKs | `Jwk`, concrete JWK structures, `JwkOptions`; multikey, SEC1, DER/PEM, low-S and handle helpers | Byte envelope/algorithm messages exist, but format/options/import/export/normalization operations and typed optional metadata are not fully defined in the schema. |
| Other primitives | Standalone X448, Poseidon2, RNG and constant-time APIs | HPKE X448 registration does not expose standalone X448; these standalone primitive operations are absent. |

There are no public Rust enums literally named `ContentMode` or `KeySource` in
this snapshot. Those concepts are currently expressed through `EcdsaInput`,
message-versus-digest function names, software key owners, opaque-provider
traits, and platform handles. Their absence as named enums does not make the
underlying contract drift disappear.

## Error vocabularies and observed losses

Most native error/reason enums are unnumbered; they repeat concepts rather than
assigning independent per-algorithm numeric ranges. The schema owns primitive
100-199, provider 200-299 and backend 300-399. These ranges are repeated in
`crates/proto/src/wire/limits.rs`. The C ABI also exposes 0/negative status codes,
and the raw WASM adapter maintains its own private 1-5 error-code vocabulary.
These are separate projections that need explicit schema-owned contracts and
compatibility handling, not silent numeric renumbering.

The following issues are source findings; no production repair is included:

- `CryptoError` has 16 outer variants. Eleven delegate to nested failure kinds,
  so one outer `thiserror` variant can currently produce several reason codes.
  `OperationError::{Primitive,Provider,Backend}` has the same issue. Transparent
  dispatch and signer wrappers add another layer of projections.
- `map_operation_error` explicitly maps only `UnsupportedAlgorithm` among
  provider reasons; the remaining provider reasons fall through to
  `PROVIDER_UNAVAILABLE` (202), losing dedicated reasons such as randomness,
  key existence, access denial, authentication, cancellation and hardware state.
- That mapper turns `PrimitiveErrorReason::VerificationFailed` into
  `AUTHENTICATION_FAILED` (122), whereas the core MAC and constant-time mapper
  uses `VERIFICATION_FAILED` (121). These independently maintained projections
  disagree on the same shared vocabulary.
- The known-reason branch validator in `crates/proto/src/wire/error.rs` lists
  provider codes 200-203 but omits the schema-defined codes **204-210**:
  key exists, key not found, access denied, authentication required, user
  canceled, hardware unavailable and hardware rejected key. The public
  known-reason constructor therefore rejects valid schema/provider pairs.
- New ECDSA, Ed448, group, RSA-representative, key-identifier, digest and
  Poseidon2 errors do not have one generated reason accessor per variant.
- Existing wildcard fallbacks and manually maintained test lists do not prove
  that every present and future variant has exactly one canonical mapping.

The [error ledger](schema-contract-errors.csv) lists each native reason/error
variant individually. The enums are grouped below without treating diagnostic
context enums such as `AeadBackend` as error reasons.

| Public error/reason enum or wrapper | Variants or wrapper | Source |
|---|---|---|
| `crypto_core::AeadFailureKind` | InvalidKeyMaterial; LengthOverflow; ShortCiphertext; InvalidOutputLength; AuthenticationFailed; BackendFailure | [crates/crypto/core/src/error/aead.rs:34](../crates/crypto/core/src/error/aead.rs#L34) |
| `crypto_core::KdfFailureKind` | InvalidSecretLength; InvalidSaltLength; InvalidOutputLength; InvalidIterationCount; InvalidParams; DerivationFailed; ResourceLimitExceeded | [crates/crypto/core/src/error/kdf.rs:66](../crates/crypto/core/src/error/kdf.rs#L66) |
| `crypto_core::HkdfFailureKind` | InvalidIkmLength; InvalidDomainTagLength; InvalidDomainTagByte; LengthOverflow; InvalidOutputLength; ExpandFailed | [crates/crypto/core/src/error/kdf.rs:124](../crates/crypto/core/src/error/kdf.rs#L124) |
| `crypto_core::KeyWrapFailureKind` | InvalidKekLength; InvalidPlaintextLength; InvalidWrappedLength; LengthOverflow; IntegrityCheckFailed; BackendFailure | [crates/crypto/core/src/error/key_wrap.rs:51](../crates/crypto/core/src/error/key_wrap.rs#L51) |
| `crypto_core::MacFailureKind` | InvalidKeyLength; InvalidTagLength; VerificationFailed; BackendFailure | [crates/crypto/core/src/error/mac.rs:31](../crates/crypto/core/src/error/mac.rs#L31) |
| `crypto_core::RngFailureKind` | EntropyUnavailable; InvalidOutputLength | [crates/crypto/core/src/error/rng.rs:49](../crates/crypto/core/src/error/rng.rs#L49) |
| `crypto_core::ConstantTimeFailureKind` | LengthMismatch; NotEqual | [crates/crypto/core/src/error/rng.rs:69](../crates/crypto/core/src/error/rng.rs#L69) |
| `crypto_core::SignatureFailureKind` | BackendFailure; InvalidPrivateKey; InvalidPublicKey; InvalidSignature; InvalidMessage; KeyGenerationFailed; SecureEnclaveUnavailable; SecureEnclaveRejectedKey | [crates/crypto/core/src/error/signature.rs:60](../crates/crypto/core/src/error/signature.rs#L60) |
| `crypto_core::KeyAgreementFailureKind` | DeriveSharedSecretFailed; KeyGenerationFailed | [crates/crypto/core/src/error/signature.rs:98](../crates/crypto/core/src/error/signature.rs#L98) |
| `crypto_core::KemFailureKind` | KeyGenerationFailed; EncapsulateFailed; DecapsulateFailed | [crates/crypto/core/src/error/signature.rs:118](../crates/crypto/core/src/error/signature.rs#L118) |
| `crypto_core::CryptoError` | InvalidKey; InvalidAeadKeyLength; InvalidAeadNonceLength; InvalidCiphertextLength; AeadEncrypt; AeadDecrypt; Signature; KeyAgreementFailure; KemFailure; KeyWrap; Kdf; Hkdf; Mac; Rng; ConstantTimeComparison; Unsupported | [crates/crypto/core/src/error/taxonomy.rs:17](../crates/crypto/core/src/error/taxonomy.rs#L17) |
| `crypto_dispatch::AlgorithmError` | UnsupportedAlgorithm; UnsupportedAeadAlgorithm; UnsupportedHashAlgorithm; UnsupportedMacAlgorithm; InvalidKey; SignatureInvalid; Crypto | [crates/crypto/dispatch/src/error.rs:12](../crates/crypto/dispatch/src/error.rs#L12) |
| `crypto_signer::SignerFailureKind` | DispatchRejected | [crates/crypto/signer/src/error.rs:12](../crates/crypto/signer/src/error.rs#L12) |
| `crypto_signer::SignerError` | SignFailed | [crates/crypto/signer/src/error.rs:29](../crates/crypto/signer/src/error.rs#L29) |
| `crypto_signer::VerifierFailureKind` | SignatureInvalid; DispatchRejected | [crates/crypto/signer/src/error.rs:46](../crates/crypto/signer/src/error.rs#L46) |
| `crypto_signer::VerifierError` | VerifyFailed | [crates/crypto/signer/src/error.rs:67](../crates/crypto/signer/src/error.rs#L67) |
| `reallyme_crypto::ecdsa_explicit::EcdsaError` | UnsupportedCurve; UnsupportedProvider; InvalidPrivateKey; InvalidPublicKey; InvalidSignature; InvalidPrehashLength; AllocationFailed; RandomnessUnavailable; ProviderFailed | [crates/crypto/src/ecdsa_explicit.rs:97](../crates/crypto/src/ecdsa_explicit.rs#L97) |
| `reallyme_crypto::ed448::Ed448Error` | UnsupportedAlgorithm; UnsupportedOperation; InvalidPrivateKey; AllocationFailed; RandomnessUnavailable; InvalidPublicKey; InvalidSignature; ProviderFailed | [crates/crypto/src/ed448.rs:30](../crates/crypto/src/ed448.rs#L30) |
| `reallyme_crypto::key_identifier::KeyIdentifierError` | EmptyInput; InputTooLong | [crates/crypto/src/key_identifier.rs:32](../crates/crypto/src/key_identifier.rs#L32) |
| `reallyme_crypto::key_random::KeyRandomError` | Unavailable | [crates/crypto/src/key_random.rs:18](../crates/crypto/src/key_random.rs#L18) |
| `reallyme_crypto::operations::OperationError` | Primitive; Provider; Backend | [crates/crypto/src/operations/error.rs:15](../crates/crypto/src/operations/error.rs#L15) |
| `reallyme_crypto::operations::PrimitiveErrorReason` | MissingAlgorithm; MissingOperation; InvalidKey; InvalidPublicKey; InvalidPrivateKey; MalformedCiphertext; InvalidParameter; InvalidLength; LengthOverflow; VerificationFailed; InvalidSharedSecret; ResourceLimitExceeded | [crates/crypto/src/operations/error.rs:39](../crates/crypto/src/operations/error.rs#L39) |
| `reallyme_crypto::operations::ProviderErrorReason` | UnsupportedAlgorithm; ProviderUnavailable; RandomnessUnavailable; FallbackProhibited; PlatformUnavailable; KeyExists; KeyNotFound; AccessDenied; UserAuthenticationRequired; UserCanceled; HardwareUnavailable; HardwareRejectedKey | [crates/crypto/src/operations/error.rs:89](../crates/crypto/src/operations/error.rs#L89) |
| `reallyme_crypto::operations::BackendErrorReason` | InvalidOutput; PanicContained; Internal | [crates/crypto/src/operations/error.rs:139](../crates/crypto/src/operations/error.rs#L139) |
| `reallyme_crypto::prime_groups::GroupErrorReason` | InvalidLength; InvalidScalar; InvalidElement; Identity; GroupMismatch; UnsupportedMapping; InvalidFieldElement; RandomUnavailable; RandomExhausted; Allocation; Arithmetic | [crates/crypto/src/prime_groups/error.rs:10](../crates/crypto/src/prime_groups/error.rs#L10) |
| `reallyme_crypto::prime_groups::GroupError` | (error wrapper) | [crates/crypto/src/prime_groups/error.rs:49](../crates/crypto/src/prime_groups/error.rs#L49) |
| `crypto_hpke::base_p256::P256BaseError` | InvalidPrivateKey; InvalidPublicKey; InvalidEncapsulatedKey; InputTooLong; TruncatedCiphertext; AllocationFailed; RandomnessUnavailable; AuthenticationFailed; ProviderFailed | [crates/hpke/src/base_p256.rs:37](../crates/hpke/src/base_p256.rs#L37) |
| `crypto_hpke::base_p256::P256BaseRandomError` | Unavailable | [crates/hpke/src/base_p256.rs:76](../crates/hpke/src/base_p256.rs#L76) |
| `crypto_hpke::HpkeError` | UnsupportedKem; UnsupportedKdf; UnsupportedAead; UnsupportedSuite; InvalidPublicKey; InvalidPrivateKey; InvalidEncapsulatedKey; InvalidCiphertext; InvalidInputKeyMaterial; InvalidPsk; InvalidPskIdentifier; InvalidInfoLength; InvalidExporterLength; RandomnessUnavailable; LengthOverflow; SealFailed; OpenFailed; ExportFailed; KeyGenerationFailed; InvalidRandomness | [crates/hpke/src/error.rs:13](../crates/hpke/src/error.rs#L13) |
| `envelopes_jwk_multikey::JwkMultikeyError` | InvalidMultikey; UnsupportedAlgorithm; InvalidJwk; EncodingError | [crates/jwk-multikey/src/error.rs:12](../crates/jwk-multikey/src/error.rs#L12) |
| `envelopes_jwk::JwtError` | InvalidEnvelope; DuplicateMember; PrivateKeyMaterial; UnknownMember; InvalidMlDsa44Key; InvalidMlDsa65Key; InvalidP256Key; InvalidSecp256k1Key; InvalidEd25519Key; InvalidX25519Key; InvalidMlDsa87Key; InvalidMlKem512Key; InvalidMlKem768Key; InvalidMlKem1024Key; InvalidSlhDsaSha2128sKey; InvalidXWing768Key; UnsupportedKeyFormat; EncodingError; BackendUnavailable | [crates/jwk/src/error.rs:12](../crates/jwk/src/error.rs#L12) |
| `crypto_p256::P256Sha256DigestError` | InvalidLength | [crates/p256/src/sha256_digest.rs:72](../crates/p256/src/sha256_digest.rs#L72) |
| `crypto_poseidon2::Poseidon2ErrorReason` | InputTooLong; InvalidLength | [crates/poseidon2/src/hash.rs:40](../crates/poseidon2/src/hash.rs#L40) |
| `crypto_poseidon2::Poseidon2Error` | (error wrapper) | [crates/poseidon2/src/hash.rs:52](../crates/poseidon2/src/hash.rs#L52) |
| `reallyme_crypto_proto::convert::UnsupportedProtoAlgorithm` | (error wrapper) | [crates/proto/src/convert.rs:43](../crates/proto/src/convert.rs#L43) |
| `reallyme_crypto_proto::wire::CryptoWireError` | (error wrapper) | [crates/proto/src/wire/error.rs:32](../crates/proto/src/wire/error.rs#L32) |
| `reallyme_crypto_proto::wire::CryptoWireErrorValidationError` | UnspecifiedReason; BranchReasonMismatch; ReasonCodeOutOfRange | [crates/proto/src/wire/error.rs:44](../crates/proto/src/wire/error.rs#L44) |
| `crypto_rsa::RsaRepresentativeErrorReason` | PublicKey; Length; Range; Allocation; Arithmetic | [crates/rsa/src/representative.rs:17](../crates/rsa/src/representative.rs#L17) |
| `crypto_rsa::RsaRepresentativeError` | (error wrapper) | [crates/rsa/src/representative.rs:37](../crates/rsa/src/representative.rs#L37) |

## Remaining options, policy and lifecycle structures

The following public structs, traits and aliases are wholly missing or extend
the existing schema beyond its represented options. Every public member and
method is included separately in the declaration ledger.

| Rust declaration | Public fields, when present | Contract status | Source |
|---|---|---|---|
| `crypto_argon2id::DeriveKeyRequest` | profile; secret; salt | extended-contract | [crates/argon2id/src/derive.rs:14](../crates/argon2id/src/derive.rs#L14) |
| `crypto_argon2id::Argon2Caps` | mem_cap_kib; time_cost_cap; lanes_cap | extended-contract | [crates/argon2id/src/profile.rs:41](../crates/argon2id/src/profile.rs#L41) |
| `crypto_argon2id::Argon2ParamsProfile` | mem_kib; time_cost; lanes | extended-contract | [crates/argon2id/src/profile.rs:52](../crates/argon2id/src/profile.rs#L52) |
| `crypto_dispatch::GeneratedKeypair` | public_key; secret_key; public_key_multikey | extended-contract | [crates/crypto/dispatch/src/keypair.rs:13](../crates/crypto/dispatch/src/keypair.rs#L13) |
| `crypto_dispatch::ProviderDecision` | operation; algorithm; provider_kind; lane; disposition; reason; key_residency; key_copy_boundary; output_policy; fallback | unrepresented | [crates/crypto/dispatch/src/provider.rs:112](../crates/crypto/dispatch/src/provider.rs#L112) |
| `reallyme_crypto::ecdsa_explicit::EcdsaKey` | Protected owner, trait or alias; see member rows | extended-contract | [crates/crypto/src/ecdsa_explicit/key.rs:21](../crates/crypto/src/ecdsa_explicit/key.rs#L21) |
| `reallyme_crypto::ecdsa_explicit::OpaqueEcdsaSigner` | Protected owner, trait or alias; see member rows | extended-contract | [crates/crypto/src/ecdsa_explicit/sign.rs:11](../crates/crypto/src/ecdsa_explicit/sign.rs#L11) |
| `reallyme_crypto::ed448::OpaqueEd448Signer` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/ed448.rs:86](../crates/crypto/src/ed448.rs#L86) |
| `reallyme_crypto::ed448::Ed448Key` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/ed448/key.rs:20](../crates/crypto/src/ed448/key.rs#L20) |
| `reallyme_crypto::key_identifier::SubjectKeyIdentifier` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/key_identifier.rs:19](../crates/crypto/src/key_identifier.rs#L19) |
| `reallyme_crypto::key_random::KeyRng` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/key_random.rs:11](../crates/crypto/src/key_random.rs#L11) |
| `reallyme_crypto::hpke::HpkePskSenderSetupOutput` | encapsulated_key; context | unrepresented | [crates/crypto/src/operations/hpke.rs:56](../crates/crypto/src/operations/hpke.rs#L56) |
| `reallyme_crypto::hpke::HpkeSenderContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/operations/hpke.rs:73](../crates/crypto/src/operations/hpke.rs#L73) |
| `reallyme_crypto::hpke::HpkePskSenderContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/operations/hpke.rs:90](../crates/crypto/src/operations/hpke.rs#L90) |
| `reallyme_crypto::hpke::HpkeReceiverContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/operations/hpke.rs:102](../crates/crypto/src/operations/hpke.rs#L102) |
| `reallyme_crypto::prime_groups::GroupElement` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/prime_groups/element.rs:16](../crates/crypto/src/prime_groups/element.rs#L16) |
| `reallyme_crypto::prime_groups::GroupScalar` | Protected owner, trait or alias; see member rows | unrepresented | [crates/crypto/src/prime_groups/scalar.rs:24](../crates/crypto/src/prime_groups/scalar.rs#L24) |
| `reallyme_crypto::secret_material::MaterialPolicy` | owner; sensitivity; retention; zeroization; export; destruction | unrepresented | [crates/crypto/src/secret_material/policy.rs:88](../crates/crypto/src/secret_material/policy.rs#L88) |
| `reallyme_crypto::secret_material::OperationSecretMaterialPolicy` | input; output; request_wire; response_wire; output_material | unrepresented | [crates/crypto/src/secret_material/policy.rs:106](../crates/crypto/src/secret_material/policy.rs#L106) |
| `crypto_csprng::SecureRandom` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/rng.rs:9](../crates/csprng/src/rng.rs#L9) |
| `crypto_csprng::OsSecureRandom` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/rng.rs:17](../crates/csprng/src/rng.rs#L17) |
| `crypto_csprng::AeadNonce12` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:16](../crates/csprng/src/types.rs#L16) |
| `crypto_csprng::Argon2Salt16` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:34](../crates/csprng/src/types.rs#L34) |
| `crypto_csprng::Argon2Salt32` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:72](../crates/csprng/src/types.rs#L72) |
| `crypto_csprng::Aes256GcmKeyMaterial` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:109](../crates/csprng/src/types.rs#L109) |
| `crypto_csprng::MlKem1024Seed` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:141](../crates/csprng/src/types.rs#L141) |
| `crypto_csprng::MlDsa87Seed` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:173](../crates/csprng/src/types.rs#L173) |
| `crypto_csprng::RandomBytes` | Protected owner, trait or alias; see member rows | unrepresented | [crates/csprng/src/types.rs:205](../crates/csprng/src/types.rs#L205) |
| `crypto_ffi::status::CryptoStatus` | Protected owner, trait or alias; see member rows | unrepresented | [crates/ffi/src/status.rs:12](../crates/ffi/src/status.rs#L12) |
| `crypto_ffi::status::KeypairBuffers` | Protected owner, trait or alias; see member rows | unrepresented | [crates/ffi/src/status.rs:35](../crates/ffi/src/status.rs#L35) |
| `crypto_ffi::status::IntoKeypairResult` | Protected owner, trait or alias; see member rows | unrepresented | [crates/ffi/src/status.rs:39](../crates/ffi/src/status.rs#L39) |
| `crypto_hkdf::HkdfSha384Prk` | Protected owner, trait or alias; see member rows | extended-contract | [crates/hkdf/src/material.rs:99](../crates/hkdf/src/material.rs#L99) |
| `crypto_hkdf::DomainTag` | Protected owner, trait or alias; see member rows | unrepresented | [crates/hkdf/src/policy.rs:59](../crates/hkdf/src/policy.rs#L59) |
| `crypto_hpke::base_p256::P256BaseRng` | Protected owner, trait or alias; see member rows | extended-contract | [crates/hpke/src/base_p256.rs:69](../crates/hpke/src/base_p256.rs#L69) |
| `crypto_hpke::base_p256::P256BaseSealed` | enc; ciphertext | extended-contract | [crates/hpke/src/base_p256/crypt.rs:17](../crates/hpke/src/base_p256/crypt.rs#L17) |
| `crypto_hpke::base_p256::P256RecipientKey` | Protected owner, trait or alias; see member rows | extended-contract | [crates/hpke/src/base_p256/key.rs:15](../crates/hpke/src/base_p256/key.rs#L15) |
| `crypto_hpke::base_p256::P256BasePlaintext` | Protected owner, trait or alias; see member rows | extended-contract | [crates/hpke/src/base_p256/plaintext.rs:16](../crates/hpke/src/base_p256/plaintext.rs#L16) |
| `crypto_hpke::HpkePskReceiverSetupRequest` | suite; encapsulated_key; recipient_private_key; info; psk; psk_id | unrepresented | [crates/hpke/src/setup_receiver.rs:30](../crates/hpke/src/setup_receiver.rs#L30) |
| `crypto_hpke::HpkeReceiverContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/hpke/src/setup_receiver.rs:94](../crates/hpke/src/setup_receiver.rs#L94) |
| `crypto_hpke::HpkePskSenderSetupRequest` | suite; recipient_public_key; info; psk; psk_id | unrepresented | [crates/hpke/src/setup_sender.rs:36](../crates/hpke/src/setup_sender.rs#L36) |
| `crypto_hpke::HpkeDerandPskSenderSetupRequest` | suite; recipient_public_key; encapsulation_randomness; info; psk; psk_id | unrepresented | [crates/hpke/src/setup_sender.rs:51](../crates/hpke/src/setup_sender.rs#L51) |
| `crypto_hpke::HpkePskSenderSetupOutput` | encapsulated_key; context | unrepresented | [crates/hpke/src/setup_sender.rs:67](../crates/hpke/src/setup_sender.rs#L67) |
| `crypto_hpke::HpkeSenderContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/hpke/src/setup_sender.rs:124](../crates/hpke/src/setup_sender.rs#L124) |
| `crypto_hpke::HpkePskSenderContext` | Protected owner, trait or alias; see member rows | unrepresented | [crates/hpke/src/setup_sender.rs:156](../crates/hpke/src/setup_sender.rs#L156) |
| `envelopes_jwk::ed25519::Ed25519Jwk` | kty; crv; x; alg; use_; kid | extended-contract | [crates/jwk/src/ed25519.rs:26](../crates/jwk/src/ed25519.rs#L26) |
| `envelopes_jwk::JwkOptions` | alg; use_sig; use_enc; kid | extended-contract | [crates/jwk/src/jwk.rs:18](../crates/jwk/src/jwk.rs#L18) |
| `envelopes_jwk::EcJwk` | kty; crv; x; y; alg; use_; kid | extended-contract | [crates/jwk/src/jwk.rs:31](../crates/jwk/src/jwk.rs#L31) |
| `envelopes_jwk::OkpJwk` | kty; crv; x; alg; use_; kid | extended-contract | [crates/jwk/src/jwk.rs:53](../crates/jwk/src/jwk.rs#L53) |
| `envelopes_jwk::AkpJwk` | kty; alg; public_key; use_; kid | extended-contract | [crates/jwk/src/jwk.rs:77](../crates/jwk/src/jwk.rs#L77) |
| `envelopes_jwk::Jwks` | keys | extended-contract | [crates/jwk/src/jwk.rs:106](../crates/jwk/src/jwk.rs#L106) |
| `envelopes_jwk::mldsa87::MlDsa87Jwk` | kty; public_key; alg; use_; kid | extended-contract | [crates/jwk/src/mldsa87.rs:40](../crates/jwk/src/mldsa87.rs#L40) |
| `envelopes_jwk::mlkem1024::MlKem1024Jwk` | kty; public_key; alg; use_; kid | extended-contract | [crates/jwk/src/mlkem1024.rs:42](../crates/jwk/src/mlkem1024.rs#L42) |
| `envelopes_jwk::x25519::X25519Jwk` | kty; crv; x; alg; use_; kid | extended-contract | [crates/jwk/src/x25519.rs:53](../crates/jwk/src/x25519.rs#L53) |
| `crypto_p256::P256Sha256Digest` | Protected owner, trait or alias; see member rows | extended-contract | [crates/p256/src/sha256_digest.rs:35](../crates/p256/src/sha256_digest.rs#L35) |
| `crypto_poseidon2::Poseidon2Digest` | Protected owner, trait or alias; see member rows | unrepresented | [crates/poseidon2/src/hash.rs:21](../crates/poseidon2/src/hash.rs#L21) |
| `crypto_rsa::RsaPublicRepresentatives` | Protected owner, trait or alias; see member rows | unrepresented | [crates/rsa/src/representative.rs:70](../crates/rsa/src/representative.rs#L70) |
| `crypto_rsa::RsaPssParams` | message_hash; mgf1_hash; salt_len | extended-contract | [crates/rsa/src/types.rs:71](../crates/rsa/src/types.rs#L71) |
| `crypto_x448::X448PrivateKey` | Protected owner, trait or alias; see member rows | unrepresented | [crates/x448/src/material.rs:12](../crates/x448/src/material.rs#L12) |
| `crypto_x448::X448PublicKey` | Protected owner, trait or alias; see member rows | unrepresented | [crates/x448/src/material.rs:47](../crates/x448/src/material.rs#L47) |
| `crypto_x448::X448SharedSecret` | Protected owner, trait or alias; see member rows | unrepresented | [crates/x448/src/material.rs:82](../crates/x448/src/material.rs#L82) |

The missing provider policy includes `ProviderKind`, `ProviderLane`,
`KeyResidency`, `KeyCopyBoundary`, `ProviderOutputPolicy`, `ProviderPolicyReason`,
`ProviderDisposition`, `FallbackPolicy`, and `ProviderDecision`.
The missing secret-material vocabulary includes `BufferOwner`,
`DestructionPolicy`, `ExportPolicy`, `OutputMaterial`, `RetentionPolicy`,
`SecretSensitivity`, `ZeroizationPolicy`, `SecretMaterialOperation`,
`MaterialPolicy`, and `OperationSecretMaterialPolicy`.
All enum variants, including their independently assigned operation
identities, are recorded in the declaration inventory and the enum table below.

Live HPKE contexts and opaque/private-key implementations must remain protected
and non-exportable. Schema reachability must be established by describing the
operation, key-source capability and opaque lifecycle contract; serializing
secret context internals merely to satisfy reachability would break the memory
and provider model.

## Limits and fixed policy values

The ledger records every public constant and associated constant, including
aliases in root and FFI layers. They include both fixed format dimensions and
resource/work-factor policy. The schema currently has no options/policy
structure that owns the following limits or fixes their cross-language parity:

| Policy | Current Rust value/source |
|---|---|
| Binary protobuf transport | 1,048,576 bytes; `proto/src/wire/limits.rs` |
| ProtoJSON transport | 1,572,864 bytes; same source |
| Error envelope | 1,024 bytes; same source |
| Recursion / unknown fields | 64 / 0, private adapter limits; same source |
| PBKDF2 password / salt / output | 4,096 bytes each; `pbkdf2/src/constants.rs` |
| PBKDF2 work-factor policy | Modern minimum 100,000, maximum 10,000,000; native iteration constructors and operation validation must retain their documented differences until migrated |
| RSA public key policy | Modulus 1,024-8,192 bits, exponent and DER/signature bounds; `rsa/src/constants.rs` and key parser |
| KMAC256 | Key 32-4,096, context 65,536, customization 4,096, output 65,536 bytes; `kmac/src/algorithm.rs` |
| Argon2 | Versioned cost tuples, mobile/desktop caps, secret/salt bounds; `argon2id/src/constants.rs` and `profile.rs` |
| HKDF / Concat KDF | Per-leaf output/input/info bounds; domain tag 1-48 constrained ASCII bytes; operation output-size restrictions also differ from generic leaf APIs |
| Fixed P-256 HPKE Base profile | Info 65,530 bytes, plaintext 16,777,216 bytes, fixed suite and empty AAD; `hpke/src/base_p256.rs` |
| Generic HPKE | Component dimensions, PSK minimum 32 bytes, context limits, registered key maxima; `hpke/src/constants.rs` |
| Subject key identifier | Exact public-key span bounded at 16,384 bytes; `crypto/src/key_identifier.rs` |
| Poseidon2 | 515-byte bound and fixed field/hash parameters; `poseidon2/src/hash.rs` |

Protocol constants must become schema-owned metadata or immutable policy
profiles where appropriate. This does not authorize callers to override fixed
cryptographic sizes, mandatory work factors or security bounds.

## Hand-written conversion locations

The [conversion trait ledger](schema-contract-conversions.csv) records each
explicit implementation. Additional hand-written tables and projections are:

| Location | Duplicated conversion/policy |
|---|---|
| `crates/proto/src/convert.rs` | Five schema-to-core `TryFrom` implementations, two reverse `From` implementations and three operation-specific reverse functions; suite-only selectors are rejected by the operation-agnostic key enum. |
| `crates/crypto/src/operation_contract/algorithms.rs` | MAC, KDF, key-wrap and HPKE component/suite selection in addition to forwarding core hash/AEAD conversions. |
| `operation_contract/{signature_algorithms,key_agreement_algorithms,kem_algorithms,signature}.rs` | Operation-specific family/suite and RSA identity selection. |
| `crates/crypto/core/src/algorithm.rs` | Native algorithm names, key dimensions, multicodec associations and family predicates. |
| `crates/hpke/src/identifiers.rs` | Numeric component conversions, component sizes/support, suite validation and named suite constants. |
| `crates/argon2id/src/profile.rs` | Integer version, native profile and core diagnostic-profile conversion plus cap resolution. |
| `crates/proto/src/wire/{mapping,error}.rs` | Native error projection, branch/reason validation and repeated numeric ranges. |
| `crates/crypto/src/operation_contract/operation_error.rs` | Another semantic-error to schema-reason mapping. |
| `crates/crypto/src/operations/*` | Per-operation native/dispatch error projections before the wire mapping. |
| `crates/ffi/src/*status.rs`, primitive boundary mappers and `crates/wasm/src/map_error.rs` | Independently maintained ABI/JavaScript error/status projections. |

A conversion from a closed generated enum cannot itself observe an unknown
numeric `buffa::EnumValue`. The migration must test the actual boundary wrapper
as well as `UNSPECIFIED`; rejecting unknown values only in one adapter is not
proof that every public conversion is total.

## Presence audit

There are **zero** hand-written `bool has_x` fields in the canonical crypto
schema. None of the eight flags previously reported in COSE is a crypto schema
field. There is no old flag number to reserve here, and no existing byte field
is relabeled as part of this inventory. Reserve actual retired numbers and names
when a real migration is made; inventing reservations for nonexistent fields
would consume the public wire namespace without fixing a defect.

Existing optional metadata in Rust JWK objects is another reason to define
future options in the schema. A future field that needs absent-versus-empty
semantics must use proto3 `optional` and pass generated ownership/zeroization,
binary/JSON and cross-language presence tests.

## Compatibility gates and migration order

`buf lint` and `buf breaking --against
'.git#tag=v0.3.17,subdir=crates/proto/proto'` both pass for the unchanged schema.
This compares with the latest local published release tag, not a self-comparison
against the working tree. No tests were executed for this inventory.

The current CI only runs lint and generation freshness. Its readiness checker
explicitly forbids `buf breaking` in the protobuf workflow
(`scripts/check_release_readiness.mjs:2330`). That prohibition conflicts with the
new contract rule and must be replaced by one pinned baseline compatibility
check when implementation starts, without adding duplicated CI runs.

1. **Algorithm/suite identity.** Define missing identity and immutable policy
   metadata in `.proto` first. Preserve assigned selectors and family ranges.
   Establish one generated/native bridge per supported native representation,
   including unknown-wrapper and `UNSPECIFIED` rejection. Regenerate all
   language bindings and compare each native value against generated values.
   Keep currently valid callers working through deliberate compatibility
   adapters rather than silently changing Rust discriminants or suite meaning.
2. **Errors.** Choose one canonical reason owner and remove competing tables.
   Map every concrete error variant to one schema code with exhaustive coverage;
   split or adapt payload-dependent outer variants deliberately. Preserve stable
   numeric status/error contracts during transition. Cover all schema provider
   codes, including 204-210, and all malformed/unknown/range cases.
3. **Remaining vocabularies, requests/results/options/policies and limits.**
   Define missing operation reachability and policy metadata area by area,
   retaining protected owner types and narrow features. Add exact parameter,
   limit, context-byte, presence, native/WASM and SDK parity checks for each area.
   Retire actual old fields only with reserved numbers/names and a reader/writer
   compatibility plan.

The dependency graph needs an explicit design before stage 1: the generated
proto package currently depends on `crypto-core` to host its conversions.
Simply making core depend on that proto package creates a cycle. Separate
schema generation from the bridge in a one-way graph; do not make lightweight
primitive users pull unrelated crypto/providers into their dependency graph.

Existing tests and public error types are part of the compatibility baseline.
The inventory does not authorize removing features, changing defaults,
serializing non-exportable state, renumbering selectors, changing exact caller
context bytes, or publishing unreleased code.

## Complete non-error enum vocabulary

This table lists every handwritten crypto enum that is not an error/reason
enum. The three private tool enums remain in the CSV with `tooling` status.
Error/reason enums are listed separately above.

| Native enum | Variants | Closest contract or gap | Source |
|---|---|---|---|
| `crypto_argon2id::Argon2Profile` | V1; V2 | Argon2idKdfVersion / CryptoArgon2idDeriveRequest | [crates/argon2id/src/profile.rs:14](../crates/argon2id/src/profile.rs#L14) |
| `crypto_argon2id::Argon2KdfVersion` | V1; V2 | Argon2idKdfVersion / CryptoArgon2idDeriveRequest | [crates/argon2id/src/profile.rs:23](../crates/argon2id/src/profile.rs#L23) |
| `crypto_argon2id::Argon2PlatformClass` | MobileModern; DesktopModern | Argon2idKdfVersion / CryptoArgon2idDeriveRequest | [crates/argon2id/src/profile.rs:32](../crates/argon2id/src/profile.rs#L32) |
| `crypto_core::Algorithm` | Ed25519; X25519; P256; P384; P521; Secp256k1; MlDsa44; MlDsa65; MlDsa87; SlhDsaSha2_128s; MlKem512; MlKem768; MlKem1024; XWing768 | CryptoAlgorithmIdentifier and family algorithm enums | [crates/crypto/core/src/algorithm.rs:7](../crates/crypto/core/src/algorithm.rs#L7) |
| `crypto_core::AeadAlgorithm` | Aes128Gcm; Aes192Gcm; Aes256Gcm; Aes256GcmSiv; ChaCha20Poly1305; XChaCha20Poly1305 | CryptoAlgorithmIdentifier and family algorithm enums | [crates/crypto/core/src/algorithm.rs:100](../crates/crypto/core/src/algorithm.rs#L100) |
| `crypto_core::HashAlgorithm` | Sha2_256; Sha2_384; Sha2_512; Sha3_224; Sha3_256; Sha3_384; Sha3_512 | CryptoAlgorithmIdentifier and family algorithm enums | [crates/crypto/core/src/algorithm.rs:137](../crates/crypto/core/src/algorithm.rs#L137) |
| `crypto_core::MacAlgorithm` | HmacSha256; HmacSha384; HmacSha512 | CryptoAlgorithmIdentifier and family algorithm enums | [crates/crypto/core/src/algorithm.rs:177](../crates/crypto/core/src/algorithm.rs#L177) |
| `crypto_core::AeadBackend` | Native; Swift; Wasm; Kotlin | No schema definition | [crates/crypto/core/src/error/aead.rs:8](../crates/crypto/core/src/error/aead.rs#L8) |
| `crypto_core::KdfAlgorithm` | Argon2id; Pbkdf2; ConcatKdf; Kmac256 | KdfAlgorithm / Argon2idKdfVersion / KeyWrapAlgorithm / MacAlgorithm / HashAlgorithm | [crates/crypto/core/src/error/kdf.rs:8](../crates/crypto/core/src/error/kdf.rs#L8) |
| `crypto_core::KdfProfile` | Argon2idV1; Argon2idV2; Pbkdf2HmacSha256; Pbkdf2HmacSha512; JwaEcdhEsSha256; Sp800185Kmac256 | KdfAlgorithm / Argon2idKdfVersion / KeyWrapAlgorithm / MacAlgorithm / HashAlgorithm | [crates/crypto/core/src/error/kdf.rs:34](../crates/crypto/core/src/error/kdf.rs#L34) |
| `crypto_core::HkdfHash` | Sha2_256; Sha2_384; Sha3_256 | KdfAlgorithm / Argon2idKdfVersion / KeyWrapAlgorithm / MacAlgorithm / HashAlgorithm | [crates/crypto/core/src/error/kdf.rs:101](../crates/crypto/core/src/error/kdf.rs#L101) |
| `crypto_core::KeyWrapAlgorithm` | Aes128Kw; Aes192Kw; Aes256Kw | KdfAlgorithm / Argon2idKdfVersion / KeyWrapAlgorithm / MacAlgorithm / HashAlgorithm | [crates/crypto/core/src/error/key_wrap.rs:8](../crates/crypto/core/src/error/key_wrap.rs#L8) |
| `crypto_core::KeyWrapOperation` | Wrap; Unwrap | CryptoOperationRequest | [crates/crypto/core/src/error/key_wrap.rs:31](../crates/crypto/core/src/error/key_wrap.rs#L31) |
| `crypto_core::MacHash` | Sha2_256; Sha2_384; Sha2_512 | KdfAlgorithm / Argon2idKdfVersion / KeyWrapAlgorithm / MacAlgorithm / HashAlgorithm | [crates/crypto/core/src/error/mac.rs:8](../crates/crypto/core/src/error/mac.rs#L8) |
| `crypto_core::RngOutputKind` | Generic; AeadNonce12; Argon2Salt16; Argon2Salt32; Aes256GcmKey; MlKem1024Seed; MlDsa87Seed; Ed25519Seed; SlhDsaSha2_128sSeed | CryptoOperationRequest | [crates/crypto/core/src/error/rng.rs:8](../crates/crypto/core/src/error/rng.rs#L8) |
| `crypto_core::SignatureBackend` | Native; Swift; Wasm; Kotlin; SecureEnclave | No schema definition | [crates/crypto/core/src/error/signature.rs:8](../crates/crypto/core/src/error/signature.rs#L8) |
| `crypto_core::SignatureOperation` | Sign; Verify; KeyManagement | CryptoOperationRequest | [crates/crypto/core/src/error/signature.rs:37](../crates/crypto/core/src/error/signature.rs#L37) |
| `crypto_dispatch::ProviderOperation` | GenerateKeyPair; DeriveKeyPair; Sign; Verify; DeriveSharedSecret; KemEncapsulate; KemDecapsulate | No schema definition | [crates/crypto/dispatch/src/provider.rs:14](../crates/crypto/dispatch/src/provider.rs#L14) |
| `crypto_dispatch::ProviderKind` | PackageOwnedRust | No schema definition | [crates/crypto/dispatch/src/provider.rs:34](../crates/crypto/dispatch/src/provider.rs#L34) |
| `crypto_dispatch::ProviderLane` | Native; Wasm | No schema definition | [crates/crypto/dispatch/src/provider.rs:42](../crates/crypto/dispatch/src/provider.rs#L42) |
| `crypto_dispatch::KeyResidency` | ProcessMemory | No schema definition | [crates/crypto/dispatch/src/provider.rs:52](../crates/crypto/dispatch/src/provider.rs#L52) |
| `crypto_dispatch::KeyCopyBoundary` | NoSecretInput; BorrowedCallerSecret; ProviderCreatesSecret | No schema definition | [crates/crypto/dispatch/src/provider.rs:60](../crates/crypto/dispatch/src/provider.rs#L60) |
| `crypto_dispatch::ProviderOutputPolicy` | PublicOnly; ZeroizingSecret | No schema definition | [crates/crypto/dispatch/src/provider.rs:72](../crates/crypto/dispatch/src/provider.rs#L72) |
| `crypto_dispatch::ProviderPolicyReason` | SelectedCompiledImplementation; RejectedOperationMismatch; RejectedFeatureDisabled | No schema definition | [crates/crypto/dispatch/src/provider.rs:82](../crates/crypto/dispatch/src/provider.rs#L82) |
| `crypto_dispatch::ProviderDisposition` | Selected; Rejected | No schema definition | [crates/crypto/dispatch/src/provider.rs:94](../crates/crypto/dispatch/src/provider.rs#L94) |
| `crypto_dispatch::FallbackPolicy` | Prohibited | No schema definition | [crates/crypto/dispatch/src/provider.rs:104](../crates/crypto/dispatch/src/provider.rs#L104) |
| `reallyme_crypto::ecdsa_explicit::EcdsaCurve` | P256; P384; P521; BrainpoolP256r1; BrainpoolP320r1; BrainpoolP384r1; BrainpoolP512r1 | SignatureAlgorithm / CryptoSignatureSignRequest / CryptoSignatureVerifyRequest | [crates/crypto/src/ecdsa_explicit.rs:37](../crates/crypto/src/ecdsa_explicit.rs#L37) |
| `reallyme_crypto::ecdsa_explicit::EcdsaHash` | Sha256; Sha384; Sha512 | SignatureAlgorithm / CryptoSignatureSignRequest / CryptoSignatureVerifyRequest | [crates/crypto/src/ecdsa_explicit.rs:56](../crates/crypto/src/ecdsa_explicit.rs#L56) |
| `reallyme_crypto::ecdsa_explicit::EcdsaInput` | Message; Prehash | SignatureAlgorithm / CryptoSignatureSignRequest / CryptoSignatureVerifyRequest | [crates/crypto/src/ecdsa_explicit.rs:68](../crates/crypto/src/ecdsa_explicit.rs#L68) |
| `reallyme_crypto::ecdsa_explicit::EcdsaEncoding` | Der; FixedWidth | SignatureAlgorithm / CryptoSignatureSignRequest / CryptoSignatureVerifyRequest | [crates/crypto/src/ecdsa_explicit.rs:87](../crates/crypto/src/ecdsa_explicit.rs#L87) |
| `reallyme_crypto::ed448::Ed448Operation` | Verify; OpaqueSign; SoftwareKeyGeneration; SoftwareKeyImport | No schema definition | [crates/crypto/src/ed448.rs:59](../crates/crypto/src/ed448.rs#L59) |
| `reallyme_crypto::operations::OperationFamily` | Hash; ConstantTime; Mac; Aead; KeyWrap; Kdf; Signature; KeyAgreement; Kem; Hpke; PlatformKey | CryptoAlgorithmFamily | [crates/crypto/src/operations/family.rs:8](../crates/crypto/src/operations/family.rs#L8) |
| `reallyme_crypto::operations::platform_key::PlatformKeyOperation` | Generate; GetPublicKey; Sign; Verify; DeriveSharedSecret; Delete; Attest | CryptoPlatformKey* standalone messages | [crates/crypto/src/operations/platform_key.rs:15](../crates/crypto/src/operations/platform_key.rs#L15) |
| `reallyme_crypto::prime_groups::PrimeGroup` | Rfc5114Dh1024_160; Rfc5114Dh2048_224; Rfc5114Dh2048_256; NistP256; BrainpoolP256r1; BrainpoolP320r1; NistP384; BrainpoolP384r1; BrainpoolP512r1; NistP521 | No schema definition | [crates/crypto/src/prime_groups/domain.rs:9](../crates/crypto/src/prime_groups/domain.rs#L9) |
| `reallyme_crypto::secret_material::DestructionPolicy` | NoneRequired; ZeroizeOnDrop; CallerControlled; ManagedRuntimeBestEffort | No schema definition | [crates/crypto/src/secret_material/destruction.rs:8](../crates/crypto/src/secret_material/destruction.rs#L8) |
| `reallyme_crypto::secret_material::ExportPolicy` | Public; SecretOwnerRequired; NonExportable | No schema definition | [crates/crypto/src/secret_material/export.rs:8](../crates/crypto/src/secret_material/export.rs#L8) |
| `reallyme_crypto::secret_material::OutputMaterial` | Public; SensitivePublic; Secret; Mixed | No schema definition | [crates/crypto/src/secret_material/output.rs:8](../crates/crypto/src/secret_material/output.rs#L8) |
| `reallyme_crypto::secret_material::BufferOwner` | Caller; OperationLayer; OperationContract; NativeAdapter; ManagedRuntime; PlatformProvider | No schema definition | [crates/crypto/src/secret_material/owner.rs:8](../crates/crypto/src/secret_material/owner.rs#L8) |
| `reallyme_crypto::secret_material::SecretMaterialOperation` | AeadSeal; AeadOpen; ConstantTimeCompare; Hash; MacAuthenticate; MacVerify; KeyDerivation; KeyWrap; KeyUnwrap; SignatureKeyGeneration; SignatureKeyDerivation; SignatureSign; SignatureVerify; SignatureEncoding; KeyAgreementKeyGeneration; KeyAgreementKeyDerivation; KeyAgreementSharedSecret; KemKeyGeneration; KemKeyDerivation; KemEncapsulate; KemDecapsulate; HpkeKeyGeneration; HpkeKeyDerivation; HpkeSenderSetup; HpkeReceiverSetup; HpkeSeal; HpkeOpen; HpkeExport; RandomFill; RandomNonce; RandomSalt; PublicKeyEncoding | No schema definition | [crates/crypto/src/secret_material/policy.rs:18](../crates/crypto/src/secret_material/policy.rs#L18) |
| `reallyme_crypto::secret_material::RetentionPolicy` | BorrowedForCall; OperationTemporary; ResultLifetime; ProviderManaged | No schema definition | [crates/crypto/src/secret_material/retention.rs:8](../crates/crypto/src/secret_material/retention.rs#L8) |
| `reallyme_crypto::secret_material::SecretSensitivity` | Public; Sensitive; Secret | No schema definition | [crates/crypto/src/secret_material/sensitivity.rs:8](../crates/crypto/src/secret_material/sensitivity.rs#L8) |
| `reallyme_crypto::secret_material::ZeroizationPolicy` | NotRequired; OwnerZeroizesOnDrop; CallerRetainsResponsibility; ManagedRuntimeBestEffort | No schema definition | [crates/crypto/src/secret_material/zeroization.rs:8](../crates/crypto/src/secret_material/zeroization.rs#L8) |
| `crypto_hkdf::HkdfSuite` | Sha2_256; Sha2_384; Sha3_256 | KdfAlgorithm | [crates/hkdf/src/policy.rs:10](../crates/hkdf/src/policy.rs#L10) |
| `crypto_hkdf::DomainKeyPurpose` | AeadContentKey; AeadWrapKey; AuthProofKey; ManifestCommitmentKey | No schema definition | [crates/hkdf/src/policy.rs:32](../crates/hkdf/src/policy.rs#L32) |
| `crypto_hpke::HpkeComponentSupport` | Executable; RegisteredUnavailable | HpkeKemId / HpkeKdfId / HpkeAeadId / HpkeSuiteIdentifier | [crates/hpke/src/identifiers.rs:21](../crates/hpke/src/identifiers.rs#L21) |
| `crypto_hpke::HpkeKemId` | DhKemP256HkdfSha256; DhKemP384HkdfSha384; DhKemP521HkdfSha512; DhKemCp256HkdfSha256; DhKemCp384HkdfSha384; DhKemCp521HkdfSha512; DhKemSecp256k1HkdfSha256; DhKemX25519HkdfSha256; DhKemX448HkdfSha512; DhKemX25519ElligatorHkdfSha256; X25519Kyber768Draft00; MlKem512; MlKem768; MlKem1024; MlKem768P256; MlKem1024P384; XWing | HpkeKemId / HpkeKdfId / HpkeAeadId / HpkeSuiteIdentifier | [crates/hpke/src/identifiers.rs:31](../crates/hpke/src/identifiers.rs#L31) |
| `crypto_hpke::HpkeKdfId` | HkdfSha256; HkdfSha384; HkdfSha512; Shake128; Shake256; TurboShake128; TurboShake256 | HpkeKemId / HpkeKdfId / HpkeAeadId / HpkeSuiteIdentifier | [crates/hpke/src/identifiers.rs:153](../crates/hpke/src/identifiers.rs#L153) |
| `crypto_hpke::HpkeAeadId` | Aes128Gcm; Aes256Gcm; ChaCha20Poly1305; ExportOnly | HpkeKemId / HpkeKdfId / HpkeAeadId / HpkeSuiteIdentifier | [crates/hpke/src/identifiers.rs:215](../crates/hpke/src/identifiers.rs#L215) |
| `envelopes_jwk::Jwk` | Ec; Okp; Akp | JsonWebKey / JsonWebKeySet | [crates/jwk/src/jwk.rs:95](../crates/jwk/src/jwk.rs#L95) |
| `crypto_pbkdf2::Pbkdf2Prf` | HmacSha256; HmacSha512 | KdfAlgorithm | [crates/pbkdf2/src/types.rs:18](../crates/pbkdf2/src/types.rs#L18) |
| `reallyme_crypto_proto::wire::CryptoWireErrorBranch` | Primitive; Provider; Backend | CryptoError.error oneof | [crates/proto/src/wire/error.rs:21](../crates/proto/src/wire/error.rs#L21) |
| `crypto_rsa::RsaHash` | Sha1; Sha256; Sha384; Sha512 | RsaPublicKeyDerEncoding / SignatureAlgorithm | [crates/rsa/src/types.rs:7](../crates/rsa/src/types.rs#L7) |
| `crypto_rsa::RsaPublicKeyDerEncoding` | Pkcs1; Spki | RsaPublicKeyDerEncoding / SignatureAlgorithm | [crates/rsa/src/types.rs:43](../crates/rsa/src/types.rs#L43) |
