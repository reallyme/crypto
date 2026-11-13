# Protobuf contract migration

The baseline inventory is recorded in
[schema-contract-inventory.md](schema-contract-inventory.md). It is a snapshot
from before migration; its declaration and export ledgers remain available for
review rather than being rewritten to hide outstanding gaps.

The source API is versioned 0.4.0. It replaces the legacy nested error
variants as a deliberate breaking change. Existing 0.3 registry packages and
release tags are not modified. No new release has been published.

## Identity migration

The first identity step defines operation-independent asymmetric key identity
as `KeyAlgorithm` and `CryptoKeyAlgorithmIdentifier`. Existing operation-suite
oneofs, native algorithm variants, defaults and discriminants remain intact.

Core key, AEAD, hash, MAC and key-wrap identity conversions now use total
borrowed generated-message conversions. Existing closed-enum compatibility
conversions delegate to the same decisions. Root adapters retain their family
checks and error precedence, and no longer maintain separate MAC/key-wrap
conversion tables. Generic key identity does not select a signature suite or
enable an unsupported operation.

HPKE suite identity has an optional bridge using the existing HPKE component
types. This bridge checks schema registration and rejects unknown or
unspecified values. Execution remains subject to the existing provider policy;
the conversion does not enable a backend or choose a fallback.

The proto package's `hpke-identities` feature compiles without a backend. The
existing execution facade still requires a concrete component/profile selection;
`native,operation-response,hpke-api` alone does not meet the upstream backend's
KEM/AEAD requirements. Its previous feature behavior is retained. Backend-free
execution-facade support remains a separate gap.

Parity and negative coverage was added for every generated identity value,
unknown/unspecified values, wrong families, retained unknown fields, fixed-suite
separation, exact wire tags and registered HPKE component combinations.
The tests are not executed during this work, as requested. Compiler, lint,
generation and schema-compatibility checks are reported separately.

The protobuf CI lane now checks compatibility against the published 0.3.17
schema commit `e57caf7a035c1ffe33aad0038d603b793a69b28a`, once, before generation.
The readiness policy requires that pinned check instead of forbidding it.

HKDF suites, PBKDF2 PRFs, Argon2 profiles/versions, RSA hashes and DER encodings,
explicit ECDSA curves/hashes, and prime-order groups now have schema metadata
and owner-local total conversions. Generated metadata owners also clear retained
unknown bytes, including descriptive policy and Argon2 numeric records outside
`crypto.proto`. Borrowed and shared views redact debug output; their backing
input bytes retain the caller or shared-buffer lifetime described in the memory
model. Native numeric values and existing executable suites are preserved.

Native workspace Clippy (all targets/features, warnings denied), the selected
WASM execution profile, TypeScript compilation, Buf lint/breaking against the
published baseline, generation idempotence and CI policy checks pass. Test
sources compile in the native all-targets check; test execution is deferred.
Sparse feature builds retain test-crate documentation or existing test-only
allowances before the feature gate, so disabled test crates do not create
unrelated missing-crate-documentation warnings.

## Canonical native error contract

The 0.4 native `CryptoError` is a validated `thiserror` struct, not a second
error enum. Its private classification field is the schema-generated
`CryptoErrorReason`; each error instance contains exactly one known, nonzero
reason. Each generated error constant fixes exactly one schema value. This
preserves the one-reason-per-classification rule without restating every reason
as another public set of variants. The Buffa bindings re-export that same enum;
its idiomatic aliases do not create additional values or types.

`CryptoError::VALUES` enumerates every native failure constant once, excluding
the zero sentinel. Parity test sources compare its complete reason/code set
against `CryptoErrorReason::VALUES` with zero removed and require unique native
constants; generator coverage also checks every constant declaration. Execution
of these tests remains deferred.

The zero sentinel remains available for protobuf defaults. It cannot construct
a native failure, and unknown numeric reasons are rejected with the fixed
invalid-parameter error. The native error has no `Default`, input-bearing
context fields, unchecked serde constructor, or provider diagnostic text.
Wire envelopes continue to represent primitive, provider, and backend ownership
through the schema oneof; branch metadata is generated from its descriptors.

The native error implementation now replaces the former core failure kinds,
operation reasons, dispatch/signer wrappers and primitive-specific error enums.
Existing area names are aliases of the same validated type. Native-to-wire
conversion preserves the original reason and uses generated branch ownership;
all provider reasons 204–210 are accepted. Signature rejection, authentication
failure and MAC/equality verification retain separate canonical reasons.
Caller-controlled invalid nonce, tag, password and salt errors are no longer
coalesced into an unrelated key or length error.

Algorithm conversions now live with their native owners: core conversions use
`crypto-core/protobuf` and HPKE conversions use `crypto-hpke/proto`. The protobuf
package has no dependency on those implementations. Default core builds depend
only on minimal schema constants, error types and `thiserror`, without Buffa
or JSON.
All Rust release packages and local pins target unpublished version 0.4.0.
Existing registry packages, SDK artifact pins and release tags remain intact.

C ABI integers and WASM's five numeric status values remain unchanged. Their
coarse projections are explicit and exhaustive over the canonical reason enum;
structured protobuf routes preserve exact reasons. Rejected JavaScript output
property writes now return a backend failure and clear the unpublished byte copy.

The native workspace compiles and passes strict Clippy for all targets/features;
all test sources compile. Eleven narrow native operation profiles, the selected
WASM profile and full WASM SDK (including test-source compilation), Buf
lint/breaking against the published baseline, regeneration,
idempotence, TypeScript compilation and the CI policy checks pass. No Rust,
Node, browser, SDK or device tests were executed during this migration. Runtime
regressions, including browser property-write failures, require execution before
release approval.

## Retired diagnostic vocabulary

The 0.4 cleanup removes eight obsolete context enums: `AeadBackend`,
`SignatureBackend`, `SignatureOperation`, `KeyWrapOperation`, `KdfProfile`,
`MacHash`, `HkdfHash` and the unused core diagnostic `KdfAlgorithm`. It also
removes the ten `FailureKind` aliases and the three per-area reason synonyms.
These names no longer select or classify failures independently of the schema.
The metadata-only `HkdfSuite::hash` and `Argon2Profile::to_kdf_profile` helpers
are retired with them.

Functional key-wrap selection and random-output purposes retain their variants
and root API paths, in focused modules outside the error namespace. Public
PBKDF2 constructors retain their selector arguments and validation. Facade and
leaf helpers now propagate the canonical error directly, preserving operational
selection, checked arithmetic and clearing ownership. Workspace all-targets,
all-features Clippy passes with warnings denied; tests remain unexecuted.

The original inventory and ledgers are historical evidence from before
migration. They are intentionally retained; this section records retirement
rather than rewriting those earlier findings.

## Provider and material policy vocabulary

The schema now defines all nine provider vocabularies, eight material-policy
vocabularies, random-output purposes and platform-key operation identities.
Each native enum has one total generated-value conversion, rejecting zero and
unknown values, and one exhaustive reverse projection. The persisted native
material-operation values 0–31 retain their existing meanings; explicit schema
mappings use nonzero family values rather than integer casts.

All 21 fields of provider and material-policy records are represented. Their
native projections destructure exhaustively, so adding a native field requires
an explicit contract update. Policy records are read-only outputs: no reverse
conversion accepts caller-created records as authorization or policy overrides.
The provider query request selects only an operation and key identity; its
adapter computes a fresh decision from compiled provider rules.

Parity, invalid-selector, exact-field and query-modifier regression sources are
added. Native all-targets/features Clippy, the WASM SDK target, Buf compatibility,
TypeScript compilation, hardening idempotence and CI policy checks pass. Tests
remain unexecuted. Generated ES imports now use explicit `.js` extensions, and
SDK output normalization covers the generated packages uniformly.

## Error generation and freshness

Error code generation is maintenance work, not a Cargo build step. The existing
protobuf freshness pipeline runs `buf generate`, then the secret-owner hardener,
then `node scripts/generate_error_contract.mjs`. The generator reads a bounded
Buf FileDescriptorSet and derives the reason values, names, aliases, constants,
and known branch ownership. It replaces the duplicate Buffa reason declaration
while retaining the generated wire traits on the shared type. The existing
freshness snapshot compares the resulting committed files, so CI needs one
generation pass rather than an additional generator job or repeated check.

For a standalone read-only maintenance check, run
`node scripts/generate_error_contract.mjs --check` after regeneration. Unchanged
outputs preserve their file timestamps. Changes to the schema, generator, or its
test sources select the existing protobuf workflow. Ordinary `--ci-policy`
validation checks the shared-owner source invariants without invoking Buf,
generating code, or launching repository tests; the existing tooling jobs own
those tests. Full local and release modes retain their complete test routing.

## Primitive dimensions and resource limits

Immutable descriptor metadata now owns 197 exact scalar or byte constants
across 39 native modules. It includes primitive key/output dimensions, PBKDF2
work factors, fixed Argon2 cost tuples and platform caps, RSA admission bounds,
KMAC limits, HKDF domain sizes, signature import limits, group-generation and
field-reduction bounds, the secure-handle prefix and wire decoder limits.
Native constants retain their public names and types and alias generated values;
existing root and FFI aliases therefore resolve to the same authority. Admission
predicates use the same generated bounds without changing accepted inputs.

The `contract-types` feature has no codec, JSON, error or cryptographic
implementation dependencies. Pure hash leaves select only this feature. Core
reexports the same module alongside its minimal error types; the full Buffa
feature remains optional. Metadata describes compiled policy and cannot be used
as a request to override costs, resource limits or cryptographic dimensions.

The existing maintenance generator reads the Buf descriptor once, validates
constant types, units, ranges, identifier safety, portability and reason-family
ownership, then renders the minimal Rust module. Both generation outputs are
validated before any write. SDK generation excludes the descriptor-option
package while retaining the complete descriptor for maintenance. No Cargo build
script or additional CI job is introduced. Compatibility-value and malformed
metadata regression sources are included; execution remains deferred.

Workspace all-targets/features Clippy with warnings denied, formatting, Buf
lint/breaking against the supported baseline, generated ownership idempotence,
maintenance freshness and CI policy checks pass for this checkpoint. No tests
were executed.

## Native options and optional metadata

Standalone contracts now describe native RSA-PSS parameters, fixed Argon2
requests and platform caps, HKDF extraction/expansion/domain inputs, JWK options
and typed public JWK/JWKS models. RSA preserves independent message and MGF1
hashes and distinguishes missing salt length from an explicit zero. Argon2 caps
and resolved parameters are read-only records; callers cannot use them to
override compiled profiles. HKDF preserves optional salt and exact context bytes
and validates the requested output length against the native const generic.

JWK KID, algorithm and usage metadata use actual optional byte fields, preserving
valid UTF-8 bytes without normalization. The draft metadata presence flags are
reserved and removed. JWK output-selection flags remain ordinary options, and
existing native public JWK structures keep their field types. Protected adapter
owners clear all copied strings and return only borrowed native views. JWK
field copies reserve fallibly through their final clearing owners.

Generated optional bytes preserve absent versus present-empty values in binary
and JSON. Setters, replacement, partial merge, clear and malformed JSON paths
retain clearing ownership. Transitive wrappers clear unknown-field storage
without adding an outer Drop implementation that prevents native field moves.
Partially decoded unknown groups and base64 output now enter guards before
fallible parsing. JSON owned strings are guarded when the deserializer transfers
ownership; borrowed input and a deserializer's internal escaped-string scratch
remain owned by that deserializer and are outside the visitor's clearing control.
This is an ownership guarantee for controlled buffers, not a compiler-wide
memory-erasure claim.

The existing CI privacy gate derives byte-field requirements from the schema
instead of maintaining another field inventory. Every byte field requires a
redacting, clearing generated owner; unknown string fields are sensitive by
default. Fixed provider-name strings retain their public classification. The
independent generated-code checks still verify these requirements.
The pinned shared validator assumes non-optional JSON staging. A local extension
checks optional staging, merge, setter, redaction and Drop ownership before
projecting those fields past that legacy shape assertion; their actual privacy
classification stays sensitive. The reviewed shared core remains unchanged.

Native workspace Clippy with warnings denied compiles the new parity, malformed
input, optional-presence and cleanup regression sources. Buf lint/breaking,
TypeScript compilation, generation and hardening idempotence pass. Runtime
execution remains deferred by request. These standalone adapters do not add
root executable selectors or enable additional cryptographic providers.

## Protected native primitive contracts

Standalone request/result contracts now cover explicit ECDSA message/prehash
inputs, DER versus fixed-width signatures, software key generation/import,
opaque signing, public-key association, verification and agreement. All seven
curves retain independently selected SHA-256/384/512 semantics. A present empty
message is distinct from an absent input, and prehash lengths are checked
without hashing the supplied digest again.

Ordinary Ed448 software/opaque capabilities, protected key lifecycle and
verification now have matching contracts. X448 generation/import/agreement
retain their protected native owners and RFC 7748 byte widths. Ten prime-group
identities now reach scalar/element import, generation, multiplication, linear
combination, field reduction/encoding, domain inspection and agreement. Public
descriptors describe capabilities; private keys/scalars and live providers stay
native and are not serialized to satisfy reachability.

The two restated native vocabularies, ECDSA encoding and Ed448 operation, have
total generated-value conversions with zero/unknown rejection. Native key-source
facts use the generated enum directly. Conversion helpers borrow contained
messages rather than assuming the generator's inline/boxed storage strategy.
Parity, known-answer, malformed-input, provider-failure and ownership regression
sources compile under strict workspace all-targets/features Clippy. Buf
compatibility and hardened regeneration pass. Tests remain unexecuted.

## HPKE identity, lifecycle and context contracts

The schema now owns 55 additional HPKE scalar entries, all 21 named suite
constants and all three ordered component registries. Existing wire enum values
remain the authority for component numbers; typed enum/constant references avoid
copying those numbers into another table. Native enum bindings and aliases are
validated against actual bounded Rust tokens before generation. The generated
owner-local suite module is covered by the existing freshness snapshot.
Existing numeric values, suite triples, registry order, support tables and
feature choices are preserved.

Standalone protected inputs cover Base/PSK one-shot operations and exporters,
PSK sender/receiver setup and record seal/open content. Live contexts remain
native, exclusive mutable owners; no key, nonce, sequence, context identifier,
reset or state-reconstruction field is added. The existing executable
`hpke_suite = 11` selector and operation oneofs remain unchanged. Input, AAD,
PSK identifier and exporter-context bytes are passed through exactly.

The fixed P-256 Base profile has its own recipient import/generation contracts,
returning the existing non-exportable recipient owner and associated public
key. It retains exact uncompressed point encoding, existing input/output
bounds, empty AAD and fallible protected allocations. Its explicit RNG path
borrows the existing native entropy capability. No new default suite or backend
is selected by metadata conversion.

A runtime HPKE configuration must select at least one KEM and one AEAD, as
required by the pinned implementation. The exact P-256/AES-128-GCM feature
recipe supplies both; the root API facade without concrete components is not
a supported runtime profile. Metadata-only leaf builds remain backend-free.

Optional-owner checks now independently inspect Drop, clear, merge, setter and
JSON staging scopes. Generated boolean fields retain the pinned ProtoJSON
null-to-default behavior. Ownership, context-lifecycle, exact-byte and negative
regression sources are added; execution remains deferred.

## Utility and adapter contracts

Immutable metadata now owns the 32 existing C/JNI/WASM/RSA selector and status
numbers and five fixed native boundary caps. Native aliases retain their exact
values, types, coarse error projections and calling conventions. Platform-derived
slice bounds remain platform-derived. No status is reinterpreted as a native
schema reason, and valid zero success codes remain valid.

Standalone contracts now reach injected secure-random filling and typed random
outputs, all three constant-time comparison APIs and the fixed Poseidon2
profile. Caller-provided result bytes cannot become trusted fresh randomness.
Constant-time comparison retains its separate boolean and typed-error semantics;
Poseidon2 keeps its existing fixed parameters and admission bound. The operation
family bridge now covers constant-time and platform-key families without
renumbering the existing nine values or changing native ordinals.

All new inputs preserve exact bytes, reject unknown modifiers, and use clearing
owners. Optional leaf metadata features and weak root forwarding keep backend
selection unchanged; no new executable operation selectors are added. Parity,
invalid-input and owner regression sources are included but unexecuted.

## Key formats, canonical signatures and identifiers

Standalone format contracts reach the existing explicit ECDSA/secp256k1
transcodes, P-256 low-S normalization and signing/verification helpers,
container import, compressed public-key extraction, existing public-key format
operations and the narrowly scoped RFC 5280 subject-key-identifier operation.
Encoding, curve and message/prehash choices remain explicit. The separate
low-S helpers do not change interoperable legacy signing or verification.
Container helpers retain their existing native-only availability, and typed
unsupported errors preserve disabled-provider behavior.

Typed JWK/JCS and multikey transformations now have matching requests/results
and protected native adapters. They preserve existing canonicalization, codec
identities, validation and unsupported families; no alternative JSON parser or
normalizer is introduced. Optional metadata bytes are copied exactly through
clearing owners. The dispatch multikey generation/binding helpers also have
contracts, retaining their existing software-private-output policy and key
validation order. No opaque private key or live context becomes serializable.

Trusted JWK JSON values now clear their owned strings and map keys on every
exit. P-256 container import immediately guards its named serialized scalar
before validation/copy. These local ownership changes are separate from
protocol vocabulary and the accepted upstream coordinate-temporary gap.
Format tests use static PEM fixtures, so metadata validation does not broaden
production dependencies. Regression sources remain unexecuted.

## Leaf queries and parameter domains

Argon2id profile, platform-budget and mobile-unlock queries now have explicit
schema requests and native adapters. Queries return the existing fixed cost
tuples and retain the native resource admission rules; they do not grant
provider authority. Material and random-fill policy queries likewise return
read-only decisions from the existing native policy.

The standards-level PBKDF2 leaf has its own request covering the native
iteration domain. The root operation keeps its established modern minimum.
Concat KDF adapters cover every admitted native output width with checked
bit-length encoding; root dispatch retains its existing fixed width set.
AlgorithmID and party bytes remain exact, including embedded zero bytes.

Argon2id writes directly into its final clearing output owner. Concat KDF
immediately guards each finalized SHA-256 block and copies into its final
clearing owner. Arbitrary AlgorithmID bytes have redacted debugging and
independently clearing clones. These ownership repairs are tracked separately
from protocol identities and the accepted upstream coordinate issue.
Parity, invalid-domain and ownership regression sources are added; execution
remains deferred.

## Conformance and key-material contracts

Explicit-coins ML-KEM/X-Wing and HPKE conformance operations have separate
requests under their existing feature gates. They preserve caller randomness,
context bytes and native validation. Ordinary randomized operations remain
distinct. HPKE exact-suite-width key derivation is separately represented from
the existing flexible-IKM operation. Private keys and live contexts remain native
clearing owners; only public descriptors are serialized.

P-256 provider-handle format requests preserve binary tags and distinguish a
nonmatching prefix from a matching empty tag with an optional byte field. These
helpers neither authenticate a provider nor export a private scalar.
X-Wing's named local encapsulation coins now enter a clearing owner immediately;
this local repair does not change randomness or dependency features.
Conformance, byte-preservation, presence and ownership regression sources are
included but unexecuted.

## RSA public operations and independent PSS parameters

Standalone RSA requests now reach protected public-representative recovery and
PSS verification with independent message/MGF1 hashes and explicit salt presence.
Existing fixed root suites and their policies are unchanged. DER wrappers are
explicit; representatives do not establish signature validity or trust.
Key and signature admission bounds precede copied ownership, while the existing
native parser preserves malformed-key error precedence.

The added regression sources cover bounded admission, canonical reasons,
generated/native parity and all twelve unequal message/MGF1 hash pairs with both
zero-byte and 32-byte salts. The 24 static known answers retain the exact pinned
primary-source provenance and license. These sources are compiled, not executed.

## FFI dimensions

The remaining 47 repeated FFI key, signature, ciphertext, shared-secret and
randomness widths now refer directly to their semantic schema constants. Ten
missing dimensions were added within the existing algorithm metadata modules;
equal numeric sizes are not treated as interchangeable meanings. Names, types,
values, feature gates and ABI widths remain unchanged. An explicit regression
source covers every alias and the historical ABI values without a second
production table.

## Variable-output hashing

The standalone SHAKE256 request specifies its output length in octets as
`uint64`. Its borrowed-output adapter checks conversion, exact destination width
and unknown modifiers before writing. Zero-length and arbitrary native widths
remain valid. Callers retain a clearing destination owner; no unbounded
allocating convenience or fixed-output hash selector is introduced. ProtoJSON
uses the pinned generator's exact 64-bit integer helper.

The three wide SHA-3 one-shot leaves now finalize directly into their final
clearing owners, matching the existing SHA3-256 ownership path. Existing NIST
answers, exact-byte/width negatives, JSON integer cases and ownership regression
sources are retained or added without executing them.

## Raw secp256k1 agreement and entropy errors

A fixed standalone secp256k1 agreement contract reaches the existing 32-byte
scalar and 65-byte uncompressed SEC1 operation. It returns the raw x-coordinate
through the existing protected agreement result; signature and HPKE suite
selectors remain separate. Independent published scalar/point answers include
a leading-zero x-coordinate, with exact-width and invalid-point negatives.

The native shared-secret owner now has an actual clearing drop implementation;
its previous marker alone did not run cleanup. Copying now initializes that final
owner directly. This local ownership defect is separate from the accepted
upstream encoding temporary.

The two deprecated X25519/secp256k1 key-generation names now return canonical
typed results by forwarding to their existing fallible implementations. This
deliberate 0.4 error-boundary break removes their historical entropy-provider
panic paths. The [migration note](0.4-entropy-error-migration.md) describes the
caller adjustment. Successful bytes, provider policy and default features are
unchanged. All added regression sources remain unexecuted.

## Remaining work

The implemented identity, error, policy, dimensions, native options, primitive,
HPKE, utility, format and conformance contracts above are the current 0.4.0
source state. The original inventory remains frozen historical evidence.
Completeness of the migration still requires a current compiler-visible export
and semantic reconciliation; a declared enum or DTO is not proof that an
operation, option, lifecycle or SDK route is reachable.

- Reconcile current public declarations, cross-workspace reexports/aliases,
  macro-expanded exports and public trait/default members with the frozen
  inventory and all newly added items. Distinguish direct native adapters,
  executable root routes, representation helpers and conformance-only gates;
  preserve explicit dispositions for derived/blanket members and adapter-only
  utilities. Close concrete missing domains without inventing executable routes.
- Complete final-checkpoint formatting, native all-target/all-feature Clippy,
  Buf compatibility/generation/freshness, TypeScript compilation and the native,
  WASM and seven mobile target compile checks. Earlier passing statements above
  describe their migration checkpoints; they do not certify subsequent changes.
  Final aggregate checks remain pending in the compatibility matrix.
- Execute the new parity, optional-presence, negative-input, canonical-error,
  ownership, provider-failure and deterministic conformance regressions against
  the final native/WASM source, with applicable property/fuzz and SDK validation
  before release readiness is asserted. No runtime execution of these migration
  regressions is claimed. Historical primitive/device results retain their
  pre-migration source scope.
- Retain absent-versus-present-empty bytes/messages and reject zero/unknown
  selectors and unknown modifiers in each actual adapter. The baseline schema
  has no manual `bool has_x` fields to retire. Generated transport copies must
  retain independent cleanup without making native keys or live contexts
  serializable. Deserializer-internal scratch remains a separate memory limit.
- Keep the accepted primefield coordinate-serialization temporary and BP512
  full-order certificate as explicit audit limits. Local ownership repairs,
  schema completeness and known answers do not close those separate findings.
- Keep the 44 Rust source package versions at 0.4.0 distinct from unchanged
  0.3.17 SDK artifact versions and published packages. Coordinated release and
  remote publication remain separate delivery steps; no 0.4.0 release is claimed.
