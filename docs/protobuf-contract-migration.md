# Protobuf contract migration

The baseline inventory is recorded in
[schema-contract-inventory.md](schema-contract-inventory.md). It is a snapshot
from before migration; its declaration and export ledgers remain available for
review rather than being rewritten to hide outstanding gaps.

The strict error API is targeted at 0.4. It will replace the legacy nested error
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
unknown bytes. Native numeric values and existing executable suites are preserved.

Native workspace Clippy (all targets/features, warnings denied), the selected
WASM execution profile, TypeScript compilation, Buf lint/breaking against the
published baseline, generation idempotence and CI policy checks pass. Test
sources compile in the native all-targets check; test execution is deferred.
The broader WASM all-targets check is blocked by an existing missing crate-doc
lint in `aead_root_open_operation_tests.rs` when that test is feature-disabled.

## Remaining work

- Replace legacy error taxonomies with the strict 0.4 schema-reason API and
  exhaustive per-variant coverage; fix missing provider reasons and lossy
  projections as part of that migration.
- Migrate the remaining options, policies, content modes, key-source contracts,
  operations and limits in separate areas with generated/native parity.
- Keep absent-versus-empty semantics explicit. The baseline crypto schema has
  no manual `bool has_x` fields to retire.
