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
only on the minimal schema error types and `thiserror`, without Buffa or JSON.
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

## Remaining work

- Migrate the remaining options, policies, content modes, key-source contracts,
  operations and limits in separate areas with generated/native parity.
- Keep absent-versus-empty semantics explicit. The baseline crypto schema has
  no manual `bool has_x` fields to retire.
