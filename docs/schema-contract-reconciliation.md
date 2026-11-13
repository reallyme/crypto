# Native API and schema reconciliation

This report binds the unpublished Rust 0.4.0 API to compiled source commit `e0368ca60ab68eb710b6cf5cf5a46b66fdbaf4c4` and tree `bb402e318337a6270901939c1b6098bd7c95eead`. It inventories **3,617 compiler-visible declaration/exposure records**, including 47 private-tooling records, and **3,511 export edges**. Counts include methods, fields, variants, constants and native alias contexts; they are not counts of independent cryptographic operations.

Every current record has an explicit source/schema or native-representation disposition. No supported product item remains unidentified in this inventory. This establishes source-contract reconciliation for the selected compiler inputs. Runtime validation is incomplete, and the native API is not asserted to be entirely wire-callable: native key owners, borrowed storage, const generics, injected providers and open traits remain explicit boundaries.

## Evidence

Rust and Rustdoc 1.100.0 compiled 45 native library documents for `aarch64-apple-darwin` and 42 for `wasm32-unknown-unknown`, with warnings denied and hidden public items included. The producer verified clean committed source before and after capture, exact document hashes, and unchanged source and HEAD. Its proof SHA-256 is `d618eec92c27ef3862d1ed7e4d13f26a9990289b1eae3383fb75ffca1f0a42be`.

Workspace metadata contains 46 packages: 44 at version 0.4.0 and two development tools at 0.0.0. The conformance-vector package has binary/test targets rather than a library document. Native library coverage includes the FFI package and two tools; the WASM pass explicitly excludes those three packages. These source versions are unpublished. Published 0.3 packages and tags are outside this migration.

| Artifact | Scope |
|---|---|
| [Current declarations](schema-contract-current.csv) | All 3,617 records, public paths, source hashes/spans, exact function/type contracts, implementation context, schema fields and scoped disposition. |
| [Current exports](schema-contract-current-exports.csv) | All 3,511 alias/reexport edges and their resolution evidence. |
| [Historical migration](schema-contract-migration.csv) | All 2,670 frozen declarations linked to current items or explicit retirement/replacement. |
| [Source-only boundaries](schema-contract-current-boundaries.csv) | The 15 historical source-only candidates, including JavaScript exports and private/tooling exclusions. |
| [Exact package versions](schema-contract-current-versions.csv) | All 46 workspace packages, target kinds and observed library lanes. |
| [Provenance](schema-contract-current-provenance.json) | Compiled checkpoint, capture/collector hashes, scope booleans, counts and artifact hashes. |

The historical inventory and its accompanying ledgers remain unchanged. The current graph is collected independently; the older list of 687 lexical additions does not limit discovery. The current graph includes 820 new source-bound records, 12 previously omitted macro-generated JWK functions, 464 additional minimal-authority records and 2,321 records sharing historical public paths. Thirty more minimal-authority records are within that last group.

## Migration and authority

The 2,670 historical rows resolve to 2,314 public-path/kind matches, 13 moved identity bridges, 16 error-owner replacements and 327 explicit retirements. A public-path/kind match does not claim an unchanged signature. The 0.4 error API deliberately replaces nested native error taxonomies with the shared validated canonical error owner; deprecated infallible entropy-generator names now return `Result`. Historical diagnostic-context getters and predicates are retired explicitly. Identity bridges now reside with their native owners, removing proto dependency backedges.

Minimal generated native authority remains included: 121 canonical-error records, 349 immutable-metadata records and 24 owner-local HPKE suite/registry records. The canonical reason enum is shared with full bindings. Native errors own one validated nonzero reason, with no unchecked native default/serde constructor or arbitrary-reason setter. Typed constant metadata declares units, types, ranges and references; HPKE component numbers remain owned by their existing schema enums. Metadata is immutable authority, not caller policy configuration.

The 1,032 full generated transport-binding records are classified separately as schema-derived. Compiler-generated trait surfaces are also separate: 2,733 derived, 16,645 blanket and 7,000 synthetic implementation records. There are 670 explicit inherent and 5,840 explicit trait implementation records. Exact native trait-member contracts remain in the declaration ledger. Inherited defaults and upstream trait mechanics do not create additional handwritten operation vocabularies.

## Parameter domains and ownership

The detailed family review covers 532 historical records: 303 operation correspondences and 229 native owner/record/capability/projection correspondences. It retains 405 exact function bodies/signatures, 64 structs, 60 public fields and three traits, with 1,325 schema field links. All 110 previously symbolic constant alias chains have individual terminal proofs.

Distinct contracts retain their full modeled domains: independent RSA-PSS message/MGF1 hashes and salt length; Argon fixed-cost admission under platform or arbitrary caller budgets; standards-minimum PBKDF2 separately from the modern facade floor; admitted const-generic Concat and HKDF output widths; zero/arbitrary SHAKE output lengths; raw secp256k1 agreement; and key-agreement generation under its own semantic owner. HKDF retains optional salt presence and exact info bytes. The root HKDF executor retains its existing 16/24/32/48/64-byte subset while the standalone native contract models admitted `N` explicitly.

Native generic parameters and protected owners remain visible in signatures. Output-only capability/policy records do not authorize a provider, export a private key or prove hardware cleanup. Open signer/RNG traits describe native capabilities; a schema enum does not prove an arbitrary implementation. Const-generic comparison and other borrowed native buffers retain their native domains, while owning transport adapters retain their documented wire-size projections. Arbitrary caller-constructed legacy JWK model states are not asserted equivalent to validated protected schema owners.

Optional bytes preserve absent versus present-empty values. Inputs, context, party data, key encodings and signature representations retain their stated native semantics. Protected copies, borrowed views and consuming raw-byte returns are distinguished; a raw native return retains caller cleanup responsibility. Local digest/HMAC/KDF call-site ownership repairs are separate from accepted upstream limits documented in [the memory model](../SECURITY_MEMORY_MODEL.md). This ledger makes no compiler/register-copy erasure or unsafe after-drop memory claim.

## Validation limits

The compiler graph has zero unresolved document or source problems. All 148 macro/source-name mismatches were retained rather than discarded. The unreached-public ledger consists of reexport `use` nodes recorded as edges and private Brainpool implementation types; it is not a list of uncovered product operations. Source-only JavaScript bindings receive their own dispositions.

This reconciliation does not execute tests, known answers, cryptographic operations, device applications or publication. Compiler/documentation and related native/WASM/mobile source checks do not establish runtime parity, mobile device execution, every feature combination or cryptographic certification. Runtime test sources remain unexecuted.

The original report handoff at `05a9846` changed only documentation/evidence after the compiled checkpoint above. That report commit is distinct from the source compiled by this capture. The later implementation review below has its own validation scope.

## Subsequent implementation review

Commit `e22f15e82e1e26fa625787234e28581c9eded9f6` adds private RSA digest-buffer cleanup and repairs three disabled-provider test files plus the existing sparse-feature CI check. Public Rust signatures, schema, generated bindings, package manifests and lockfiles are unchanged. The original compiler capture and its ledgers remain bound to `e0368ca`; this follow-up does not claim a new compiler-graph capture. Its native, WASM, mobile and minimum-version compile results are recorded in the [compatibility matrix](reader-primitive-compatibility.md#subsequent-rsa-and-feature-review). Runtime regressions remain unexecuted.

## Legacy group additions

The subsequent [legacy prime-group extension](legacy-prime-groups.md) adds three native variants and matching schema identities: `NistP192`/130, `BrainpoolP192r1`/240 and `BrainpoolP224r1`/250. Their existing owner and operation shapes are retained. The parameter types remain private implementation bindings. This explicit supplement accounts for the additions; the original compiler-capture counts and historical ledgers retain their recorded checkpoint rather than being relabelled as a new capture.

## Explicit DH parameter validation

The [DH parameter validation contract](prime-group-domain-validation.md) accounts for one additional native method and its standalone schema adapter. The schema defines the request's selected group and canonical unsigned `p`/`g`/optional-`q`/optional-`j`, plus the validated-identifier result, before their implementation. The two new generated messages carry that sole field authority; no new native enum, error reason, caller-defined domain or policy type is introduced. This supplement preserves the original compiler checkpoint and does not claim a recapture or runtime execution.
