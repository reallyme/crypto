# Legacy prime-group domains

The unpublished 0.4.0 source API adds three explicit prime-group identities for
legacy interoperability. Their parameter bindings extend the existing protected
supplied-base interface. Deployment strength and protocol acceptance remain
caller policy.

| Native `PrimeGroup` variant | Protobuf value | Field/scalar bytes | Uncompressed point bytes | Parameter source |
| --- | --- | --- | --- | --- |
| `NistP192` | `PRIME_GROUP_NIST_P192 = 130` | 24 / 24 | 49 | [Standards for Efficient Cryptography 2 (SEC 2), version 2.0, section 2.2.2](https://www.secg.org/sec2-v2.pdf#page=10) |
| `BrainpoolP192r1` | `PRIME_GROUP_BRAINPOOL_P192R1 = 240` | 24 / 24 | 49 | [RFC 5639 section 3.2](https://www.rfc-editor.org/rfc/rfc5639.html#section-3.2) |
| `BrainpoolP224r1` | `PRIME_GROUP_BRAINPOOL_P224R1 = 250` | 28 / 28 | 57 | [RFC 5639 section 3.3](https://www.rfc-editor.org/rfc/rfc5639.html#section-3.3) |

These schema numbers belong to the existing NIST and Brainpool families. They
are independent of a protocol's domain-parameter IDs. Existing schema values
retain their meanings. The native variants are appended; checked schema
conversions remain the supported numeric projection.

## API and arithmetic

Select `prime-groups`, with defaults disabled when a narrow dependency graph is
required. Add `operation-response` for the existing standalone schema adapters.
The extension uses the existing `generator`, `scalar`, `random_scalar`,
supplied-base `multiply`, `linear_combination`, `reduce_to_field`, `encode_field`
and agreement interfaces. The seven-curve ECDSA interface remains a separate
contract.

Only standard parameters, generic-engine trait bindings and exact-domain
dispatch branches are added. Secret supplied-base multiplication continues
through the existing fixed-width ladder of complete additions/doublings and
conditional selection in `prime_groups/ec.rs`. Field operations use the existing
`primefield`/`primeorder` implementations; bounded reduction and Icart encoding
use the existing protected Montgomery helpers. All three moduli satisfy the
existing encoder's `p = 3 mod 4` requirement. The field and scalar multiplicative
generators were independently checked against complete factorizations of the
public modulus-minus-one values.

One set of parameter literals feeds both backend constants and exported domain
bytes. Optional `hex-literal` 1.1.0 decodes those public constants at compile time.
No registry package version, source or checksum changes are required. The
existing `primefield` 0.14.0 encoding-temporary limitation remains separately
tracked in [the memory model](../SECURITY_MEMORY_MODEL.md); these parameter
bindings do not repair that dependency implementation.

Private scalars retain secrecy owners. Returned points, reduced fields and
agreement values retain their clearing owners and exact widths, including
leading-zero bytes. Scalar zero/order/width checks, point canonicality,
nonidentity validation, domain binding, bounded allocation, entropy failures
and typed errors remain owned by the existing boundary.

## Regression coverage

The retained fixture set now covers thirteen domains. The original ten rows
are unchanged. `scripts/generate_prime_group_vectors.py` reproduces the public
known answers with independent integer and affine arithmetic. Coverage includes
standard generators, scalar multiples, supplied-base agreement, linear
combinations, order-minus-one and identity behavior, 512-byte reduction,
Icart encodings and leading-zero agreement outputs.

`crates/crypto/tests/prime_groups.rs` extends all existing hostile-input checks
to the three new rows, checks the same-width NIST/Brainpool domain distinction,
and adds schema-adapter comparisons against the independent multiplication,
reduction and Icart answers. The identity and native-contract suites cover all
thirteen domains and permanent wire encodings.

The earlier public-API inventory retains its recorded compiler checkpoint.
This extension accounts for the three new native variants and their three
schema counterparts; the protected owner and operation API shapes are retained.
Runtime validation of the 0.4.0 schema adapters requires the matching generated
bindings.

## Validation scope

| Check | Recorded result |
| --- | --- |
| Native all-target `prime-groups,operation-response` compilation | Passed with warnings denied |
| Workspace all-target/all-feature Clippy | Passed with warnings denied |
| WASM all-target `prime-groups,operation-response` compilation | Passed with warnings denied |
| Rust 1.96.0 minimum-version all-target compilation | Passed with warnings denied; the development toolchain remains 1.100.0 |
| Seven iOS/simulator/Android library targets | Passed with warnings denied using `native,prime-groups,operation-response`; no application or device execution |
| Buf lint and breaking against the pinned published 0.3.17 baseline | Passed |
| Generated error/constants/HPKE freshness, hardening idempotence and formatting | Passed |
| TypeScript build, static CI policy, workflow lint and offline Cargo Deny | Passed; dependency registry versions, sources and checksums are unchanged |
| Local canonical 0.4.0 runtime regression execution | Unexecuted under the requested no-tests constraint |
| Independent group runtime execution | Ten functions passed on each of native and WASM across thirteen domains at `561b7b0`, using the reviewed repaired-field override; the full schema-adapter suite was not run |

The mobile targets are `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
`x86_64-apple-ios`, `aarch64-linux-android`, `armv7-linux-androideabi`,
`i686-linux-android` and `x86_64-linux-android`. Compilation is separate from
known-answer execution and device integration.

The subsequent [independent runtime evidence](primefield-release-plan.md#independent-runtime-evidence)
binds those ten group functions and five exact DH validation functions to the
unchanged source archive and canonical fixtures. It records the repaired field
source separately from the canonical registry dependency; the latter remains
unmodified. The original compiler inventory checkpoint is retained.

The aligned Rust source packages remain unpublished 0.4.0. Existing published
0.3.17 packages and SDK artifact versions are unchanged. Runtime release gates
and publication retain their separate requirements.
