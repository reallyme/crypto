# Explicit DH domain validation

`PrimeGroup::validate_dh_parameters(p, g, q, j)` validates explicit public
parameters against the selected built-in RFC 5114 group. It is available with
`prime-groups`; defaults can remain disabled. The operation admits no additional
group, changes no agreement arithmetic and makes no protocol-strength decision.

The canonical schema first defines
`CryptoPrimeGroupDhParametersValidationRequest` and
`CryptoPrimeGroupDhParametersValidationResult`. With `operation-response`,
`prime_groups::contract::validate_dh_parameters` borrows that request and returns
the validated identifier. Existing error reasons and group identifiers retain
their numbers. All generated language bindings carry the same optional fields.

| Schema field | Native input or result | Validation |
| --- | --- | --- |
| `request.group` | Method receiver `PrimeGroup` | Exactly one of the three existing RFC 5114 DH groups; elliptic curves are rejected. |
| `request.p` | Borrowed `p` bytes | Minimal, nonzero, unsigned big-endian; exact built-in modulus. |
| `request.g` | Borrowed `g` bytes | Same representation; exact built-in standard generator. |
| `request.q` | `Option<&[u8]>` | Absent order is established by exact built-in `p`/`g`; a present order must match the built-in `q`. |
| `request.j` | `Option<&[u8]>` | A present cofactor must equal `(p - 1) / q`, using the built-in order whether or not `request.q` is present. |
| `result.group` | Successful schema result | Echoes only the validated built-in identity; confers no trust or policy approval. |

Optional `q` and `j` use real protobuf presence. Present-empty values are
invalid; they are not treated as absence. Leading-zero padding and ASN.1 signed
representations are rejected. DER decoding, positivity and sign-pad removal
belong to the caller's strict codec boundary. `p`, `g` and `j` cannot exceed the
selected field width; `q` cannot exceed its subgroup-order width. Validation
borrows those bytes without normalizing or copying them.

The built-in parameters are specified in
[RFC 5114 sections 2.1–2.3](https://www.rfc-editor.org/rfc/rfc5114.html#section-2).
The optional X9.42 cofactor relationship is described in
[RFC 3279 section 2.3.3](https://www.rfc-editor.org/rfc/rfc3279.html#section-2.3.3).
This native operation can check metadata extracted from different parameter
encodings; it is not an ASN.1 parser or an implementation of either container.

## Bounded arithmetic and errors

All lengths, canonical forms and exact `p`/`g`/supplied-`q` identity are checked
before cofactor arithmetic. That arithmetic uses the existing `crypto-bigint`
helpers and only built-in public widths and divisors. No attacker-selected
primality testing, generator search, modulus preprocessing or unbounded
allocation is performed. Temporary integers, quotient and remainder retain
clearing owners. The operation does not import private scalars or export keys.

Empty/oversized integer fields return `PRIMITIVE_INVALID_LENGTH`.
Noncanonical integers, mismatched parameters, inconsistent cofactors and an
elliptic-curve selection return `PRIMITIVE_INVALID_PARAMETER`. The schema
adapter rejects missing selectors, unknown enum values and unknown modifiers
through the existing checked identity and canonical error contracts; it does
not introduce a second error vocabulary.

## Regression and delivery scope

`crates/crypto/tests/prime_group_dh_parameters_tests.rs` contains independent
cofactor inputs calculated from the published RFC parameters. Its five test
functions cover all optional combinations for every built-in DH domain,
same-width cross-domain confusion, malformed and oversized integers, mismatched
`p`/`g`/`q`/`j`, elliptic-curve rejection, generated/native parity, wire-level
absent versus present-empty fields, unknown fields and clearing-owner traits.
Each function registers for both native and WASM execution.

The schema and source regression checks are compiled without executing these
tests under the requested source-only validation constraint. No new runtime,
SDK route or device-execution result is claimed. Packages remain unpublished
0.4.0 source; existing published releases are unchanged. The separate
[primefield dependency repair](primefield-release-plan.md) remains a distinct
delivery requirement and is not closed by this public-parameter validator.

| Validation | Result |
| --- | --- |
| Workspace all-target/all-feature Clippy | Passed with warnings denied |
| Native group/adapter all-target Clippy | Passed with warnings denied |
| WASM group/adapter all-target compilation | Passed with warnings denied |
| Rust 1.96.0 minimum-version all-target compilation | Passed with warnings denied; development toolchain remains 1.100.0 |
| All seven installed iOS/simulator/Android library targets | Passed with warnings denied using `native,prime-groups,operation-response` |
| Buf lint and breaking against the pinned published 0.3.17 baseline | Passed |
| Generated-contract freshness, hardening idempotence, formatting, TypeScript build and static CI policy | Passed |
| Runtime, SDK and device regression execution | Unexecuted under the retained no-tests constraint |

The mobile targets are `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
`x86_64-apple-ios`, `aarch64-linux-android`, `armv7-linux-androideabi`,
`i686-linux-android` and `x86_64-linux-android`. No package manifest, dependency
version, feature set, workflow or existing wire-field number changes.
