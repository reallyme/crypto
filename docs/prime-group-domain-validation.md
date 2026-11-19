# Explicit DH parameter validation

With `prime-groups`, call `PrimeGroup::validate_dh_parameters(p, g, q, j)` to
match explicit parameters against one of the three built-in RFC 5114 groups.
It does not admit arbitrary groups or decide whether a protocol permits them.

| Input | Requirement |
| --- | --- |
| Selected `PrimeGroup` | One of the three RFC 5114 finite-field groups |
| `p`, `g` | Required; exactly the built-in modulus and standard generator |
| `q` | Optional; if present, exactly the built-in subgroup order |
| `j` | Optional; if present, exactly `(p - 1) / q`, using the built-in order |

Integers are minimal, nonzero, unsigned big-endian bytes. Present-empty values,
leading-zero padding and ASN.1 signed representations are rejected. Decode DER
and remove its sign padding before calling this API. Field lengths must not
exceed the selected field or subgroup width.

With `operation-response`,
`prime_groups::contract::validate_dh_parameters` accepts
`CryptoPrimeGroupDhParametersValidationRequest` and returns the validated group
identifier. Optional `q` and `j` preserve presence; absence is not empty bytes.

Empty or oversized fields return `PRIMITIVE_INVALID_LENGTH`. Noncanonical
integers, mismatches, inconsistent cofactors and elliptic-curve selections
return `PRIMITIVE_INVALID_PARAMETER`. Success establishes parameter identity,
not trust or protocol approval.

Parameter sources: [RFC 5114 §§2.1–2.3](https://www.rfc-editor.org/rfc/rfc5114.html#section-2)
and [RFC 3279 §2.3.3](https://www.rfc-editor.org/rfc/rfc3279.html#section-2.3.3).
