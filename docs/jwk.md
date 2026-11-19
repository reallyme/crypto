# JWK And Multikey

JWK and multikey encode public keys. Import rejects private-key members.

The shared byte-exact contract lives in [../vectors/jwk.json](../vectors/jwk.json).
Each supported key maps to its canonical JCS JWK form and, when a stable
multicodec identifier exists, its matching multikey form.

## Encoding Policy

Classical keys use the registered JOSE shapes:

| Key family | JWK shape |
|---|---|
| Ed25519 | `kty: "OKP"` |
| X25519 | `kty: "OKP"` |
| P-256 | `kty: "EC"` |
| secp256k1 | `kty: "EC"` |

OKP `alg` and `use` members are optional for public-byte JWKs, but they are
enforced when present. Ed25519 accepts only `alg: "EdDSA"`
and `use: "sig"`; X25519 accepts only `alg: "ECDH-ES"` and `use: "enc"`.
Conflicting metadata is rejected instead of being treated as advisory.
EC `alg` and `use` are also optional on import; when supplied, P-256 requires
`ES256` and `sig`, and secp256k1 requires `ES256K` and `sig`. AKP requires
`alg`, while its `use` is optional and must match the algorithm when supplied.
Public `kid` and `x-*` extension members are accepted but do not change the
extracted key bytes. JWKS may carry additional set-level metadata. The shared
metadata policy is pinned in [../vectors/jwk_policy.json](../vectors/jwk_policy.json).
Explicit JSON `null` has the same meaning as absence for optional `alg`, `use`,
and `kid` metadata. AKP still requires a string `alg`, and required key fields
never accept null. Duplicate members remain invalid even when one value is null.
The secp256k1 encoder requires compressed SEC1 (`0x02` or `0x03` plus the
x-coordinate); the backend's compact-point extension (`0x05`) is rejected.
X25519 public-key identities require canonical field-element encodings below
2²⁵⁵ − 19. RFC 7748 agreement accepts non-canonical inputs, but those inputs
would give the same key multiple JWK or multikey identifiers.

Imports reject duplicate members, private-key members, mixed JWK shapes and
unknown non-extension members. Oversized values return typed length errors.

Ed25519 envelopes require a canonical, nonidentity prime-subgroup point.
Swift requires the bundled Rust C ABI validator for this check. A valid point
does not prove possession of its secret key.

EC `x` and `y` must describe the same valid curve point; mismatched coordinates
are invalid even if their parity could select a point.

JWK-to-Multikey conversion consumes this same validated public-key boundary.
It does not independently decode coordinates or bypass `alg`/`use`, key-length,
or exact-coordinate policy.

Post-quantum and hybrid keys use this package's asymmetric-key-pair profile:

| Field | Meaning |
|---|---|
| `kty: "AKP"` | Algorithm-bound asymmetric key pair. |
| `alg` | Concrete algorithm name. |
| `pub` | Base64url-encoded public key bytes. |
| `use` | `sig` for signature keys or `enc` for KEM keys. |

In this contract, AKP means an algorithm-bound asymmetric key pair. The
algorithm name, not a curve name, identifies the public-key byte format.
If `use` is present, signature algorithms require `sig` and KEM algorithms
require `enc`.

## Multikey Availability

This package supports JWKs but no Multikey mapping for SLH-DSA-SHA2-128s and
X-Wing-768. Their vector entries use:

```json
{
  "multikey_status": "multicodec-missing",
  "multikey": null
}
```

Conversion returns a typed unsupported result; no provisional identifier is emitted.

## Changing The Contract

Changing this encoding is a wire-contract change. Update the Rust envelope
contract first, regenerate [../vectors/jwk.json](../vectors/jwk.json), and then
make the Swift, Kotlin, and TypeScript facades pass the same vectors
independently.
