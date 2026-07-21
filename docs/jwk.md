<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# JWK And Multikey

JWK and multikey are envelope formats over public key bytes. They are not
cryptographic primitive identifiers, so they live in the envelope and facade
layers rather than in proto or the C ABI.

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

Deserialization dispatches on `kty` explicitly. Duplicate members, private-key
members, mixed JWK shapes, and unknown non-extension members are rejected before
key extraction. Public members are length-checked before base64url decoding so
oversized values cannot trigger a second attacker-proportional allocation.

EC JWK import treats both coordinates as identity-bearing input. The parser
reconstructs the compressed SEC1 key, decompresses it through the reviewed curve
primitive, and compares the recovered `x` and `y` coordinates byte-for-byte with
the supplied JWK members. Mismatched coordinates are invalid even when their
parity would otherwise identify a decomposable point.

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

## Why AKP

ML-DSA, ML-KEM, SLH-DSA, and X-Wing are not encoded as `OKP`, because OKP is
the RFC 8037 Ed/X curve key type and would make post-quantum keys look like
curve keys.

The package also does not introduce a `PQK` or `PQX` key type. Those names
would bake in either a post-quantum-only category or an X-Wing/hybrid-specific
category where the actual invariant is broader. `AKP` keeps the envelope
generic while requiring the `alg` field to bind the bytes to a concrete
algorithm.

## Multikey Availability

Some AKP keys intentionally have JWK vectors before they have multikey vectors.
SLH-DSA-SHA2-128s and X-Wing-768 are waiting on stable Multicodec public key
identifiers, so their vector entries use:

```json
{
  "multikey_status": "multicodec-missing",
  "multikey": null
}
```

The package does not emit provisional numeric identifiers. Doing so would
freeze an unreviewed wire contract. Those vectors should gain multikey values
only after the Multicodec table is updated.

## Changing The Contract

Changing this encoding is a wire-contract change. Update the Rust envelope
contract first, regenerate [../vectors/jwk.json](../vectors/jwk.json), and then
make the Swift, Kotlin, and TypeScript facades pass the same vectors
independently.
