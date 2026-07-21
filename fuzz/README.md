<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Fuzzing Harnesses

Coverage-guided libFuzzer targets for the untrusted-input parsers: the places
that turn attacker-controlled bytes into structured values. Every target asserts
the same baseline safety property: arbitrary input must not panic, overflow,
read out of bounds, or run unbounded. Parsing fails closed with a typed error.

This crate is intentionally outside the main Cargo workspace. It declares its
own empty `[workspace]` so it does not inherit lint settings that libFuzzer's
`#![no_main]` runtime would violate. The root workspace lists `fuzz` under
`[workspace] exclude`.

## Targets

| Target | Parser under test | Entry point |
| --- | --- | --- |
| `rsa_der` | RSA public-key DER (PKCS#1 / SPKI) | `crypto_rsa::{verify_rsa_pkcs1v15, verify_rsa_pss}` |
| `p256_point` | P-256 SEC1 point + ECDSA DER signature | `crypto_p256::{decompress_p256, verify_p256_der_prehash}` |
| `operation_response` | Crypto operation-response boundary | `reallyme_crypto::operation_contract::process_operation_response` |
| `jwk_multikey` | Public JWK and multikey parsers | `envelopes_jwk::{Jwk, Jwks}` and `envelopes_jwk_multikey::multikey_to_jwk` |
| `key_encodings` | NIST/secp256k1 SEC1, ECDSA DER/JOSE, P-256 PKCS#8/SEC1/SPKI DER and PEM, BIP-340 public keys, Secure Enclave handles | Public encoding/import helpers in the P-256, P-384, P-521, and secp256k1 modules |
| `post_quantum_encodings` | Fixed-width ML-KEM public keys/ciphertexts and ML-DSA/SLH-DSA public keys/signatures | Native post-quantum decode, decapsulation, and verification entrypoints |
| `operation_family_boundaries` | HPKE suite and sealed-message inputs plus HKDF, PBKDF2, and JWA Concat KDF parameter wrappers | `crypto_hpke`, `crypto_hkdf`, `crypto_pbkdf2`, and `crypto_concat_kdf` typed boundary constructors |

## Boundary Coverage

The target list is an evidence inventory, not a claim that every boundary is
already fuzzed. The following status must be reviewed whenever a parser,
serialization format, or language adapter is added:

| Boundary family | Current fuzz status | Required follow-up |
| --- | --- | --- |
| Binary operation protobuf and strict operation ProtoJSON | Covered by `operation_response` | Keep all operation families enabled in the target and seed the corpus with valid requests. |
| JWK, JWKS, and public multikey conversion | Covered by `jwk_multikey` | Add corpus entries for every supported curve, RSA shape, and rejected private/public mismatch. |
| RSA PKCS#1/SPKI DER | Covered by `rsa_der` | Retain malformed length, nesting, integer, and trailing-data cases. |
| P-256 SEC1 points and ECDSA DER | Covered by `p256_point` | Extend equivalent coverage to other exposed elliptic-curve encoded boundaries. |
| Generated protobuf requests, operation responses, and structured errors | Covered by `operation_response` | Keep raw arbitrary input plus mutations of valid structured responses. |
| NIST/secp256k1 public-key, key-container, and ECDSA signature encodings | Covered by `p256_point` and `key_encodings` | Add new key-container formats to `key_encodings` when they become public. |
| Post-quantum key, ciphertext, and signature encodings | Covered by `post_quantum_encodings` | The harness synthesizes exact-width candidates so mutations pass outer length checks. |
| HPKE sealed-message and KDF parameter boundaries | Covered by `operation_family_boundaries` | Keep HPKE registered component parsing, open/open-PSK validation, HKDF suite selection, PBKDF2 iteration constructors, and Concat KDF length prefixing in one target. |
| Swift, Kotlin/JVM, Android, JNI, and TypeScript adapter decoders | Not directly covered | Add platform-native property or fuzz harnesses; Rust fuzzing does not prove managed-runtime decoder safety. |
| Provider-specific key import and protocol message decoders | Partial through operation dispatch | Inventory each exposed encoding and add a direct target when dispatch cannot reach its full parser state. |

Codec-owned multibase, multicodec, DAG-CBOR, and general base64url parsers are
outside this repository's assurance scope and must be fuzzed in
`reallyme/codec`. Crypto must still fuzz any crypto-specific wrapper that adds
semantic validation around those values.

A boundary is considered covered only when the scheduled workflow runs its
target, a useful valid-input corpus reaches structured parsing, malformed and
oversized inputs are accepted by the harness, crashes are retained, and the
target has an owner. Building a harness without scheduled execution is only a
bit-rot check.

## Running

Requires a nightly toolchain (libFuzzer) and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.2 --locked

# From the repository root:
cargo +nightly fuzz run operation_response
cargo +nightly fuzz run jwk_multikey
cargo +nightly fuzz run key_encodings
cargo +nightly fuzz run rsa_der -- -max_total_time=60   # time-boxed
cargo +nightly fuzz run post_quantum_encodings
cargo +nightly fuzz run operation_family_boundaries
cargo +nightly fuzz list                                 # all targets
```

Reproduce a crash artifact:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

## CI

Targets are built (not run to convergence) in CI as a smoke check so they cannot
bit-rot. A scheduled job runs each target time-boxed; any crash artifact is
uploaded and fails the job.
