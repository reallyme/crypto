# Fuzzing

Rust libFuzzer targets exercise public parsing and operation boundaries. They do
not cover Swift, Kotlin or TypeScript decoders directly. General codec parsers
belong to the Codec repository; these targets test crypto-specific validation.

## Targets

| Target | Parser under test | Entry point |
| --- | --- | --- |
| `rsa_der` | RSA public-key DER (PKCS#1 / SPKI) | `crypto_rsa::{verify_rsa_pkcs1v15, verify_rsa_pss}` |
| `p256_point` | P-256 SEC1 point + ECDSA DER signature | `crypto_p256::{decompress_p256, verify_p256_sha256_message_der_interoperable}` |
| `operation_response` | Crypto operation-response boundary | `reallyme_crypto::operation_contract::process_operation_response` |
| `jwk_multikey` | Public JWK and multikey parsers | `envelopes_jwk::{Jwk, Jwks}` and `envelopes_jwk_multikey::multikey_to_jwk` |
| `key_encodings` | NIST/secp256k1 SEC1, ECDSA DER/JOSE, P-256 PKCS#8/SEC1/SPKI DER and PEM, BIP-340 public keys, Secure Enclave handles | Public encoding/import helpers in the P-256, P-384, P-521, and secp256k1 modules |
| `post_quantum_encodings` | Fixed-width ML-KEM public keys/ciphertexts and ML-DSA/SLH-DSA public keys/signatures | Native post-quantum decode, decapsulation, and verification entrypoints |
| `operation_family_boundaries` | HPKE suite and sealed-message inputs plus HKDF, PBKDF2, and JWA Concat KDF parameter wrappers | `crypto_hpke`, `crypto_hkdf`, `crypto_pbkdf2`, and `crypto_concat_kdf` typed boundary constructors |

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

CI builds the targets; the scheduled workflow runs them with time limits and
retains crashes. A successful build is not a fuzzing result. New formats need
valid corpus inputs as well as malformed and oversized cases.
