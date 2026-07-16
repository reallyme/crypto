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
| `proto_process` | Crypto process-proto operation boundary | `reallyme_crypto::proto_process::process_proto` |
| `jwk_multikey` | Public JWK and multikey parsers | `envelopes_jwk::{Jwk, Jwks}` and `envelopes_jwk_multikey::multikey_to_jwk` |

## Running

Requires a nightly toolchain (libFuzzer) and `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.2 --locked

# From the repository root:
cargo +nightly fuzz run proto_process
cargo +nightly fuzz run jwk_multikey
cargo +nightly fuzz run rsa_der -- -max_total_time=60   # time-boxed
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
