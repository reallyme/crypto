<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Formal Models

This directory contains symbolic models for protocol compositions in the crypto
layer, checked with [Tamarin](https://tamarin-prover.github.io/).

Cryptographic primitives such as AES, SHA-2, and ML-KEM are validated by
conformance vectors and fuzzing, not by symbolic proofs. A symbolic model
reasons about how primitives are composed, treating each primitive as an
idealized function.

## Models

| Model | Composition | Proves |
| --- | --- | --- |
| [`tamarin/hpke_base.spthy`](tamarin/hpke_base.spthy) | HPKE Base mode (RFC 9180): DHKEM encap/decap + HKDF key schedule + AEAD | **Plaintext confidentiality** against a network adversary, unless the recipient's static key is revealed |

The HPKE model is suite-agnostic: DH is the built-in `diffie-hellman` theory, so
it covers both package suites (DHKEM-P256-…-AES-256-GCM and
DHKEM-X25519-…-ChaCha20-Poly1305). HKDF is abstracted as a PRF chain and the
AEAD as authenticated encryption. It keeps RFC 9180 `info` and AEAD `aad`
separate, matching the Rust wrapper's `HpkeSealRequest` / `HpkeOpenRequest`
fields. HPKE Base intentionally provides **no** sender authentication, so the
model does not claim it.

Each model carries an `exists-trace` sanity lemma so the security lemmas cannot
pass vacuously.

## Checking

Requires `tamarin-prover` on `PATH`:

```sh
tamarin-prover --prove formal/tamarin/hpke_base.spthy
```

Expected result:

```
sanity_roundtrip_exists (exists-trace): verified
plaintext_secrecy (all-traces): verified
```

Interactive exploration:

```sh
tamarin-prover interactive formal/tamarin/
```
