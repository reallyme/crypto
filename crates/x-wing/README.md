<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-x-wing

X-Wing hybrid KEM primitives for ReallyMe Crypto.

This crate implements the draft X-Wing construction over X25519 and ML-KEM-768.

The X-Wing construction follows the IETF CFRG Internet-Draft
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

The private key is a 32-byte seed. The public key is the ML-KEM public key
followed by the X25519 public key. The ciphertext is the ML-KEM ciphertext
followed by the X25519 ephemeral public key.

Decapsulation follows the X-Wing draft combiner semantics and does not add a
separate X25519 contributory-behavior rejection for the ciphertext component.
Low-order X25519 ciphertext components therefore feed the combiner instead of
creating an additional decapsulation-failure oracle.

All secret outputs are returned in `Zeroizing<Vec<u8>>`. Deterministic keygen
and encapsulation entry points exist so conformance vectors can be reproduced
exactly; production callers should use the randomized keygen and encapsulation
functions.
