<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-x-wing

X-Wing hybrid KEM primitives for ReallyMe Crypto.

This crate implements the draft X-Wing construction over X25519 and ML-KEM-768,
plus a ReallyMe `X-Wing-1024` suite that keeps the same combiner shape with
ML-KEM-1024.

The X-Wing-768 construction follows the IETF CFRG Internet-Draft
[`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).
X-Wing-1024 is a ReallyMe suite variant using ML-KEM-1024.

The private key is a 32-byte seed. The public key is the ML-KEM public key
followed by the X25519 public key. The ciphertext is the ML-KEM ciphertext
followed by the X25519 ephemeral public key.

All secret outputs are returned in `Zeroizing<Vec<u8>>`. Deterministic keygen
and encapsulation entry points exist so conformance vectors can be reproduced
exactly; production callers should use the randomized keygen and encapsulation
functions.
