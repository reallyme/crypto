<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-dispatch

`reallyme-crypto-dispatch` owns algorithm-selected
signatures, key agreement, key encapsulation, and public-key encoding. It is
normally consumed through the public `reallyme-crypto` facade.

Dispatch operations fail closed with typed `AlgorithmError` values. Secret
outputs use zeroizing owners, and primitive crates retain responsibility for
cryptographic validation and constant-time verification.

## Fail-closed signature verification

```rust
// This example requires the `ed25519` feature.
# #[cfg(feature = "ed25519")]
# fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
use crypto_core::Algorithm;
use crypto_dispatch::{generate_keypair, sign, verify};

let (public, secret) = generate_keypair(Algorithm::Ed25519)?;
let signature = sign(Algorithm::Ed25519, &secret, b"message")?;
verify(Algorithm::Ed25519, &public, b"message", &signature)?;

// Invalid signatures are typed errors, never `Ok(false)`.
assert!(verify(Algorithm::Ed25519, &public, b"tampered", &signature).is_err());
# Ok(())
# }
# #[cfg(not(feature = "ed25519"))]
# fn main() {}
```

## Hash ownership

Hash selection is owned by `reallyme_crypto::operations::hash`, leaving one
semantic hash selector. Applications should use
`reallyme_crypto::dispatch::hash_digest`; adapters should call
`reallyme_crypto::operations::hash::digest` directly.

## MAC ownership

MAC selection is owned by `reallyme_crypto::operations::mac`, leaving one
semantic MAC selector. Applications should use `reallyme_crypto::dispatch::{mac_authenticate,
mac_verify}`; adapters should call `reallyme_crypto::operations::mac` directly.

## AEAD ownership

AEAD selection is owned by `reallyme_crypto::operations::aead`, leaving one
semantic AEAD selector. Applications should use `reallyme_crypto::dispatch::{aead_encrypt,
aead_decrypt}`; adapters should call `reallyme_crypto::operations::aead`
directly.
