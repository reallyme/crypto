# reallyme-crypto-dispatch

Algorithm-selected signatures, key agreement, KEM and public-key encoding.
Applications normally use the re-exports in `reallyme-crypto`.

```rust
# #[cfg(feature = "ed25519")]
# fn main() -> Result<(), crypto_dispatch::AlgorithmError> {
use crypto_core::Algorithm;
use crypto_dispatch::{generate_keypair, sign, verify};

let (public, secret) = generate_keypair(Algorithm::Ed25519)?;
let signature = sign(Algorithm::Ed25519, &secret, b"message")?;
verify(Algorithm::Ed25519, &public, b"message", &signature)?;
assert!(verify(Algorithm::Ed25519, &public, b"tampered", &signature).is_err());
# Ok(())
# }
# #[cfg(not(feature = "ed25519"))]
# fn main() {}
```

Select an execution lane and the required algorithm features. Unsupported
operations and invalid signatures return typed errors. For hash, MAC and AEAD,
use `reallyme_crypto::operations::{hash, mac, aead}` or the corresponding facade
re-exports.

`crypto_dispatch::provider::provider_decision(operation, algorithm)` returns an
inspectable `ProviderDecision` before execution. It records the selected or
rejected provider, execution lane, key residency and output cleanup policy.
Use it to inspect a build's capabilities; it does not execute the operation.
