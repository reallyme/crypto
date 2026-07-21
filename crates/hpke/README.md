<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-hpke

`reallyme-crypto-hpke` exposes typed RFC 9180 and post-quantum HPKE component
identifiers. Suites are explicit `(KEM, KDF, AEAD)` values; unknown algorithms
and registered algorithms without an installed implementation fail closed with
typed errors.

Private keys, plaintext outputs, and exporter outputs have zeroizing owners.
Callers remain responsible for protecting public-key authenticity, generating
high-entropy PSKs, and binding application context through `info` and AAD.

HPKE derives the AEAD key and 12-byte nonce inside the sender and receiver
contexts. `HpkeSealRequest` therefore has no nonce field, and callers cannot
inject a random or externally selected nonce. A fresh Base-mode seal obtains
new KEM randomness from the operating system. Deterministic KEM randomness is
available only through the `test-vectors` feature and is intended exclusively
for reproducible conformance vectors.

```rust
#[cfg(feature = "native")]
fn main() -> Result<(), crypto_hpke::HpkeError> {
    use crypto_hpke::{
        derive_keypair, open_base, seal_base, HpkeOpenRequest, HpkeSealRequest,
        HPKE_MLKEM1024P384_SHAKE256_AES256GCM,
    };

    let suite = HPKE_MLKEM1024P384_SHAKE256_AES256GCM;
    let input_key_material = [0x5a; 32];
    let recipient = derive_keypair(suite, &input_key_material)?;
    let sealed = seal_base(&HpkeSealRequest {
        suite,
        recipient_public_key: &recipient.public_key,
        info: b"reallyme/example/v1",
        aad: b"message metadata",
        plaintext: b"confidential payload",
    })?;
    let opened = open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient.private_key(),
        info: b"reallyme/example/v1",
        aad: b"message metadata",
        ciphertext: &sealed.ciphertext,
    })?;

    assert_eq!(opened.plaintext.as_slice(), b"confidential payload");
    Ok(())
}

#[cfg(not(feature = "native"))]
fn main() {}
```

## IANA registry and runtime support

The identifier enums cover the complete assigned IANA HPKE registry snapshot
dated 2026-04-16. Registry recognition and runtime support are deliberately
separate: `support()` returns `Executable` or `RegisteredUnavailable`, and any
unavailable component fails before backend setup with `UnsupportedKem` or
`UnsupportedKdf`. Registry-only entries are parser metadata, not deferred
implementation commitments or advertised package algorithms.

| KEM ID | KEM | `native`/`wasm` runtime |
|---:|---|---|
| `0x0010` | DHKEM(P-256, HKDF-SHA256) | Executable |
| `0x0011` | DHKEM(P-384, HKDF-SHA384) | Executable |
| `0x0012` | DHKEM(P-521, HKDF-SHA512) | Executable |
| `0x0013` | DHKEM(CP-256, HKDF-SHA256) | Registered, unavailable |
| `0x0014` | DHKEM(CP-384, HKDF-SHA384) | Registered, unavailable |
| `0x0015` | DHKEM(CP-521, HKDF-SHA512) | Registered, unavailable |
| `0x0016` | DHKEM(secp256k1, HKDF-SHA256) | Executable |
| `0x0020` | DHKEM(X25519, HKDF-SHA256) | Executable |
| `0x0021` | DHKEM(X448, HKDF-SHA512) | Executable |
| `0x0022` | DHKEM(X25519+Elligator, HKDF-SHA256) | Registered, unavailable |
| `0x0030` | X25519Kyber768Draft00 | Registered, unavailable |
| `0x0040` | ML-KEM-512 | Executable |
| `0x0041` | ML-KEM-768 | Executable |
| `0x0042` | ML-KEM-1024 | Executable |
| `0x0050` | MLKEM768-P256 | Executable |
| `0x0051` | MLKEM1024-P384 | Executable |
| `0x647a` | X-Wing | Executable |

| KDF ID | KDF | `native`/`wasm` runtime |
|---:|---|---|
| `0x0001` | HKDF-SHA256 | Executable |
| `0x0002` | HKDF-SHA384 | Executable |
| `0x0003` | HKDF-SHA512 | Executable |
| `0x0010` | SHAKE128 | Registered, unavailable |
| `0x0011` | SHAKE256 | Executable |
| `0x0012` | TurboSHAKE128 | Registered, unavailable |
| `0x0013` | TurboSHAKE256 | Registered, unavailable |

All four registered AEAD identifiers are represented: AES-128-GCM (`0x0001`),
AES-256-GCM (`0x0002`), ChaCha20-Poly1305 (`0x0003`), and export-only
(`0xffff`). Export-only is accepted only by exporter operations; seal/open
reject it with a typed unsupported-suite error.
