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

OpenMLS integrations can establish PSK mode with suite-generic live contexts.
`setup_sender_psk` returns the encapsulated key and an opaque
`HpkeSenderContext`, allowing the caller to bind the encapsulated key into
targeted-message AAD before calling `seal`. `setup_receiver_psk` consumes that
encapsulated key and returns the matching `HpkeReceiverContext` for `open`.
Both contexts are neither cloneable nor serializable and zeroize traffic state
on drop. Their setup requests require validated `HpkePskRef` and
`HpkePskIdRef` values so secret material and its public identifier cannot be
swapped accidentally. The single-shot PSK APIs remain source-compatible.
They delegate to these same live context paths and do not maintain a parallel
PSK key schedule.

`derive_keypair_from_ikm` accepts non-empty arbitrary-length MLS input keying
material and delegates normalization to the selected KEM's registered HPKE
`DeriveKeyPair` procedure. The stricter `derive_keypair` entry point
continues to require suite-sized input for callers whose protocol already owns
that contract.

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
        HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM,
    };

    let suite = HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM;
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

The Rust API also names the draft MLS profiles directly:

- `MLS_192_MLKEM1024_AES256GCM_SHA384_P384`
- `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`
- `MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384`

The draft-06 profiles select HPKE HKDF-SHA384 (`0x0002`) because MLS requires
separate Extract and Expand operations. The final suffix identifies the MLS
signature profile and is not part of the HPKE triple. The first two aliases
therefore resolve to the same ML-KEM-1024, HKDF-SHA384, AES-256-GCM suite.

The `test-vectors` feature exposes deterministic Base-mode seal, Base-mode
sender export, and PSK sender setup for reproducible conformance data. The root
facade supplies matching operation-layer wrappers so vectors exercise the same
secret-material policy and `OperationError` mapping as production operations.
Published production integrations must use the randomized setup functions.

## Feature selection

`native` remains the compatibility aggregate for the complete reviewed HPKE
implementation. Protocol adapters can instead select the individual `kem-*`,
`kdf-*`, and `aead-*` features they execute. Each component feature includes
the internal native backend automatically; registered components that were not
selected remain recognizable but fail closed as unavailable.

The `openmls` aggregate enables only ML-KEM-1024, ML-KEM-1024/P-384, X-Wing,
HKDF-SHA256, HKDF-SHA384, AES-256-GCM, and ChaCha20-Poly1305. It deliberately
does not enable P-256, P-521, secp256k1, X448, the SHAKE256 HPKE KDF, or
unrelated KDF and AEAD implementations. ML-KEM still brings its required
SHAKE primitive dependency for KEM-internal operations. Consumers needing
another reviewed component can compose its individual feature explicitly.

## IANA registry and runtime support

The identifier enums cover the complete assigned IANA HPKE registry snapshot
dated 2026-04-16. Registry recognition and runtime support are deliberately
separate: `support()` returns `Executable` or `RegisteredUnavailable`, and any
unavailable component fails before backend setup with `UnsupportedKem` or
`UnsupportedKdf`. Registry-only entries are parser metadata, not deferred
implementation commitments or advertised package algorithms.

| KEM ID | KEM | `native` compatibility aggregate |
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

| KDF ID | KDF | `native` compatibility aggregate |
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
