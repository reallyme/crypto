// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Primary facade structured operation boundary.
//!
//! Wire-format decoding and encoding stay in `crates/proto`. This module owns
//! the generated operation request/response execution boundary and routes every
//! declared branch either through the semantic operation layer or to a typed
//! unsupported-provider outcome.

#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api"
    )
))]
mod algorithms;
mod boundary;
mod error;
#[cfg(all(feature = "hpke-api", any(feature = "native", feature = "wasm")))]
mod hpke;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "secp256k1",
        feature = "x25519",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa",
        feature = "x-wing"
    )
))]
mod identifier;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf"
    )
))]
mod kdf;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
mod kem_algorithms;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "x25519",
        feature = "p256",
        feature = "p384",
        feature = "p521"
    )
))]
mod key_agreement_algorithms;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "secp256k1",
        feature = "x25519",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa",
        feature = "x-wing"
    )
))]
mod operation_error;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "x25519",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "x-wing"
    )
))]
mod operations;
mod request;
mod request_hpke;
mod request_kdf;
mod request_signature;
mod request_symmetric;
#[cfg(all(
    any(feature = "native", feature = "wasm"),
    any(
        feature = "sha2",
        feature = "sha3",
        feature = "aes",
        feature = "aes-gcm-siv",
        feature = "chacha20-poly1305",
        feature = "hmac",
        feature = "aes-kw",
        feature = "kmac",
        feature = "hkdf",
        feature = "argon2id",
        feature = "pbkdf2",
        feature = "concat-kdf",
        feature = "hpke-api",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "rsa",
        feature = "secp256k1",
        feature = "x25519",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "ml-kem-512",
        feature = "ml-kem-768",
        feature = "ml-kem-1024",
        feature = "slh-dsa",
        feature = "x-wing"
    )
))]
mod response;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "rsa",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "slh-dsa"
    )
))]
mod signature;
#[cfg(all(
    feature = "dispatch",
    any(
        feature = "rsa",
        feature = "ed25519",
        feature = "p256",
        feature = "p384",
        feature = "p521",
        feature = "secp256k1",
        feature = "ml-dsa-44",
        feature = "ml-dsa-65",
        feature = "ml-dsa-87",
        feature = "slh-dsa"
    )
))]
mod signature_algorithms;
mod wire_error;

pub use self::boundary::{
    process_operation_response, process_operation_response_json,
    process_operation_response_json_output, process_operation_response_output,
};
pub use crypto_proto::operation_response_wire::MAX_CRYPTO_OPERATION_RESPONSE_BYTES;
pub use crypto_proto::wire::{MAX_CRYPTO_PROTO_JSON_BYTES, MAX_CRYPTO_PROTO_MESSAGE_BYTES};
