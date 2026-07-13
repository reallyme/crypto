// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-256 ECDSA signatures and ECDH key agreement.

mod jose_signature;
mod secure_enclave_handle;

#[cfg(feature = "native")]
mod import_pem;

#[cfg(any(
    feature = "native",
    all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))
))]
mod import_secret_key;

#[cfg(any(
    feature = "native",
    all(feature = "wasm", target_arch = "wasm32", not(feature = "native"))
))]
pub use import_secret_key::generate_p256_keypair_from_secret_key;
pub use jose_signature::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_der_to_jose_signature_permissive,
    p256_ecdsa_jose_signature_to_der, P256_ECDSA_JOSE_SIGNATURE_LEN,
};
pub use secure_enclave_handle::{decode_se_handle, encode_se_handle, SE_HANDLE_PREFIX};

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    compress_p256, compress_public_key, decompress_p256, decompress_public_key,
    derive_p256_shared_secret, generate_p256_keypair, sign_p256_der_prehash,
    verify_p256_der_prehash,
};

#[cfg(feature = "native")]
pub use import_pem::{
    compressed_public_key_from_private_key, private_key_from_pem, private_key_from_pkcs8_der,
    private_key_from_pkcs8_pem, private_key_from_sec1_der, private_key_from_sec1_pem,
    public_key_from_spki_der, public_key_from_spki_pem,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{
    compress_p256, compress_public_key, decompress_p256, decompress_public_key,
    derive_p256_shared_secret, generate_p256_keypair, sign_p256_der_prehash,
    verify_p256_der_prehash,
};
