// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! P-256 ECDSA signatures and ECDH key agreement.

mod jose_signature;
mod secure_enclave_handle;

pub use jose_signature::{
    p256_ecdsa_der_to_jose_signature, p256_ecdsa_der_to_jose_signature_permissive,
    p256_ecdsa_jose_signature_to_der, P256_ECDSA_JOSE_SIGNATURE_LEN,
};
pub use secure_enclave_handle::{decode_se_handle, encode_se_handle, SE_HANDLE_PREFIX};

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
mod native;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
pub use native::{
    compress_p256, compress_public_key, decompress_p256, decompress_public_key,
    derive_p256_shared_secret, generate_p256_keypair, generate_p256_keypair_from_secret_key,
    sign_p256_der_prehash, verify_p256_der_prehash,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::{
    compress_p256, compress_public_key, decompress_p256, decompress_public_key,
    derive_p256_shared_secret, generate_p256_keypair, sign_p256_der_prehash,
    verify_p256_der_prehash,
};
