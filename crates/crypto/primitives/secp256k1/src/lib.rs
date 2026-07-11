// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! secp256k1 ECDSA signatures and BIP-340 Schnorr signatures.

mod constants;

pub use constants::{
    BIP340_SCHNORR_AUX_RAND_LEN, BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN,
    BIP340_SCHNORR_SIGNATURE_LEN, SECP256K1_SECRET_KEY_LEN,
};

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
mod native;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
pub use native::{
    assert_secp256k1_public_key, decode_bip340_schnorr_public_key, decode_public_key,
    decode_secp256k1_public_key, decompress_public_key, decompress_secp256k1_public_key,
    derive_bip340_schnorr_public_key, encode_bip340_schnorr_public_key, encode_public_key,
    encode_secp256k1_public_key, generate_secp256k1_keypair,
    generate_secp256k1_keypair_from_secret_key, sign_bip340_schnorr, sign_secp256k1,
    verify_bip340_schnorr, verify_secp256k1,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::{
    assert_secp256k1_public_key, decode_bip340_schnorr_public_key, decode_public_key,
    decode_secp256k1_public_key, decompress_public_key, decompress_secp256k1_public_key,
    derive_bip340_schnorr_public_key, encode_bip340_schnorr_public_key, encode_public_key,
    encode_secp256k1_public_key, generate_secp256k1_keypair, sign_bip340_schnorr, sign_secp256k1,
    verify_bip340_schnorr, verify_secp256k1,
};
