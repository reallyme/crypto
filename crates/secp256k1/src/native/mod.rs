// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

mod encoding;
mod key_agreement;
mod keypair;
mod schnorr_encode;
mod schnorr_sign;
mod schnorr_verify;
mod sign;
mod verify;

pub use encoding::{
    assert_secp256k1_public_key, decode_secp256k1_public_key as decode_public_key,
    decode_secp256k1_public_key, decompress_secp256k1_public_key as decompress_public_key,
    decompress_secp256k1_public_key, encode_secp256k1_public_key as encode_public_key,
    encode_secp256k1_public_key,
};
pub use key_agreement::{derive_secp256k1_shared_secret, Secp256k1SharedSecret};
pub use keypair::{generate_secp256k1_keypair, generate_secp256k1_keypair_from_secret_key};
pub use schnorr_encode::{
    decode_bip340_schnorr_public_key, derive_bip340_schnorr_public_key,
    encode_bip340_schnorr_public_key,
};
pub use schnorr_sign::sign_bip340_schnorr;
pub use schnorr_verify::verify_bip340_schnorr;
pub use sign::sign_secp256k1;
pub use verify::verify_secp256k1;
