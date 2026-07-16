// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! npm-facing WebAssembly bindings for ReallyMe Crypto.

#![forbid(unsafe_code)]

mod aead;
mod argon2id;
mod hpke;
mod key_wrap;
mod map_error;
mod ml_dsa;
mod ml_kem;
mod rsa;
mod slh_dsa;
mod validate_bytes;
mod x_wing;

pub use aead::{
    aes_256_gcm_open, aes_256_gcm_seal, aes_256_gcm_siv_open, aes_256_gcm_siv_seal,
    chacha20_poly1305_open, chacha20_poly1305_seal, xchacha20_poly1305_open,
    xchacha20_poly1305_seal,
};
pub use argon2id::argon2id_derive_key;
pub use hpke::{hpke_open_base, hpke_seal_base, hpke_seal_base_derand};
pub use key_wrap::{aes_256_kw_unwrap_key, aes_256_kw_wrap_key};
pub use ml_dsa::{
    ml_dsa_44_generate_keypair, ml_dsa_44_sign, ml_dsa_44_verify, ml_dsa_65_generate_keypair,
    ml_dsa_65_sign, ml_dsa_65_verify, ml_dsa_87_generate_keypair, ml_dsa_87_sign, ml_dsa_87_verify,
};
pub use ml_kem::{
    ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate_keypair,
    ml_kem_512_decapsulate, ml_kem_512_encapsulate, ml_kem_512_generate_keypair,
    ml_kem_768_decapsulate, ml_kem_768_encapsulate, ml_kem_768_generate_keypair,
};
pub use rsa::{rsa_verify_pkcs1v15, rsa_verify_pss};
pub use slh_dsa::{
    slh_dsa_sha2_128s_derive_keypair, slh_dsa_sha2_128s_generate_keypair, slh_dsa_sha2_128s_sign,
    slh_dsa_sha2_128s_verify,
};
pub use x_wing::{
    x_wing_1024_decapsulate, x_wing_1024_derive_keypair, x_wing_1024_encapsulate,
    x_wing_1024_encapsulate_derand, x_wing_1024_generate_keypair, x_wing_768_decapsulate,
    x_wing_768_derive_keypair, x_wing_768_encapsulate, x_wing_768_encapsulate_derand,
    x_wing_768_generate_keypair,
};
