// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-1024 (FIPS 203) post-quantum key encapsulation.

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    assert_ml_kem_1024_public_key, decode_ml_kem_1024_public_key,
    decode_ml_kem_1024_public_key as decode_public_key, encode_ml_kem_1024_public_key,
    encode_ml_kem_1024_public_key as encode_public_key, generate_ml_kem_1024_keypair,
    generate_ml_kem_1024_keypair_from_seed, ml_kem_1024_decapsulate, ml_kem_1024_encapsulate,
    ml_kem_1024_encapsulate_derand, ML_KEM_1024_PUBLIC_KEY_LEN, ML_KEM_1024_SECRET_KEY_LEN,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_kem_1024_keypair,
    ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ML_KEM_1024_PUBLIC_KEY_LEN,
    ML_KEM_1024_SECRET_KEY_LEN,
};
