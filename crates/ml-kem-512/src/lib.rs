// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-512 (FIPS 203) post-quantum key encapsulation.

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    assert_ml_kem_512_public_key, assert_ml_kem_512_public_key as assert_public_key,
    decode_ml_kem_512_public_key, decode_ml_kem_512_public_key as decode_public_key,
    encode_ml_kem_512_public_key, encode_ml_kem_512_public_key as encode_public_key,
    generate_ml_kem_512_keypair, generate_ml_kem_512_keypair_from_seed, ml_kem_512_decapsulate,
    ml_kem_512_encapsulate, ml_kem_512_encapsulate_derand, ML_KEM_512_PUBLIC_KEY_LEN,
    ML_KEM_512_SECRET_KEY_LEN,
};
