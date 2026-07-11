// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-44 (FIPS 204) post-quantum signatures.

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_dsa_44_keypair,
    generate_ml_dsa_44_keypair_from_seed, sign_ml_dsa_44, verify_ml_dsa_44,
    ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SECRET_SEED_LEN, ML_DSA_44_SIGNATURE_LEN,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "native")))]
pub use wasm::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_dsa_44_keypair,
    sign_ml_dsa_44, verify_ml_dsa_44, ML_DSA_44_PUBLIC_KEY_LEN,
};
