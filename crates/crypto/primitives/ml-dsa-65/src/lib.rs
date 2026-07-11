// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-65 (FIPS 204) post-quantum signatures.

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
mod native;

#[cfg(all(feature = "native", not(all(feature = "wasm", target_arch = "wasm32"))))]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_dsa_65_keypair,
    generate_ml_dsa_65_keypair_from_seed, sign_ml_dsa_65, verify_ml_dsa_65,
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_SEED_LEN, ML_DSA_65_SIGNATURE_LEN,
};

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use wasm::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_dsa_65_keypair,
    sign_ml_dsa_65, verify_ml_dsa_65, ML_DSA_65_PUBLIC_KEY_LEN,
};
