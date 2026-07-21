// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-87 (FIPS 204) post-quantum signatures.

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    assert_public_key, decode_public_key, encode_public_key, generate_ml_dsa_87_keypair,
    generate_ml_dsa_87_keypair_from_seed, sign_ml_dsa_87, verify_ml_dsa_87,
    ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SECRET_SEED_LEN, ML_DSA_87_SIGNATURE_LEN,
};
