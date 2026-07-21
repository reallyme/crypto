// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA (FIPS 205) hash-based post-quantum signatures.

mod constants;

pub use constants::{
    SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN, SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN,
    SLH_DSA_SHA2_128S_SECRET_KEY_LEN, SLH_DSA_SHA2_128S_SIGNATURE_LEN,
};

#[cfg(any(feature = "native", feature = "wasm"))]
mod native;

#[cfg(any(feature = "native", feature = "wasm"))]
pub use native::{
    decode_slh_dsa_sha2_128s_public_key, derive_slh_dsa_sha2_128s_keypair,
    encode_slh_dsa_sha2_128s_public_key, generate_slh_dsa_sha2_128s_keypair,
    sign_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128s,
};
