// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// mod.rs

mod encapsulate;
mod encoding;
mod keypair;

pub use encapsulate::{
    ml_kem_512_decapsulate, ml_kem_512_encapsulate, ml_kem_512_encapsulate_derand,
};
pub use encoding::{
    assert_ml_kem_512_public_key, decode_ml_kem_512_public_key, encode_ml_kem_512_public_key,
    ML_KEM_512_PUBLIC_KEY_LEN,
};
pub use keypair::{
    generate_ml_kem_512_keypair, generate_ml_kem_512_keypair_from_seed, ML_KEM_512_SECRET_KEY_LEN,
};
