// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// mod.rs

mod encoding;
mod keypair;
mod sign;
mod verify;

pub use encoding::{
    assert_public_key, decode_public_key, encode_public_key, ML_DSA_44_PUBLIC_KEY_LEN,
    ML_DSA_44_SECRET_SEED_LEN, ML_DSA_44_SIGNATURE_LEN,
};
pub use keypair::{generate_ml_dsa_44_keypair, generate_ml_dsa_44_keypair_from_seed};
pub use sign::sign_ml_dsa_44;
pub use verify::verify_ml_dsa_44;
