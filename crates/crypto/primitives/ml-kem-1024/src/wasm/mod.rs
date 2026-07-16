// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

mod encapsulate;
mod encoding;
mod keypair;

pub use encapsulate::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate};
pub use encoding::{
    assert_public_key, decode_public_key, encode_public_key, ML_KEM_1024_PUBLIC_KEY_LEN,
    ML_KEM_1024_SECRET_KEY_LEN,
};
pub use keypair::generate_ml_kem_1024_keypair;
