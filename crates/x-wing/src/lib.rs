// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! X-Wing hybrid KEM suites over X25519 and ML-KEM.

#![forbid(unsafe_code)]

mod combine;
mod decapsulate;
mod encapsulate;
mod expand;
mod generate;
mod random;
mod suite;

pub use decapsulate::x_wing_768_decapsulate;
pub use encapsulate::{x_wing_768_encapsulate, x_wing_768_encapsulate_derand};
pub use generate::{generate_x_wing_768_keypair, generate_x_wing_768_keypair_derand};
pub use suite::{
    X_WING_768_CIPHERTEXT_LEN, X_WING_768_PUBLIC_KEY_LEN, X_WING_ENCAPS_SEED_LEN,
    X_WING_SECRET_KEY_LEN, X_WING_SHARED_SECRET_LEN,
};
