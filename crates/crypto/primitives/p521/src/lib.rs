// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! NIST P-521 ECDSA / ES512 primitive.

#![forbid(unsafe_code)]

mod constants;
mod encoding;
mod keypair;
mod sign;
mod verify;

pub use constants::{
    P521_PUBLIC_KEY_COMPRESSED_LEN, P521_PUBLIC_KEY_RAW_LEN, P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P521_SECRET_KEY_LEN, P521_SIGNATURE_DER_MAX_LEN,
};
pub use encoding::{compress_p521, decompress_p521};
pub use keypair::{generate_p521_keypair, generate_p521_keypair_from_secret_key};
pub use sign::sign_p521_der_prehash;
pub use verify::verify_p521_der_prehash;
