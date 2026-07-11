// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! NIST P-384 ECDSA / ES384 primitive.

#![forbid(unsafe_code)]

mod constants;
mod encoding;
mod keypair;
mod sign;
mod verify;

pub use constants::{
    P384_PUBLIC_KEY_COMPRESSED_LEN, P384_PUBLIC_KEY_RAW_LEN, P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P384_SECRET_KEY_LEN, P384_SIGNATURE_DER_MAX_LEN,
};
pub use encoding::{compress_p384, decompress_p384};
pub use keypair::{generate_p384_keypair, generate_p384_keypair_from_secret_key};
pub use sign::sign_p384_der_prehash;
pub use verify::verify_p384_der_prehash;
