// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! NIST P-521 ECDSA / ES512 and ECDH primitive.

#![forbid(unsafe_code)]

mod constants;

#[cfg(feature = "native")]
mod derive_shared_secret;
#[cfg(feature = "native")]
mod encoding;
#[cfg(feature = "native")]
mod keypair;
#[cfg(feature = "native")]
mod sign;
#[cfg(feature = "native")]
mod verify;

pub use constants::{
    P521_PUBLIC_KEY_COMPRESSED_LEN, P521_PUBLIC_KEY_RAW_LEN, P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P521_SECRET_KEY_LEN, P521_SHARED_SECRET_LEN, P521_SIGNATURE_DER_MAX_LEN,
};
#[cfg(feature = "native")]
pub use derive_shared_secret::derive_p521_shared_secret;
#[cfg(feature = "native")]
pub use encoding::{
    compress_p521, compress_p521 as compress_public_key, decompress_p521,
    decompress_p521 as decompress_public_key,
};
#[cfg(feature = "native")]
pub use keypair::{generate_p521_keypair, generate_p521_keypair_from_secret_key};
#[cfg(feature = "native")]
pub use sign::sign_p521_der_prehash;
#[cfg(feature = "native")]
pub use verify::verify_p521_der_prehash;
