// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! NIST P-384 ECDSA / ES384 and ECDH primitive.

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
    P384_PUBLIC_KEY_COMPRESSED_LEN, P384_PUBLIC_KEY_RAW_LEN, P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
    P384_SECRET_KEY_LEN, P384_SHARED_SECRET_LEN, P384_SIGNATURE_DER_MAX_LEN,
};
#[cfg(feature = "native")]
pub use derive_shared_secret::derive_p384_shared_secret;
#[cfg(feature = "native")]
pub use encoding::{
    compress_p384, compress_p384 as compress_public_key, decompress_p384,
    decompress_p384 as decompress_public_key,
};
#[cfg(feature = "native")]
pub use keypair::{generate_p384_keypair, generate_p384_keypair_from_secret_key};
#[cfg(feature = "native")]
pub use sign::sign_p384_der_prehash;
#[cfg(feature = "native")]
pub use verify::verify_p384_der_prehash;
