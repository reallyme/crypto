// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RSA signature verification primitive.

#![forbid(unsafe_code)]

mod constants;
#[cfg(feature = "proto")]
mod convert_proto_identity;
mod hash;
mod key;
/// Protected standalone public-representative and independent-PSS operations.
#[cfg(feature = "proto")]
pub mod proto_operations;
/// Protected protobuf options and request adapters.
#[cfg(feature = "proto")]
pub mod proto_options;
mod pss;
mod representative;
mod types;
mod verify;

pub use constants::{
    RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS, RSA_PUBLIC_KEY_DER_MAX_LEN, RSA_SIGNATURE_MAX_LEN,
};
pub use types::{RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};
pub use verify::{verify_rsa_pkcs1v15, verify_rsa_pss};

pub use representative::{
    rsa_public_representatives, RsaPublicRepresentatives, RsaRepresentativeError,
};
