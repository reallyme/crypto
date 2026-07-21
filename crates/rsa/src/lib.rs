// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RSA signature verification primitive.

#![forbid(unsafe_code)]

mod constants;
mod hash;
mod key;
mod pss;
mod types;
mod verify;

pub use constants::{
    RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS, RSA_PUBLIC_KEY_DER_MAX_LEN, RSA_SIGNATURE_MAX_LEN,
};
pub use types::{RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};
pub use verify::{verify_rsa_pkcs1v15, verify_rsa_pss};
