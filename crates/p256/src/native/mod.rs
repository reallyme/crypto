// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod derive_shared_secret;
mod encoding;
mod keypair;
mod sign;
mod sign_digest;
mod verify;
mod verify_digest;

pub use derive_shared_secret::derive_p256_shared_secret;
pub use encoding::{
    compress_p256 as compress_public_key, compress_p256, decompress_p256 as decompress_public_key,
    decompress_p256,
};
pub use keypair::generate_p256_keypair;
#[allow(deprecated)]
pub use sign::sign_p256_der_prehash;
pub use sign::sign_p256_sha256_message_low_s_der;
#[allow(deprecated)]
pub use sign_digest::sign_p256_digest_der;
pub use sign_digest::sign_p256_sha256_digest_low_s_der;
#[allow(deprecated)]
pub use verify::verify_p256_der_prehash;
pub use verify::verify_p256_sha256_message_der_interoperable;
#[allow(deprecated)]
pub use verify_digest::verify_p256_digest_der;
pub use verify_digest::verify_p256_sha256_digest_low_s_der;
