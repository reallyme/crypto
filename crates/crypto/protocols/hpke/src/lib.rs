// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RFC 9180 HPKE Base-mode protocol wrapper.

#![forbid(unsafe_code)]

mod constants;
mod error;
#[cfg(feature = "native")]
mod seal;
mod types;

pub use constants::{
    HPKE_AEAD_AES_256_GCM, HPKE_AEAD_CHACHA20_POLY1305, HPKE_AEAD_TAG_LEN,
    HPKE_ENCAPSULATED_KEY_MAX_LEN, HPKE_KDF_HKDF_SHA256, HPKE_KEM_DHKEM_P256_HKDF_SHA256,
    HPKE_KEM_DHKEM_X25519_HKDF_SHA256, HPKE_P256_PRIVATE_KEY_LEN, HPKE_P256_PUBLIC_KEY_LEN,
    HPKE_X25519_PRIVATE_KEY_LEN, HPKE_X25519_PUBLIC_KEY_LEN,
};
pub use error::HpkeError;
#[cfg(all(feature = "native", feature = "test-vectors"))]
pub use seal::seal_base_derand;
#[cfg(feature = "native")]
pub use seal::{open_base, seal_base};
#[cfg(feature = "test-vectors")]
pub use types::HpkeDerandSealRequest;
pub use types::{
    HpkeOpenOutput, HpkeOpenRequest, HpkePrivateKeyBytes, HpkeSealOutput, HpkeSealRequest,
    HpkeSuite,
};
