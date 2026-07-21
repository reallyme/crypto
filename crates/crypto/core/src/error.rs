// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Typed, secret-free error taxonomy shared across crypto crates.

mod aead;
mod kdf;
mod key_wrap;
mod mac;
mod rng;
mod signature;
mod taxonomy;

pub use self::aead::{AeadBackend, AeadFailureKind};
pub use self::kdf::{HkdfFailureKind, HkdfHash, KdfAlgorithm, KdfFailureKind, KdfProfile};
pub use self::key_wrap::{KeyWrapAlgorithm, KeyWrapFailureKind, KeyWrapOperation};
pub use self::mac::{MacFailureKind, MacHash};
pub use self::rng::{ConstantTimeFailureKind, RngFailureKind, RngOutputKind};
pub use self::signature::{
    KemFailureKind, KeyAgreementFailureKind, SignatureBackend, SignatureFailureKind,
    SignatureOperation,
};
pub use self::taxonomy::CryptoError;
