// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// X-Wing private key seed length, in bytes.
pub const X_WING_SECRET_KEY_LEN: usize = 32;
/// X-Wing encapsulation seed length, in bytes.
pub const X_WING_ENCAPS_SEED_LEN: usize = 64;
/// X-Wing shared secret length, in bytes.
pub const X_WING_SHARED_SECRET_LEN: usize = 32;

pub(crate) const X25519_KEY_LEN: usize = 32;
pub(crate) const X_WING_LABEL: &[u8; 6] = b"\\.//^\\";
pub(crate) const X_WING_EXPANDED_SECRET_LEN: usize = 96;
pub(crate) const ML_KEM_SECRET_SEED_LEN: usize = 64;
pub(crate) const ML_KEM_SHARED_SECRET_LEN: usize = 32;
pub(crate) const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;
pub(crate) const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
pub(crate) const ML_KEM_1024_PUBLIC_KEY_LEN: usize = 1568;
pub(crate) const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;

/// X-Wing public key length for the standard ML-KEM-768 suite.
pub const X_WING_768_PUBLIC_KEY_LEN: usize = ML_KEM_768_PUBLIC_KEY_LEN + X25519_KEY_LEN;
/// X-Wing ciphertext length for the standard ML-KEM-768 suite.
pub const X_WING_768_CIPHERTEXT_LEN: usize = ML_KEM_768_CIPHERTEXT_LEN + X25519_KEY_LEN;
/// X-Wing public key length for the ReallyMe ML-KEM-1024 suite.
pub const X_WING_1024_PUBLIC_KEY_LEN: usize = ML_KEM_1024_PUBLIC_KEY_LEN + X25519_KEY_LEN;
/// X-Wing ciphertext length for the ReallyMe ML-KEM-1024 suite.
pub const X_WING_1024_CIPHERTEXT_LEN: usize = ML_KEM_1024_CIPHERTEXT_LEN + X25519_KEY_LEN;

#[derive(Clone, Copy)]
pub(crate) enum XWingSuite {
    MlKem768,
    MlKem1024,
}

impl XWingSuite {
    pub(crate) fn public_key_len(self) -> usize {
        match self {
            XWingSuite::MlKem768 => X_WING_768_PUBLIC_KEY_LEN,
            XWingSuite::MlKem1024 => X_WING_1024_PUBLIC_KEY_LEN,
        }
    }

    pub(crate) fn ciphertext_len(self) -> usize {
        match self {
            XWingSuite::MlKem768 => X_WING_768_CIPHERTEXT_LEN,
            XWingSuite::MlKem1024 => X_WING_1024_CIPHERTEXT_LEN,
        }
    }

    pub(crate) fn ml_kem_public_key_len(self) -> usize {
        match self {
            XWingSuite::MlKem768 => ML_KEM_768_PUBLIC_KEY_LEN,
            XWingSuite::MlKem1024 => ML_KEM_1024_PUBLIC_KEY_LEN,
        }
    }

    pub(crate) fn ml_kem_ciphertext_len(self) -> usize {
        match self {
            XWingSuite::MlKem768 => ML_KEM_768_CIPHERTEXT_LEN,
            XWingSuite::MlKem1024 => ML_KEM_1024_CIPHERTEXT_LEN,
        }
    }
}
