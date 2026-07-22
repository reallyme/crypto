// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::constants::{
    HPKE_AEAD_AES_128_GCM, HPKE_AEAD_AES_256_GCM, HPKE_AEAD_CHACHA20_POLY1305,
    HPKE_AEAD_EXPORT_ONLY, HPKE_AEAD_TAG_LEN, HPKE_KDF_HKDF_SHA256, HPKE_KDF_HKDF_SHA384,
    HPKE_KDF_HKDF_SHA512, HPKE_KDF_SHAKE128, HPKE_KDF_SHAKE256, HPKE_KDF_TURBO_SHAKE128,
    HPKE_KDF_TURBO_SHAKE256, HPKE_KEM_DHKEM_CP256_HKDF_SHA256, HPKE_KEM_DHKEM_CP384_HKDF_SHA384,
    HPKE_KEM_DHKEM_CP521_HKDF_SHA512, HPKE_KEM_DHKEM_P256_HKDF_SHA256,
    HPKE_KEM_DHKEM_P384_HKDF_SHA384, HPKE_KEM_DHKEM_P521_HKDF_SHA512,
    HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256, HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256,
    HPKE_KEM_DHKEM_X25519_HKDF_SHA256, HPKE_KEM_DHKEM_X448_HKDF_SHA512, HPKE_KEM_ML_KEM_1024,
    HPKE_KEM_ML_KEM_1024_P384, HPKE_KEM_ML_KEM_512, HPKE_KEM_ML_KEM_768, HPKE_KEM_ML_KEM_768_P256,
    HPKE_KEM_X25519_KYBER768_DRAFT00, HPKE_KEM_X_WING,
};
use crate::error::HpkeError;

/// Runtime availability of an IANA-registered HPKE component in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeComponentSupport {
    /// The component is implemented by this crate's selected backend.
    Executable,
    /// The identifier is recognized, but this crate has no reviewed backend.
    RegisteredUnavailable,
}

/// Registered HPKE KEM identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HpkeKemId {
    /// DHKEM(P-256, HKDF-SHA256).
    DhKemP256HkdfSha256 = HPKE_KEM_DHKEM_P256_HKDF_SHA256,
    /// DHKEM(P-384, HKDF-SHA384).
    DhKemP384HkdfSha384 = HPKE_KEM_DHKEM_P384_HKDF_SHA384,
    /// DHKEM(P-521, HKDF-SHA512).
    DhKemP521HkdfSha512 = HPKE_KEM_DHKEM_P521_HKDF_SHA512,
    /// DHKEM(CP-256, HKDF-SHA256).
    DhKemCp256HkdfSha256 = HPKE_KEM_DHKEM_CP256_HKDF_SHA256,
    /// DHKEM(CP-384, HKDF-SHA384).
    DhKemCp384HkdfSha384 = HPKE_KEM_DHKEM_CP384_HKDF_SHA384,
    /// DHKEM(CP-521, HKDF-SHA512).
    DhKemCp521HkdfSha512 = HPKE_KEM_DHKEM_CP521_HKDF_SHA512,
    /// DHKEM(secp256k1, HKDF-SHA256).
    DhKemSecp256k1HkdfSha256 = HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256,
    /// DHKEM(X25519, HKDF-SHA256).
    DhKemX25519HkdfSha256 = HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
    /// DHKEM(X448, HKDF-SHA512).
    DhKemX448HkdfSha512 = HPKE_KEM_DHKEM_X448_HKDF_SHA512,
    /// DHKEM(X25519+Elligator, HKDF-SHA256).
    DhKemX25519ElligatorHkdfSha256 = HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256,
    /// X25519Kyber768Draft00.
    X25519Kyber768Draft00 = HPKE_KEM_X25519_KYBER768_DRAFT00,
    /// ML-KEM-512.
    MlKem512 = HPKE_KEM_ML_KEM_512,
    /// ML-KEM-768.
    MlKem768 = HPKE_KEM_ML_KEM_768,
    /// ML-KEM-1024.
    MlKem1024 = HPKE_KEM_ML_KEM_1024,
    /// MLKEM768-P256.
    MlKem768P256 = HPKE_KEM_ML_KEM_768_P256,
    /// MLKEM1024-P384.
    MlKem1024P384 = HPKE_KEM_ML_KEM_1024_P384,
    /// X-Wing.
    XWing = HPKE_KEM_X_WING,
}

impl HpkeKemId {
    /// Reports whether this registered KEM has a reviewed implementation.
    pub const fn support(self) -> HpkeComponentSupport {
        match self {
            Self::DhKemP256HkdfSha256 if cfg!(feature = "kem-dh-p256") => {
                HpkeComponentSupport::Executable
            }
            Self::DhKemP384HkdfSha384 if cfg!(feature = "kem-dh-p384") => {
                HpkeComponentSupport::Executable
            }
            Self::DhKemP521HkdfSha512 if cfg!(feature = "kem-dh-p521") => {
                HpkeComponentSupport::Executable
            }
            Self::DhKemSecp256k1HkdfSha256 if cfg!(feature = "kem-secp256k1") => {
                HpkeComponentSupport::Executable
            }
            Self::DhKemX25519HkdfSha256 if cfg!(feature = "kem-x25519") => {
                HpkeComponentSupport::Executable
            }
            Self::DhKemX448HkdfSha512 if cfg!(feature = "kem-x448") => {
                HpkeComponentSupport::Executable
            }
            Self::MlKem512 if cfg!(feature = "kem-ml-kem-512") => HpkeComponentSupport::Executable,
            Self::MlKem768 if cfg!(feature = "kem-ml-kem-768") => HpkeComponentSupport::Executable,
            Self::MlKem1024 if cfg!(feature = "kem-ml-kem-1024") => {
                HpkeComponentSupport::Executable
            }
            Self::MlKem768P256 if cfg!(feature = "kem-ml-kem-768-p256") => {
                HpkeComponentSupport::Executable
            }
            Self::MlKem1024P384 if cfg!(feature = "kem-ml-kem-1024-p384") => {
                HpkeComponentSupport::Executable
            }
            Self::XWing if cfg!(feature = "kem-x-wing") => HpkeComponentSupport::Executable,
            Self::DhKemCp256HkdfSha256
            | Self::DhKemCp384HkdfSha384
            | Self::DhKemCp521HkdfSha512
            | Self::DhKemX25519ElligatorHkdfSha256
            | Self::X25519Kyber768Draft00
            | Self::DhKemP256HkdfSha256
            | Self::DhKemP384HkdfSha384
            | Self::DhKemP521HkdfSha512
            | Self::DhKemSecp256k1HkdfSha256
            | Self::DhKemX25519HkdfSha256
            | Self::DhKemX448HkdfSha512
            | Self::MlKem512
            | Self::MlKem768
            | Self::MlKem1024
            | Self::MlKem768P256
            | Self::MlKem1024P384
            | Self::XWing => HpkeComponentSupport::RegisteredUnavailable,
        }
    }
}

impl TryFrom<u16> for HpkeKemId {
    type Error = HpkeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            HPKE_KEM_DHKEM_P256_HKDF_SHA256 => Ok(Self::DhKemP256HkdfSha256),
            HPKE_KEM_DHKEM_P384_HKDF_SHA384 => Ok(Self::DhKemP384HkdfSha384),
            HPKE_KEM_DHKEM_P521_HKDF_SHA512 => Ok(Self::DhKemP521HkdfSha512),
            HPKE_KEM_DHKEM_CP256_HKDF_SHA256 => Ok(Self::DhKemCp256HkdfSha256),
            HPKE_KEM_DHKEM_CP384_HKDF_SHA384 => Ok(Self::DhKemCp384HkdfSha384),
            HPKE_KEM_DHKEM_CP521_HKDF_SHA512 => Ok(Self::DhKemCp521HkdfSha512),
            HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256 => Ok(Self::DhKemSecp256k1HkdfSha256),
            HPKE_KEM_DHKEM_X25519_HKDF_SHA256 => Ok(Self::DhKemX25519HkdfSha256),
            HPKE_KEM_DHKEM_X448_HKDF_SHA512 => Ok(Self::DhKemX448HkdfSha512),
            HPKE_KEM_DHKEM_X25519_ELLIGATOR_HKDF_SHA256 => Ok(Self::DhKemX25519ElligatorHkdfSha256),
            HPKE_KEM_X25519_KYBER768_DRAFT00 => Ok(Self::X25519Kyber768Draft00),
            HPKE_KEM_ML_KEM_512 => Ok(Self::MlKem512),
            HPKE_KEM_ML_KEM_768 => Ok(Self::MlKem768),
            HPKE_KEM_ML_KEM_1024 => Ok(Self::MlKem1024),
            HPKE_KEM_ML_KEM_768_P256 => Ok(Self::MlKem768P256),
            HPKE_KEM_ML_KEM_1024_P384 => Ok(Self::MlKem1024P384),
            HPKE_KEM_X_WING => Ok(Self::XWing),
            _ => Err(HpkeError::UnsupportedKem),
        }
    }
}

/// Registered HPKE KDF identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HpkeKdfId {
    /// HKDF-SHA256.
    HkdfSha256 = HPKE_KDF_HKDF_SHA256,
    /// HKDF-SHA384.
    HkdfSha384 = HPKE_KDF_HKDF_SHA384,
    /// HKDF-SHA512.
    HkdfSha512 = HPKE_KDF_HKDF_SHA512,
    /// SHAKE128 single-stage KDF.
    Shake128 = HPKE_KDF_SHAKE128,
    /// SHAKE256 single-stage KDF.
    Shake256 = HPKE_KDF_SHAKE256,
    /// TurboSHAKE128 single-stage KDF.
    TurboShake128 = HPKE_KDF_TURBO_SHAKE128,
    /// TurboSHAKE256 single-stage KDF.
    TurboShake256 = HPKE_KDF_TURBO_SHAKE256,
}

impl HpkeKdfId {
    /// Reports whether this registered KDF has a reviewed implementation.
    pub const fn support(self) -> HpkeComponentSupport {
        match self {
            Self::HkdfSha256 if cfg!(feature = "kdf-hkdf-sha256") => {
                HpkeComponentSupport::Executable
            }
            Self::HkdfSha384 if cfg!(feature = "kdf-hkdf-sha384") => {
                HpkeComponentSupport::Executable
            }
            Self::HkdfSha512 if cfg!(feature = "kdf-hkdf-sha512") => {
                HpkeComponentSupport::Executable
            }
            Self::Shake256 if cfg!(feature = "kdf-shake256") => HpkeComponentSupport::Executable,
            Self::HkdfSha256
            | Self::HkdfSha384
            | Self::HkdfSha512
            | Self::Shake128
            | Self::Shake256
            | Self::TurboShake128
            | Self::TurboShake256 => HpkeComponentSupport::RegisteredUnavailable,
        }
    }
}

impl TryFrom<u16> for HpkeKdfId {
    type Error = HpkeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            HPKE_KDF_HKDF_SHA256 => Ok(Self::HkdfSha256),
            HPKE_KDF_HKDF_SHA384 => Ok(Self::HkdfSha384),
            HPKE_KDF_HKDF_SHA512 => Ok(Self::HkdfSha512),
            HPKE_KDF_SHAKE128 => Ok(Self::Shake128),
            HPKE_KDF_SHAKE256 => Ok(Self::Shake256),
            HPKE_KDF_TURBO_SHAKE128 => Ok(Self::TurboShake128),
            HPKE_KDF_TURBO_SHAKE256 => Ok(Self::TurboShake256),
            _ => Err(HpkeError::UnsupportedKdf),
        }
    }
}

/// Registered HPKE AEAD identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HpkeAeadId {
    /// AES-128-GCM.
    Aes128Gcm = HPKE_AEAD_AES_128_GCM,
    /// AES-256-GCM.
    Aes256Gcm = HPKE_AEAD_AES_256_GCM,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305 = HPKE_AEAD_CHACHA20_POLY1305,
    /// Export-only mode.
    ExportOnly = HPKE_AEAD_EXPORT_ONLY,
}

impl HpkeAeadId {
    /// Reports whether this registered AEAD has a reviewed implementation.
    pub const fn support(self) -> HpkeComponentSupport {
        match self {
            Self::Aes128Gcm if cfg!(feature = "aead-aes128-gcm") => {
                HpkeComponentSupport::Executable
            }
            Self::Aes256Gcm if cfg!(feature = "aead-aes256-gcm") => {
                HpkeComponentSupport::Executable
            }
            Self::ChaCha20Poly1305 if cfg!(feature = "aead-chacha20-poly1305") => {
                HpkeComponentSupport::Executable
            }
            Self::ExportOnly if cfg!(feature = "aead-export-only") => {
                HpkeComponentSupport::Executable
            }
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::ExportOnly => {
                HpkeComponentSupport::RegisteredUnavailable
            }
        }
    }
}

/// Complete IANA HPKE KEM registry snapshot supported by the `0.3.3` contract.
pub const HPKE_REGISTERED_KEMS: [HpkeKemId; 17] = [
    HpkeKemId::DhKemP256HkdfSha256,
    HpkeKemId::DhKemP384HkdfSha384,
    HpkeKemId::DhKemP521HkdfSha512,
    HpkeKemId::DhKemCp256HkdfSha256,
    HpkeKemId::DhKemCp384HkdfSha384,
    HpkeKemId::DhKemCp521HkdfSha512,
    HpkeKemId::DhKemSecp256k1HkdfSha256,
    HpkeKemId::DhKemX25519HkdfSha256,
    HpkeKemId::DhKemX448HkdfSha512,
    HpkeKemId::DhKemX25519ElligatorHkdfSha256,
    HpkeKemId::X25519Kyber768Draft00,
    HpkeKemId::MlKem512,
    HpkeKemId::MlKem768,
    HpkeKemId::MlKem1024,
    HpkeKemId::MlKem768P256,
    HpkeKemId::MlKem1024P384,
    HpkeKemId::XWing,
];

/// Complete IANA HPKE KDF registry snapshot supported by the `0.3.3` contract.
pub const HPKE_REGISTERED_KDFS: [HpkeKdfId; 7] = [
    HpkeKdfId::HkdfSha256,
    HpkeKdfId::HkdfSha384,
    HpkeKdfId::HkdfSha512,
    HpkeKdfId::Shake128,
    HpkeKdfId::Shake256,
    HpkeKdfId::TurboShake128,
    HpkeKdfId::TurboShake256,
];

/// Complete IANA HPKE AEAD registry snapshot supported by the `0.3.3` contract.
pub const HPKE_REGISTERED_AEADS: [HpkeAeadId; 4] = [
    HpkeAeadId::Aes128Gcm,
    HpkeAeadId::Aes256Gcm,
    HpkeAeadId::ChaCha20Poly1305,
    HpkeAeadId::ExportOnly,
];

impl TryFrom<u16> for HpkeAeadId {
    type Error = HpkeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            HPKE_AEAD_AES_128_GCM => Ok(Self::Aes128Gcm),
            HPKE_AEAD_AES_256_GCM => Ok(Self::Aes256Gcm),
            HPKE_AEAD_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            HPKE_AEAD_EXPORT_ONLY => Ok(Self::ExportOnly),
            _ => Err(HpkeError::UnsupportedAead),
        }
    }
}

/// A typed HPKE ciphersuite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeSuite {
    /// KEM component.
    pub kem: HpkeKemId,
    /// KDF component.
    pub kdf: HpkeKdfId,
    /// AEAD component.
    pub aead: HpkeAeadId,
}

impl HpkeSuite {
    /// Constructs a suite from registered component identifiers.
    pub const fn new(kem: HpkeKemId, kdf: HpkeKdfId, aead: HpkeAeadId) -> Self {
        Self { kem, kdf, aead }
    }

    /// HPKE KEM identifier.
    pub const fn kem_id(self) -> u16 {
        self.kem as u16
    }

    /// HPKE KDF identifier.
    pub const fn kdf_id(self) -> u16 {
        self.kdf as u16
    }

    /// HPKE AEAD identifier.
    pub const fn aead_id(self) -> u16 {
        self.aead as u16
    }

    /// AEAD tag length, or zero for export-only mode.
    pub const fn tag_len(self) -> usize {
        match self.aead {
            HpkeAeadId::ExportOnly => 0,
            HpkeAeadId::Aes128Gcm | HpkeAeadId::Aes256Gcm | HpkeAeadId::ChaCha20Poly1305 => {
                HPKE_AEAD_TAG_LEN
            }
        }
    }
}

/// DHKEM(P-256), HKDF-SHA256, AES-128-GCM.
pub const HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP256HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);
/// DHKEM(P-256), HKDF-SHA256, AES-256-GCM.
pub const HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP256HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes256Gcm,
);
/// DHKEM(P-384), HKDF-SHA384, AES-256-GCM.
pub const HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP384HkdfSha384,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);
/// DHKEM(P-521), HKDF-SHA512, AES-256-GCM.
pub const HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP521HkdfSha512,
    HpkeKdfId::HkdfSha512,
    HpkeAeadId::Aes256Gcm,
);
/// DHKEM(X25519), HKDF-SHA256, AES-128-GCM.
pub const HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemX25519HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);
/// DHKEM(X25519), HKDF-SHA256, ChaCha20-Poly1305.
pub const HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemX25519HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::ChaCha20Poly1305,
);
/// ML-KEM-512, HKDF-SHA256, AES-128-GCM.
///
/// ML-KEM-512 targets NIST security category 1. Prefer ML-KEM-768,
/// ML-KEM-1024, or a hybrid KEM unless a constrained profile requires it.
pub const HPKE_MLKEM512_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem512,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);
/// X-Wing, HKDF-SHA256, ChaCha20-Poly1305.
pub const HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305: HpkeSuite = HpkeSuite::new(
    HpkeKemId::XWing,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::ChaCha20Poly1305,
);
/// ML-KEM-768, SHAKE256, AES-256-GCM.
pub const HPKE_MLKEM768_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem768,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);
/// ML-KEM-1024, SHAKE256, AES-256-GCM.
pub const HPKE_MLKEM1024_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);
/// ML-KEM-1024, HKDF-SHA384, AES-256-GCM.
pub const HPKE_MLKEM1024_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);
/// MLKEM768-P256, SHAKE256, AES-256-GCM.
pub const HPKE_MLKEM768P256_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem768P256,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);
/// MLKEM1024-P384, SHAKE256, AES-256-GCM.
pub const HPKE_MLKEM1024P384_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024P384,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);
/// MLKEM1024-P384, HKDF-SHA384, AES-256-GCM.
pub const HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024P384,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);
/// MLS 192-bit profile: ML-KEM-1024, HKDF-SHA384, AES-256-GCM, and P-384 signatures.
///
/// The profile's MLS transcript hash and HPKE KDF both use SHA-384, but they
/// remain distinct protocol components. The P-384 suffix identifies the MLS
/// signature algorithm and does not alter the HPKE ciphersuite triple.
pub const MLS_192_MLKEM1024_AES256GCM_SHA384_P384: HpkeSuite = HPKE_MLKEM1024_HKDF_SHA384_AES256GCM;
/// MLS 256-bit profile: ML-KEM-1024, HKDF-SHA384, AES-256-GCM, and ML-DSA-87 signatures.
///
/// The ML-DSA-87 suffix identifies the MLS signature algorithm and does not
/// alter the HPKE ciphersuite triple represented by this value.
pub const MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87: HpkeSuite =
    HPKE_MLKEM1024_HKDF_SHA384_AES256GCM;
/// MLS 192-bit profile: MLKEM1024-P384, HKDF-SHA384, AES-256-GCM, and P-384 signatures.
///
/// The profile's MLS transcript hash and HPKE KDF both use SHA-384, but they
/// remain distinct protocol components. The final P-384 suffix identifies the
/// MLS signature algorithm rather than an additional HPKE component.
pub const MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384: HpkeSuite =
    HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM;
