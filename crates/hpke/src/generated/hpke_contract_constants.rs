// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from schema metadata. Regenerate with scripts/generate_error_contract.mjs.

use super::{HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuite};

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_P256_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP256HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP256HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_P384_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP384HkdfSha384,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_P521_HKDF_SHA512_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemP521HkdfSha512,
    HpkeKdfId::HkdfSha512,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_X25519_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemX25519HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305: HpkeSuite = HpkeSuite::new(
    HpkeKemId::DhKemX25519HkdfSha256,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::ChaCha20Poly1305,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024P384,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM1024P384_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024P384,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM1024_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM1024_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem1024,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM512_HKDF_SHA256_AES128GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem512,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::Aes128Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM768P256_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem768P256,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM768_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem768,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_MLKEM768_SHAKE256_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::MlKem768,
    HpkeKdfId::Shake256,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_XWING_HKDF_SHA256_CHACHA20POLY1305: HpkeSuite = HpkeSuite::new(
    HpkeKemId::XWing,
    HpkeKdfId::HkdfSha256,
    HpkeAeadId::ChaCha20Poly1305,
);

/// Schema-owned HPKE component triple; availability is provider policy.
pub const HPKE_XWING_HKDF_SHA384_AES256GCM: HpkeSuite = HpkeSuite::new(
    HpkeKemId::XWing,
    HpkeKdfId::HkdfSha384,
    HpkeAeadId::Aes256Gcm,
);

/// Schema-owned HPKE component triple; availability is provider policy.
#[allow(non_upper_case_globals)]
pub const MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519: HpkeSuite =
    HPKE_XWING_HKDF_SHA384_AES256GCM;

/// Schema-owned HPKE component triple; availability is provider policy.
pub const MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384: HpkeSuite =
    HPKE_MLKEM1024P384_HKDF_SHA384_AES256GCM;

/// Schema-owned HPKE component triple; availability is provider policy.
pub const MLS_192_MLKEM1024_AES256GCM_SHA384_P384: HpkeSuite = HPKE_MLKEM1024_HKDF_SHA384_AES256GCM;

/// Schema-owned HPKE component triple; availability is provider policy.
pub const MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65: HpkeSuite =
    HPKE_MLKEM768_HKDF_SHA384_AES256GCM;

/// Schema-owned HPKE component triple; availability is provider policy.
pub const MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87: HpkeSuite =
    HPKE_MLKEM1024_HKDF_SHA384_AES256GCM;

/// Registered schema identities in the reviewed order.
pub const HPKE_REGISTERED_AEADS: [HpkeAeadId; 4] = [
    HpkeAeadId::Aes128Gcm,
    HpkeAeadId::Aes256Gcm,
    HpkeAeadId::ChaCha20Poly1305,
    HpkeAeadId::ExportOnly,
];

/// Registered schema identities in the reviewed order.
pub const HPKE_REGISTERED_KDFS: [HpkeKdfId; 7] = [
    HpkeKdfId::HkdfSha256,
    HpkeKdfId::HkdfSha384,
    HpkeKdfId::HkdfSha512,
    HpkeKdfId::Shake128,
    HpkeKdfId::Shake256,
    HpkeKdfId::TurboShake128,
    HpkeKdfId::TurboShake256,
];

/// Registered schema identities in the reviewed order.
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
