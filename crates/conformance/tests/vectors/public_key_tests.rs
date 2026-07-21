// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_ed25519::{sign_ed25519, verify_ed25519};
use crypto_ml_dsa_44::{sign_ml_dsa_44, verify_ml_dsa_44};
use crypto_ml_dsa_65::{sign_ml_dsa_65, verify_ml_dsa_65};
use crypto_ml_dsa_87::{sign_ml_dsa_87, verify_ml_dsa_87};
use crypto_ml_kem_1024::ml_kem_1024_decapsulate;
use crypto_ml_kem_512::ml_kem_512_decapsulate;
use crypto_ml_kem_768::ml_kem_768_decapsulate;
use crypto_p256::{
    decompress_p256, derive_p256_shared_secret, sign_p256_der_prehash, verify_p256_der_prehash,
};
use crypto_p384::{decompress_p384, derive_p384_shared_secret, verify_p384_der_prehash};
use crypto_p521::{decompress_p521, derive_p521_shared_secret, verify_p521_der_prehash};
use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};
use crypto_secp256k1::{
    derive_bip340_schnorr_public_key, sign_bip340_schnorr, sign_secp256k1, verify_bip340_schnorr,
    verify_secp256k1,
};
use crypto_slh_dsa::{sign_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128s};
use crypto_x25519::derive_x25519_shared_secret;
use crypto_x_wing::{
    generate_x_wing_768_keypair_derand, x_wing_768_decapsulate, x_wing_768_encapsulate_derand,
};
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_string, load, object_field, VectorTestError};

include!("public_key_tests/classical_ec_signature.rs");
include!("public_key_tests/rsa.rs");
include!("public_key_tests/agreement_hybrid.rs");
include!("public_key_tests/pq_signature.rs");
include!("public_key_tests/ml_kem.rs");
