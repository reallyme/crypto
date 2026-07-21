// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crypto_aes256_gcm::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, encrypt_aes128_gcm, encrypt_aes192_gcm,
    Aes128GcmDecryptRequest, Aes128GcmEncryptRequest, Aes128GcmKey, Aes128GcmNonce,
    Aes192GcmDecryptRequest, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
};
use crypto_aes256_gcm_siv::{
    decrypt as gcm_siv_decrypt, encrypt as gcm_siv_encrypt, Aes256GcmSivKey, Aes256GcmSivNonce,
    CiphertextWithTag as GcmSivCiphertextWithTag, DecryptRequest as GcmSivDecryptRequest,
    EncryptRequest as GcmSivEncryptRequest,
};
use crypto_aes_kw::{
    unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256, wrap_key_aes128, wrap_key_aes192,
    wrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek,
};
use crypto_argon2id::{
    derive_key as argon2id_derive_key, Argon2Profile, Argon2Salt, Argon2Secret, DeriveKeyRequest,
};
use crypto_chacha20_poly1305::{
    decrypt as chacha_decrypt, decrypt_xchacha20_poly1305, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, CiphertextWithTag as ChaChaCiphertextWithTag,
    DecryptRequest as ChaChaDecryptRequest, XChaCha20Poly1305DecryptRequest,
    XChaCha20Poly1305Nonce,
};
use crypto_concat_kdf::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfRequest, JwaPartyInfo,
    JwaSharedSecret,
};
use crypto_core::MacAlgorithm;
use crypto_hkdf::{
    derive as hkdf_derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite,
};
use crypto_hmac::{authenticate as hmac_authenticate, verify as hmac_verify, HmacKey};
use crypto_kmac::{derive_kmac256, Kmac256Key};
use crypto_pbkdf2::{
    derive_key as derive_pbkdf2_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request,
    Pbkdf2Salt,
};
use crypto_sha2::{digest_sha2_384, digest_sha2_512};
use crypto_sha2_256::digest as sha2_256_digest;
use crypto_sha3::{digest_sha3_224, digest_sha3_384, digest_sha3_512};
use crypto_sha3_256::digest as sha3_256_digest;
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_string, load, object_field, VectorTestError};

include!("symmetric_codec_tests/aead_aes_gcm.rs");
include!("symmetric_codec_tests/key_wrap.rs");
include!("symmetric_codec_tests/aead_chacha_and_gcm_siv.rs");
include!("symmetric_codec_tests/mac_and_hash.rs");
include!("symmetric_codec_tests/kdf.rs");
