// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! # reallyme-crypto
//!
//! Umbrella crate that re-exports the ReallyMe cryptographic primitives,
//! codecs, dispatch, and signer abstractions behind one dependency and a
//! consistent feature set.
//!
//! ## Platform lanes
//!
//! Every primitive is available through four backend lanes selected by
//! Cargo feature and target: `native` (portable Rust), `wasm` (browser
//! bindings), `swift` (Apple CryptoKit / Secure Enclave), and `kotlin`
//! (Android Keystore). Selecting a platform lane compiles against that
//! platform's crypto; a lane never silently falls back to native Rust —
//! an Apple/Android build without the corresponding link cfg fails to
//! compile rather than substituting a different backend.
//!
//! ## Security posture
//!
//! `#![forbid(unsafe_code)]` here; secret material is returned in zeroizing
//! wrappers; signature verification fails closed; and cross-implementation
//! conformance vectors pin the Rust output against an independent oracle.
//! See `SECURITY.md` and `SECURITY_MEMORY_MODEL.md` at the repository root.
//!
//! ## Example: sign then verify
//!
//! A detached signature round-trip through [`dispatch`] (requires the
//! `dispatch` and `ed25519` features, both on by default). Verification
//! fails closed — tampering with the message yields `Err`, never `Ok(false)`.
//!
//! ```
//! # #[cfg(all(feature = "dispatch", feature = "ed25519"))]
//! # fn main() -> Result<(), reallyme_crypto::dispatch::AlgorithmError> {
//! use reallyme_crypto::core::Algorithm;
//! use reallyme_crypto::dispatch::{generate_keypair, sign, verify};
//!
//! let (public, secret) = generate_keypair(Algorithm::Ed25519)?;
//! let message = b"attested payload";
//!
//! let signature = sign(Algorithm::Ed25519, &secret, message)?;
//! verify(Algorithm::Ed25519, &public, message, &signature)?;
//!
//! // A signature never covers a different message: verify returns Err.
//! assert!(verify(Algorithm::Ed25519, &public, b"tampered", &signature).is_err());
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "dispatch", feature = "ed25519")))]
//! # fn main() {}
//! ```

#![forbid(unsafe_code)]

pub use crypto_core as core;

/// JSON Web Key envelope types and public-key conversion helpers.
#[cfg(feature = "jwk")]
pub use envelopes_jwk as jwk;

/// Bidirectional conversion between JWK and Multikey public-key envelopes.
#[cfg(feature = "jwk-multikey")]
pub use envelopes_jwk_multikey as jwk_multikey;

/// Algorithm-selected dispatch: keygen, sign/verify, key agreement, KEM, AEAD,
/// hashing, and multikey binding routed by an [`core::Algorithm`] selector.
#[cfg(feature = "dispatch")]
pub mod dispatch {
    pub use crypto_dispatch::{
        aead_decrypt, aead_encrypt, derive_shared_secret, generate_keypair,
        generate_multikey_keypair, hash_digest, kem_decapsulate, kem_encapsulate, mac_authenticate,
        mac_verify, public_key_to_multikey, sign, validate_verification_method_multikey, verify,
        AeadParams, AlgorithmError, GeneratedKeypair, MacParams,
    };
}

/// Signer/verifier traits and dispatch-backed implementations for producing and
/// checking detached signatures.
#[cfg(feature = "signer")]
pub mod signer {
    pub use crypto_signer::{
        DispatchSigner, DispatchVerifier, Signer, SignerError, SignerFailureKind, Verifier,
        VerifierError, VerifierFailureKind,
    };
}

/// AES-256-GCM authenticated encryption primitive and its typed key/nonce
/// wrappers and length constants.
#[cfg(feature = "aes")]
pub mod aes {
    pub use crypto_aes256_gcm::{
        decrypt, encrypt, Aes256GcmKey, Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
        EncryptRequest, AES_256_GCM_KEY_LENGTH, AES_256_GCM_NONCE_LENGTH, AES_256_GCM_TAG_LENGTH,
    };
}

/// AES-256 Key Wrap (RFC 3394) for wrapping compact key material.
#[cfg(feature = "aes-kw")]
pub mod aes_kw {
    pub use crypto_aes_kw::{
        unwrap_key, wrap_key, Aes256KwKek, AesKwKeyData, AesKwWrappedKey, AES_256_KW_KEK_LENGTH,
        AES_KW_BLOCK_LENGTH, AES_KW_INTEGRITY_CHECK_LENGTH, AES_KW_MAX_KEY_DATA_LENGTH,
        AES_KW_MIN_KEY_DATA_LENGTH, AES_KW_MIN_WRAPPED_KEY_LENGTH,
    };
}

/// AES-256-GCM-SIV nonce-misuse-resistant authenticated encryption primitive and
/// its typed key/nonce wrappers and length constants.
#[cfg(feature = "aes-gcm-siv")]
pub mod aes_gcm_siv {
    pub use crypto_aes256_gcm_siv::{
        decrypt, encrypt, Aes256GcmSivKey, Aes256GcmSivNonce, CiphertextWithTag, DecryptRequest,
        EncryptRequest, AES_256_GCM_SIV_KEY_LENGTH, AES_256_GCM_SIV_NONCE_LENGTH,
        AES_256_GCM_SIV_TAG_LENGTH,
    };
}

/// ChaCha20-Poly1305 and XChaCha20-Poly1305 authenticated encryption
/// primitives with typed key and nonce wrappers.
#[cfg(feature = "chacha20-poly1305")]
pub mod chacha20_poly1305 {
    pub use crypto_chacha20_poly1305::{
        decrypt, decrypt_xchacha20_poly1305, encrypt, encrypt_xchacha20_poly1305,
        ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, CiphertextWithTag, DecryptRequest,
        EncryptRequest, XChaCha20Poly1305DecryptRequest, XChaCha20Poly1305EncryptRequest,
        XChaCha20Poly1305Nonce, CHACHA20_POLY1305_KEY_LENGTH, CHACHA20_POLY1305_NONCE_LENGTH,
        CHACHA20_POLY1305_TAG_LENGTH, XCHACHA20_POLY1305_NONCE_LENGTH,
    };
}

/// Argon2id password-based key derivation, including platform-tuned cost
/// profiles and typed salt/secret/derived-key wrappers.
#[cfg(feature = "argon2id")]
pub mod argon2id {
    pub use crypto_argon2id::{
        derive_key, derive_key_for_version, resolve_mobile_profile_for_unlock,
        resolve_profile_params_for_platform, resolve_profile_params_with_caps, Argon2Caps,
        Argon2KdfVersion, Argon2ParamsProfile, Argon2PlatformClass, Argon2Profile, Argon2Salt,
        Argon2Secret, Argon2idDerivedKey, DeriveKeyRequest, ARGON2ID_DERIVED_KEY_LENGTH,
        ARGON2ID_SALT_MAX_LENGTH, ARGON2ID_SALT_MIN_LENGTH, ARGON2ID_V1_LANES,
        ARGON2ID_V1_MEMORY_COST_KIB, ARGON2ID_V1_TIME_COST, ARGON2ID_V2_LANES,
        ARGON2ID_V2_MEMORY_COST_KIB, ARGON2ID_V2_TIME_COST,
    };
}

/// Constant-time (non-short-circuiting) byte-slice equality checks.
#[cfg(feature = "constant-time")]
pub mod constant_time {
    pub use crypto_constant_time::{ct_eq, ct_eq_fixed, require_ct_eq};
}

/// OS-backed cryptographically secure randomness and typed generators for AEAD
/// nonces and Argon2 salts.
#[cfg(feature = "csprng")]
pub mod csprng {
    pub use crypto_csprng::{
        generate_aead_nonce_12, generate_argon2_salt_16, generate_argon2_salt_32, generate_bytes,
        AeadNonce12, Argon2Salt16, Argon2Salt32, OsSecureRandom, RandomBytes, SecureRandom,
        AEAD_NONCE_12_LENGTH, ARGON2_SALT_16_LENGTH, ARGON2_SALT_32_LENGTH,
    };
}

/// Ed25519 signatures: keypair generation, sign/verify, and public-key encoding.
#[cfg(feature = "ed25519")]
pub mod ed25519 {
    pub use crypto_ed25519::{
        assert_public_key, decode_public_key, encode_public_key, generate_ed25519_keypair,
        generate_ed25519_keypair_from_seed, sign_ed25519, verify_ed25519,
    };
}

/// HMAC authentication tags over SHA-256 and SHA-512.
#[cfg(feature = "hmac")]
pub mod hmac {
    pub use crypto_hmac::{
        authenticate, verify, HmacKey, HmacTag, HMAC_MAX_KEY_LENGTH, HMAC_SHA256_TAG_LENGTH,
        HMAC_SHA512_TAG_LENGTH,
    };
}

/// NIST P-256 (secp256r1) ECDSA over pre-hashed messages, with public-key
/// compression and Secure Enclave handle encoding.
#[cfg(feature = "p256")]
pub mod p256 {
    pub use crypto_p256::{
        compress_public_key, decode_se_handle, decompress_public_key, derive_p256_shared_secret,
        encode_se_handle, generate_p256_keypair, generate_p256_keypair_from_secret_key,
        sign_p256_der_prehash, verify_p256_der_prehash, SE_HANDLE_PREFIX,
    };
}

/// NIST P-384 (secp384r1) ECDSA over pre-hashed messages, with public-key
/// compression/decompression helpers.
#[cfg(feature = "p384")]
pub mod p384 {
    pub use crypto_p384::{
        compress_p384, decompress_p384, generate_p384_keypair,
        generate_p384_keypair_from_secret_key, sign_p384_der_prehash, verify_p384_der_prehash,
        P384_PUBLIC_KEY_COMPRESSED_LEN, P384_PUBLIC_KEY_RAW_LEN, P384_PUBLIC_KEY_UNCOMPRESSED_LEN,
        P384_SECRET_KEY_LEN, P384_SIGNATURE_DER_MAX_LEN,
    };
}

/// NIST P-521 (secp521r1) ECDSA over pre-hashed messages, with public-key
/// compression/decompression helpers.
#[cfg(feature = "p521")]
pub mod p521 {
    pub use crypto_p521::{
        compress_p521, decompress_p521, generate_p521_keypair,
        generate_p521_keypair_from_secret_key, sign_p521_der_prehash, verify_p521_der_prehash,
        P521_PUBLIC_KEY_COMPRESSED_LEN, P521_PUBLIC_KEY_RAW_LEN, P521_PUBLIC_KEY_UNCOMPRESSED_LEN,
        P521_SECRET_KEY_LEN, P521_SIGNATURE_DER_MAX_LEN,
    };
}

/// PBKDF2 (RFC 8018) for legacy password-based key derivation.
#[cfg(feature = "pbkdf2")]
pub mod pbkdf2 {
    pub use crypto_pbkdf2::{
        derive_key, Pbkdf2Iterations, Pbkdf2Output, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request,
        Pbkdf2Salt, PBKDF2_MAX_OUTPUT_LENGTH, PBKDF2_MAX_PASSWORD_LENGTH, PBKDF2_MAX_SALT_LENGTH,
        PBKDF2_MIN_ITERATIONS, PBKDF2_MIN_OUTPUT_LENGTH, PBKDF2_MIN_PASSWORD_LENGTH,
        PBKDF2_MIN_SALT_LENGTH,
    };
}

/// RSA signature verification for PKCS#1 v1.5 and PSS.
#[cfg(feature = "rsa")]
pub mod rsa {
    pub use crypto_rsa::{
        verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
        RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS, RSA_PUBLIC_KEY_DER_MAX_LEN,
        RSA_SIGNATURE_MAX_LEN,
    };
}

/// secp256k1 ECDSA signs SHA-256(message) once, returns compact low-S `r || s`,
/// and uses compressed SEC1 public keys as the canonical API representation.
#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    pub use crypto_secp256k1::{
        decode_bip340_schnorr_public_key, decode_public_key, decompress_public_key,
        derive_bip340_schnorr_public_key, encode_bip340_schnorr_public_key, encode_public_key,
        generate_secp256k1_keypair, generate_secp256k1_keypair_from_secret_key,
        sign_bip340_schnorr, sign_secp256k1, verify_bip340_schnorr, verify_secp256k1,
        BIP340_SCHNORR_AUX_RAND_LEN, BIP340_SCHNORR_MESSAGE_LEN, BIP340_SCHNORR_PUBLIC_KEY_LEN,
        BIP340_SCHNORR_SIGNATURE_LEN, SECP256K1_SECRET_KEY_LEN,
    };
}

/// X25519 Diffie–Hellman key agreement and public-key encoding.
#[cfg(feature = "x25519")]
pub mod x25519 {
    pub use crypto_x25519::{
        decode_public_key, derive_x25519_shared_secret, encode_public_key, generate_x25519_keypair,
        generate_x25519_keypair_from_seed,
    };
}

/// X-Wing hybrid KEM suites over X25519 plus ML-KEM-768 or ML-KEM-1024.
#[cfg(feature = "x-wing")]
pub mod x_wing {
    pub use crypto_x_wing::{
        generate_x_wing_1024_keypair, generate_x_wing_1024_keypair_derand,
        generate_x_wing_768_keypair, generate_x_wing_768_keypair_derand, x_wing_1024_decapsulate,
        x_wing_1024_encapsulate, x_wing_1024_encapsulate_derand, x_wing_768_decapsulate,
        x_wing_768_encapsulate, x_wing_768_encapsulate_derand, X_WING_1024_CIPHERTEXT_LEN,
        X_WING_1024_PUBLIC_KEY_LEN, X_WING_768_CIPHERTEXT_LEN, X_WING_768_PUBLIC_KEY_LEN,
        X_WING_ENCAPS_SEED_LEN, X_WING_SECRET_KEY_LEN, X_WING_SHARED_SECRET_LEN,
    };
}

/// RFC 9180 HPKE Base-mode encryption over supported DHKEM/HKDF/AEAD suites.
#[cfg(feature = "hpke")]
pub mod hpke {
    pub use crypto_hpke::{
        open_base, seal_base, HpkeError, HpkeOpenOutput, HpkeOpenRequest, HpkePrivateKeyBytes,
        HpkeSealOutput, HpkeSealRequest, HpkeSuite, HPKE_AEAD_AES_256_GCM,
        HPKE_AEAD_CHACHA20_POLY1305, HPKE_AEAD_TAG_LEN, HPKE_ENCAPSULATED_KEY_MAX_LEN,
        HPKE_KDF_HKDF_SHA256, HPKE_KEM_DHKEM_P256_HKDF_SHA256, HPKE_KEM_DHKEM_X25519_HKDF_SHA256,
        HPKE_P256_PRIVATE_KEY_LEN, HPKE_P256_PUBLIC_KEY_LEN, HPKE_X25519_PRIVATE_KEY_LEN,
        HPKE_X25519_PUBLIC_KEY_LEN,
    };
}

/// HKDF (RFC 5869) extract-and-expand key derivation over the SHA-2/SHA-3 suites,
/// with domain-separated key derivation helpers.
#[cfg(feature = "hkdf")]
pub mod hkdf {
    pub use crypto_hkdf::{
        derive, derive_domain_key_32, DeriveRequest, DomainKeyPurpose, DomainTag, HkdfInfo,
        HkdfInputKeyMaterial, HkdfOutput, HkdfSalt, HkdfSuite,
    };
}

/// ML-DSA-44 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    pub use crypto_ml_dsa_44::{
        decode_public_key, encode_public_key, generate_ml_dsa_44_keypair,
        generate_ml_dsa_44_keypair_from_seed, sign_ml_dsa_44, verify_ml_dsa_44,
    };
}

/// ML-DSA-65 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    pub use crypto_ml_dsa_65::{
        decode_public_key, encode_public_key, generate_ml_dsa_65_keypair,
        generate_ml_dsa_65_keypair_from_seed, sign_ml_dsa_65, verify_ml_dsa_65,
    };
}

/// ML-DSA-87 (FIPS 204) post-quantum signatures: keygen, sign/verify, and
/// public-key encoding.
#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    pub use crypto_ml_dsa_87::{
        decode_public_key, encode_public_key, generate_ml_dsa_87_keypair,
        generate_ml_dsa_87_keypair_from_seed, sign_ml_dsa_87, verify_ml_dsa_87,
    };
}

/// SLH-DSA-SHA2-128s (FIPS 205) hash-based post-quantum signatures.
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa {
    pub use crypto_slh_dsa::{
        decode_slh_dsa_sha2_128s_public_key, derive_slh_dsa_sha2_128s_keypair,
        encode_slh_dsa_sha2_128s_public_key, generate_slh_dsa_sha2_128s_keypair,
        sign_slh_dsa_sha2_128s, verify_slh_dsa_sha2_128s, SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN,
        SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN, SLH_DSA_SHA2_128S_SECRET_KEY_LEN,
        SLH_DSA_SHA2_128S_SIGNATURE_LEN,
    };
}

/// ML-KEM-512 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-512")]
pub mod ml_kem_512 {
    pub use crypto_ml_kem_512::{
        generate_ml_kem_512_keypair, generate_ml_kem_512_keypair_from_seed, ml_kem_512_decapsulate,
        ml_kem_512_encapsulate, ml_kem_512_encapsulate_derand,
    };
}

/// ML-KEM-768 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-768")]
pub mod ml_kem_768 {
    pub use crypto_ml_kem_768::{
        generate_ml_kem_768_keypair, generate_ml_kem_768_keypair_from_seed, ml_kem_768_decapsulate,
        ml_kem_768_encapsulate, ml_kem_768_encapsulate_derand,
    };
}

/// ML-KEM-1024 (FIPS 203) post-quantum key encapsulation: keygen, encapsulate,
/// and decapsulate.
#[cfg(feature = "ml-kem-1024")]
pub mod ml_kem_1024 {
    pub use crypto_ml_kem_1024::{
        generate_ml_kem_1024_keypair, generate_ml_kem_1024_keypair_from_seed,
        ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_encapsulate_derand,
    };
}

/// SHA-2-256 hashing and its fixed-length digest wrapper.
#[cfg(feature = "sha2")]
pub mod sha2 {
    pub use crypto_sha2::{
        digest_sha2_384, digest_sha2_512, Sha2_384Digest, Sha2_512Digest, SHA2_384_DIGEST_LENGTH,
        SHA2_512_DIGEST_LENGTH,
    };
    pub use crypto_sha2_256::{digest, Sha2_256Digest, SHA2_256_DIGEST_LENGTH};
}

/// SHA-3-256 hashing and its fixed-length digest wrapper.
#[cfg(feature = "sha3")]
pub mod sha3 {
    pub use crypto_sha3::{
        digest_sha3_224, digest_sha3_384, digest_sha3_512, Sha3_224Digest, Sha3_384Digest,
        Sha3_512Digest, SHA3_224_DIGEST_LENGTH, SHA3_384_DIGEST_LENGTH, SHA3_512_DIGEST_LENGTH,
    };
    pub use crypto_sha3_256::{digest, Sha3_256Digest, SHA3_256_DIGEST_LENGTH};
}

/// Encoding and serialization codecs: base64, base64url, DAG-CBOR, JCS,
/// multibase, multicodec, and multikey.
#[cfg(feature = "codec")]
pub mod codec {
    /// Standard (RFC 4648) base64 encode/decode.
    #[cfg(feature = "codec-base64")]
    pub mod base64 {
        pub use codec_base64::{base64_to_bytes, bytes_to_base64, Base64Error};
    }

    /// URL-safe (RFC 4648 §5) base64 encode/decode without padding.
    #[cfg(feature = "codec-base64url")]
    pub mod base64url {
        pub use codec_base64url::{
            base64url_bytes_to_bytes, base64url_to_bytes, bytes_to_base64url, Base64UrlError,
        };
    }

    /// DAG-CBOR encode/decode and content-identifier (CID) computation and
    /// verification.
    #[cfg(feature = "codec-cbor")]
    pub mod cbor {
        pub use codec_cbor::{
            compute_cid_dag_cbor, dag_cbor_multihash, decode_dag_cbor, encode_dag_cbor,
            is_valid_cid_string, sha2_256_content_hash, try_parse_cid, verify_dag_cbor_cid,
            CborError, CborValue, ContentHash, DagCborMultihash, DAG_CBOR_CODEC,
        };
    }

    /// JSON Canonicalization Scheme (RFC 8785) serialization.
    #[cfg(feature = "codec-jcs")]
    pub mod jcs {
        pub use codec_jcs::{canonicalize_json, JcsError};
    }

    /// Multibase self-describing base encodings (base58btc and base64url).
    #[cfg(feature = "codec-multibase")]
    pub mod multibase {
        pub use codec_multibase::{
            base58btc_decode, base58btc_encode, bytes_to_multibase58btc,
            bytes_to_multibase_base64url, multibase_to_bytes, Base58Error, MultibaseError,
        };
    }

    /// Multicodec varint prefix lookup and stripping.
    #[cfg(feature = "codec-multicodec")]
    pub mod multicodec {
        pub use codec_multicodec::{
            lookup_codec_prefix, strip_codec_prefix, CodecLookupResult, CodecSpec, MULTICODEC_TABLE,
        };
    }

    /// Multikey encoding/parsing that binds an algorithm to its public-key bytes.
    #[cfg(feature = "codec-multikey")]
    pub mod multikey {
        pub use codec_multikey::{
            binding_type_matches_codec, encode_multikey, parse_multikey, validate_key_binding,
            KeyBindingInput, MultikeyError, ParsedMultikey,
        };
    }
}
