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
    generate_x_wing_1024_keypair_derand, generate_x_wing_768_keypair_derand,
    x_wing_1024_decapsulate, x_wing_1024_encapsulate_derand, x_wing_768_decapsulate,
    x_wing_768_encapsulate_derand,
};
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_string, load, object_field, VectorTestError};

#[test]
fn p256_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("p256.json")?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk_c = b64u_to_bytes(field_string(&v, "public_key_compressed")?)?;
    let pk_u = b64u_to_bytes(field_string(&v, "public_key_uncompressed")?)?;
    let peer_sk = b64u_to_bytes(field_string(&v, "peer_secret_key")?)?;
    let peer_pk_c = b64u_to_bytes(field_string(&v, "peer_public_key_compressed")?)?;
    let peer_pk_u = b64u_to_bytes(field_string(&v, "peer_public_key_uncompressed")?)?;
    let shared_secret = b64u_to_bytes(field_string(&v, "shared_secret")?)?;

    assert_eq!(sk.len(), 32);
    assert_eq!(pk_c.len(), 33);
    assert!(pk_c[0] == 0x02 || pk_c[0] == 0x03);
    assert_eq!(pk_u.len(), 65);
    assert_eq!(pk_u[0], 0x04);
    assert_eq!(peer_sk.len(), 32);
    assert_eq!(peer_pk_c.len(), 33);
    assert!(peer_pk_c[0] == 0x02 || peer_pk_c[0] == 0x03);
    assert_eq!(peer_pk_u.len(), 65);
    assert_eq!(peer_pk_u[0], 0x04);
    assert_eq!(shared_secret.len(), 32);

    let recomputed = decompress_p256(&pk_c).map_err(|_| VectorTestError::P256Decompress)?;
    assert_eq!(recomputed, pk_u);
    let recomputed_peer =
        decompress_p256(&peer_pk_c).map_err(|_| VectorTestError::P256Decompress)?;
    assert_eq!(recomputed_peer, peer_pk_u);

    let derived =
        derive_p256_shared_secret(&sk, &peer_pk_c).map_err(|_| VectorTestError::P256Ecdh)?;
    let peer_derived =
        derive_p256_shared_secret(&peer_sk, &pk_c).map_err(|_| VectorTestError::P256Ecdh)?;
    assert_eq!(derived.as_slice(), shared_secret.as_slice());
    assert_eq!(peer_derived.as_slice(), shared_secret.as_slice());

    // ECDSA (ES256): deterministic for the Rust package lane. Re-signing must
    // reproduce the vector byte-for-byte; verify accepts it; a tampered
    // signature is rejected. Platform native lanes may verify this vector
    // without claiming deterministic or canonical-S emit.
    let message = b64u_to_bytes(field_string(&v, "ecdsa_message")?)?;
    let signature = b64u_to_bytes(field_string(&v, "ecdsa_signature_der")?)?;
    let resigned = sign_p256_der_prehash(&sk, &message).map_err(|_| VectorTestError::EcdsaSign)?;
    assert_eq!(
        resigned, signature,
        "P-256 ECDSA deterministic Rust signing must match the vector"
    );
    verify_p256_der_prehash(&signature, &message, &pk_c)
        .map_err(|_| VectorTestError::EcdsaVerify)?;
    let mut tampered = signature;
    tampered[0] ^= 0x01;
    if verify_p256_der_prehash(&tampered, &message, &pk_c).is_ok() {
        return Err(VectorTestError::EcdsaVerify);
    }
    Ok(())
}

type SharedSecretDeriver =
    fn(&[u8], &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, crypto_core::CryptoError>;

struct Sec1EcdsaVectorCase<Decompress, Verify> {
    vector_name: &'static str,
    secret_key_len: usize,
    compressed_len: usize,
    uncompressed_len: usize,
    shared_secret_len: usize,
    decompress: Decompress,
    derive_shared_secret: SharedSecretDeriver,
    verify: Verify,
}

fn verify_sec1_ecdsa_vector<Decompress, Verify>(
    case: Sec1EcdsaVectorCase<Decompress, Verify>,
) -> Result<(), VectorTestError>
where
    Decompress: Fn(&[u8]) -> Result<Vec<u8>, crypto_core::CryptoError>,
    Verify: Fn(&[u8], &[u8], &[u8]) -> Result<(), crypto_core::CryptoError>,
{
    let v = load(case.vector_name)?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk_c = b64u_to_bytes(field_string(&v, "public_key_compressed")?)?;
    let pk_u = b64u_to_bytes(field_string(&v, "public_key_uncompressed")?)?;
    let peer_sk = b64u_to_bytes(field_string(&v, "peer_secret_key")?)?;
    let peer_pk_c = b64u_to_bytes(field_string(&v, "peer_public_key_compressed")?)?;
    let peer_pk_u = b64u_to_bytes(field_string(&v, "peer_public_key_uncompressed")?)?;
    let shared_secret = b64u_to_bytes(field_string(&v, "shared_secret")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let signature = b64u_to_bytes(field_string(&v, "signature_der")?)?;

    assert_eq!(sk.len(), case.secret_key_len);
    assert_eq!(pk_c.len(), case.compressed_len);
    assert!(pk_c[0] == 0x02 || pk_c[0] == 0x03);
    assert_eq!(pk_u.len(), case.uncompressed_len);
    assert_eq!(pk_u[0], 0x04);
    assert_eq!(peer_sk.len(), case.secret_key_len);
    assert_eq!(peer_pk_c.len(), case.compressed_len);
    assert!(peer_pk_c[0] == 0x02 || peer_pk_c[0] == 0x03);
    assert_eq!(peer_pk_u.len(), case.uncompressed_len);
    assert_eq!(peer_pk_u[0], 0x04);
    assert_eq!(shared_secret.len(), case.shared_secret_len);

    let recomputed = (case.decompress)(&pk_c).map_err(|_| VectorTestError::Sec1Decompress)?;
    assert_eq!(recomputed, pk_u);
    let recomputed_peer =
        (case.decompress)(&peer_pk_c).map_err(|_| VectorTestError::Sec1Decompress)?;
    assert_eq!(recomputed_peer, peer_pk_u);

    let derived =
        (case.derive_shared_secret)(&sk, &peer_pk_c).map_err(|_| VectorTestError::P256Ecdh)?;
    let peer_derived =
        (case.derive_shared_secret)(&peer_sk, &pk_c).map_err(|_| VectorTestError::P256Ecdh)?;
    assert_eq!(derived.as_slice(), shared_secret.as_slice());
    assert_eq!(peer_derived.as_slice(), shared_secret.as_slice());

    (case.verify)(&signature, &message, &pk_c).map_err(|_| VectorTestError::EcdsaVerify)?;

    let mut tampered = signature;
    tampered[0] ^= 0x01;
    if (case.verify)(&tampered, &message, &pk_c).is_ok() {
        return Err(VectorTestError::EcdsaVerify);
    }
    Ok(())
}

#[test]
fn p384_vector_invariants() -> Result<(), VectorTestError> {
    verify_sec1_ecdsa_vector(Sec1EcdsaVectorCase {
        vector_name: "p384.json",
        secret_key_len: 48,
        compressed_len: 49,
        uncompressed_len: 97,
        shared_secret_len: 48,
        decompress: decompress_p384,
        derive_shared_secret: derive_p384_shared_secret,
        verify: verify_p384_der_prehash,
    })
}

#[test]
fn p521_vector_invariants() -> Result<(), VectorTestError> {
    verify_sec1_ecdsa_vector(Sec1EcdsaVectorCase {
        vector_name: "p521.json",
        secret_key_len: 66,
        compressed_len: 67,
        uncompressed_len: 133,
        shared_secret_len: 66,
        decompress: decompress_p521,
        derive_shared_secret: derive_p521_shared_secret,
        verify: verify_p521_der_prehash,
    })
}

#[test]
fn ed25519_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("ed25519.json")?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk = b64u_to_bytes(field_string(&v, "public_key")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let signature = b64u_to_bytes(field_string(&v, "signature")?)?;

    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 32);
    assert_eq!(signature.len(), 64);
    assert_eq!(
        sign_ed25519(&sk, &message).map_err(|_| VectorTestError::Ed25519Sign)?,
        signature
    );
    verify_ed25519(&pk, &message, &signature).map_err(|_| VectorTestError::Ed25519Verify)?;
    Ok(())
}

#[test]
fn secp256k1_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("secp256k1.json")?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk = b64u_to_bytes(field_string(&v, "public_key_compressed")?)?;

    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 33);
    assert!(pk[0] == 0x02 || pk[0] == 0x03);

    // ECDSA (ES256K): deterministic, SHA-256 prehashed, 64-byte compact low-S.
    // Re-signing must reproduce the vector byte-for-byte (locks every lane to
    // the same emit convention); verify accepts it and rejects a tampered one
    // (verify enforces low-S / rejects the high-S twin).
    let message = b64u_to_bytes(field_string(&v, "ecdsa_message")?)?;
    let signature = b64u_to_bytes(field_string(&v, "ecdsa_signature_compact")?)?;
    assert_eq!(signature.len(), 64);
    let resigned = sign_secp256k1(&sk, &message).map_err(|_| VectorTestError::EcdsaSign)?;
    assert_eq!(
        resigned, signature,
        "secp256k1 ECDSA is deterministic and low-S; re-signing must match the vector"
    );
    verify_secp256k1(&signature, &message, &pk).map_err(|_| VectorTestError::EcdsaVerify)?;
    let mut tampered = signature;
    tampered[0] ^= 0x01;
    if verify_secp256k1(&tampered, &message, &pk).is_ok() {
        return Err(VectorTestError::EcdsaVerify);
    }
    Ok(())
}

#[test]
fn bip340_schnorr_vector_known_answer() -> Result<(), VectorTestError> {
    let v = load("bip340_schnorr.json")?;
    let secret_key = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let public_key = b64u_to_bytes(field_string(&v, "public_key_xonly")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let aux_rand = b64u_to_bytes(field_string(&v, "aux_rand")?)?;
    let expected_signature = b64u_to_bytes(field_string(&v, "signature")?)?;

    assert_eq!(field_string(&v, "public_key_format")?, "x-only");
    assert_eq!(secret_key.len(), 32);
    assert_eq!(public_key.len(), 32);
    assert_eq!(message.len(), 32);
    assert_eq!(aux_rand.len(), 32);
    assert_eq!(expected_signature.len(), 64);

    let derived_public = derive_bip340_schnorr_public_key(&secret_key)
        .map_err(|_| VectorTestError::Bip340SchnorrOperation)?;
    if derived_public != public_key {
        return Err(VectorTestError::Bip340SchnorrMismatch);
    }

    let signature = sign_bip340_schnorr(&secret_key, &message, &aux_rand)
        .map_err(|_| VectorTestError::Bip340SchnorrOperation)?;
    if signature != expected_signature {
        return Err(VectorTestError::Bip340SchnorrMismatch);
    }

    verify_bip340_schnorr(&expected_signature, &message, &public_key)
        .map_err(|_| VectorTestError::Bip340SchnorrOperation)?;

    let mut tampered = expected_signature;
    tampered[0] ^= 0x01;
    if verify_bip340_schnorr(&tampered, &message, &public_key).is_ok() {
        return Err(VectorTestError::Bip340SchnorrTamperAccepted);
    }

    Ok(())
}

#[test]
fn rsa_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("rsa.json")?;
    let public_key = b64u_to_bytes(field_string(&v, "public_key_der")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let encoding = RsaPublicKeyDerEncoding::Pkcs1;

    assert_eq!(field_string(&v, "key_format")?, "PKCS1-DER-RSAPublicKey");
    assert_eq!(public_key.first().copied(), Some(0x30));

    // PKCS#1 v1.5 across every committed digest. Each signature must verify,
    // reject a one-bit tamper, and reject verification under the wrong digest.
    let pkcs1v15_cases: [(&str, RsaHash, RsaHash); 4] = [
        ("pkcs1v15_sha1_signature", RsaHash::Sha1, RsaHash::Sha256),
        ("pkcs1v15_sha256_signature", RsaHash::Sha256, RsaHash::Sha1),
        (
            "pkcs1v15_sha384_signature",
            RsaHash::Sha384,
            RsaHash::Sha512,
        ),
        (
            "pkcs1v15_sha512_signature",
            RsaHash::Sha512,
            RsaHash::Sha384,
        ),
    ];
    for (field, hash, wrong_hash) in pkcs1v15_cases {
        let signature = b64u_to_bytes(field_string(&v, field)?)?;
        assert_eq!(signature.len(), 256, "{field}");
        verify_rsa_pkcs1v15(&public_key, encoding, hash, &message, &signature)
            .map_err(|_| VectorTestError::RsaVerify)?;
        // Wrong digest identifier must not verify.
        if verify_rsa_pkcs1v15(&public_key, encoding, wrong_hash, &message, &signature).is_ok() {
            return Err(VectorTestError::RsaVerify);
        }
        let mut tampered = signature;
        tampered[0] ^= 0x01;
        if verify_rsa_pkcs1v15(&public_key, encoding, hash, &message, &tampered).is_ok() {
            return Err(VectorTestError::RsaVerify);
        }
    }

    // PSS across every committed digest (message hash == MGF1 hash).
    let pss_cases: [(&str, &str, RsaHash); 4] = [
        (
            "pss_sha256_mgf1_sha256_signature",
            "pss_sha256_mgf1_sha256_salt_len",
            RsaHash::Sha256,
        ),
        (
            "pss_sha1_mgf1_sha1_signature",
            "pss_sha1_mgf1_sha1_salt_len",
            RsaHash::Sha1,
        ),
        (
            "pss_sha384_mgf1_sha384_signature",
            "pss_sha384_mgf1_sha384_salt_len",
            RsaHash::Sha384,
        ),
        (
            "pss_sha512_mgf1_sha512_signature",
            "pss_sha512_mgf1_sha512_salt_len",
            RsaHash::Sha512,
        ),
    ];
    for (sig_field, salt_field, hash) in pss_cases {
        let signature = b64u_to_bytes(field_string(&v, sig_field)?)?;
        let salt_len = v
            .get(salt_field)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(VectorTestError::InvalidField)?;
        assert_eq!(signature.len(), 256, "{sig_field}");
        let params = RsaPssParams {
            message_hash: hash,
            mgf1_hash: hash,
            salt_len,
        };
        verify_rsa_pss(&public_key, encoding, params, &message, &signature)
            .map_err(|_| VectorTestError::RsaVerify)?;
        let mut tampered = signature;
        tampered[0] ^= 0x01;
        if verify_rsa_pss(&public_key, encoding, params, &message, &tampered).is_ok() {
            return Err(VectorTestError::RsaVerify);
        }
    }

    Ok(())
}

#[test]
fn x25519_vector_invariants() -> Result<(), VectorTestError> {
    let v = load("x25519.json")?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let pk = b64u_to_bytes(field_string(&v, "public_key")?)?;
    let peer_sk = b64u_to_bytes(field_string(&v, "peer_secret_key")?)?;
    let peer_pk = b64u_to_bytes(field_string(&v, "peer_public_key")?)?;
    let expected_shared_secret = b64u_to_bytes(field_string(&v, "shared_secret")?)?;

    assert_eq!(sk.len(), 32);
    assert_eq!(pk.len(), 32);
    assert_eq!(peer_sk.len(), 32);
    assert_eq!(peer_pk.len(), 32);
    assert_eq!(expected_shared_secret.len(), 32);

    let ss =
        derive_x25519_shared_secret(&sk, &peer_pk).map_err(|_| VectorTestError::X25519Derive)?;
    let peer_ss =
        derive_x25519_shared_secret(&peer_sk, &pk).map_err(|_| VectorTestError::X25519Derive)?;
    assert_eq!(*ss, expected_shared_secret);
    assert_eq!(*peer_ss, expected_shared_secret);
    Ok(())
}

fn verify_x_wing_case<Keypair, Encapsulate, Decapsulate>(
    v: &Value,
    public_key_len: usize,
    ciphertext_len: usize,
    keypair: Keypair,
    encapsulate: Encapsulate,
    decapsulate: Decapsulate,
) -> Result<(), VectorTestError>
where
    Keypair: Fn(&[u8]) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>,
    Encapsulate: Fn(
        &[u8],
        &[u8],
    )
        -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), crypto_core::CryptoError>,
    Decapsulate: Fn(&[u8], &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, crypto_core::CryptoError>,
{
    assert_eq!(field_string(v, "secret_key_format")?, "x-wing-seed");
    let secret_key = b64u_to_bytes(field_string(v, "secret_key")?)?;
    let public_key = b64u_to_bytes(field_string(v, "public_key")?)?;
    let encaps_seed = b64u_to_bytes(field_string(v, "encaps_seed")?)?;
    let ciphertext = b64u_to_bytes(field_string(v, "ciphertext")?)?;
    let shared_secret = b64u_to_bytes(field_string(v, "shared_secret")?)?;

    assert_eq!(secret_key.len(), 32);
    assert_eq!(public_key.len(), public_key_len);
    assert_eq!(encaps_seed.len(), 64);
    assert_eq!(ciphertext.len(), ciphertext_len);
    assert_eq!(shared_secret.len(), 32);

    let (derived_public, _derived_secret) =
        keypair(&secret_key).map_err(|_| VectorTestError::XWingOperation)?;
    if derived_public != public_key {
        return Err(VectorTestError::XWingMismatch);
    }

    let (derived_ciphertext, derived_shared_secret) =
        encapsulate(&public_key, &encaps_seed).map_err(|_| VectorTestError::XWingOperation)?;
    if derived_ciphertext != ciphertext || derived_shared_secret.as_slice() != shared_secret {
        return Err(VectorTestError::XWingMismatch);
    }

    let decapsulated =
        decapsulate(&ciphertext, &secret_key).map_err(|_| VectorTestError::XWingOperation)?;
    if decapsulated.as_slice() != shared_secret {
        return Err(VectorTestError::XWingMismatch);
    }
    Ok(())
}

#[test]
fn x_wing_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("x_wing.json")?;
    verify_x_wing_case(
        object_field(&v, "x_wing_768")?,
        1216,
        1120,
        generate_x_wing_768_keypair_derand,
        x_wing_768_encapsulate_derand,
        x_wing_768_decapsulate,
    )?;
    verify_x_wing_case(
        object_field(&v, "x_wing_1024")?,
        1600,
        1600,
        generate_x_wing_1024_keypair_derand,
        x_wing_1024_encapsulate_derand,
        x_wing_1024_decapsulate,
    )
}

fn verify_ml_dsa_known_answer<Sign, Verify>(
    vector_name: &str,
    public_key_length: usize,
    signature_length: usize,
    sign: Sign,
    verify: Verify,
) -> Result<(), VectorTestError>
where
    Sign: Fn(&[u8], &[u8]) -> Result<Vec<u8>, VectorTestError>,
    Verify: Fn(&[u8], &[u8], &[u8]) -> Result<(), VectorTestError>,
{
    let v = load(vector_name)?;
    let pk = b64u_to_bytes(field_string(&v, "public_key")?)?;
    let sk = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let expected_signature = b64u_to_bytes(field_string(&v, "signature")?)?;

    assert_eq!(field_string(&v, "secret_key_format")?, "fips-204-seed");
    assert_eq!(pk.len(), public_key_length);
    assert_eq!(sk.len(), 32);
    assert_eq!(expected_signature.len(), signature_length);

    // Deterministic signing through the workspace primitive must reproduce
    // the committed signature bit-for-bit (the same value the noble oracle
    // reproduces), proving cross-implementation agreement.
    let signature = sign(&sk, &message)?;
    if signature != expected_signature {
        return Err(VectorTestError::MlDsaSignatureMismatch);
    }

    // The committed signature must verify, and any tampering must be
    // rejected (fail closed).
    verify(&pk, &message, &expected_signature)?;
    let mut tampered = expected_signature.clone();
    tampered[0] ^= 0x01;
    if verify(&pk, &message, &tampered).is_ok() {
        return Err(VectorTestError::MlDsaTamperAccepted);
    }
    Ok(())
}

#[test]
fn ml_dsa_44_vector_known_answer() -> Result<(), VectorTestError> {
    verify_ml_dsa_known_answer(
        "ml_dsa_44.json",
        1312,
        2420,
        |sk, message| sign_ml_dsa_44(sk, message).map_err(|_| VectorTestError::MlDsaOperation),
        |pk, message, signature| {
            verify_ml_dsa_44(pk, message, signature).map_err(|_| VectorTestError::MlDsaOperation)
        },
    )
}

#[test]
fn ml_dsa_65_vector_known_answer() -> Result<(), VectorTestError> {
    verify_ml_dsa_known_answer(
        "ml_dsa_65.json",
        1952,
        3309,
        |sk, message| sign_ml_dsa_65(sk, message).map_err(|_| VectorTestError::MlDsaOperation),
        |pk, message, signature| {
            verify_ml_dsa_65(pk, message, signature).map_err(|_| VectorTestError::MlDsaOperation)
        },
    )
}

#[test]
fn ml_dsa_87_vector_known_answer() -> Result<(), VectorTestError> {
    verify_ml_dsa_known_answer(
        "ml_dsa_87.json",
        2592,
        4627,
        |sk, message| sign_ml_dsa_87(sk, message).map_err(|_| VectorTestError::MlDsaOperation),
        |pk, message, signature| {
            verify_ml_dsa_87(pk, message, signature).map_err(|_| VectorTestError::MlDsaOperation)
        },
    )
}

#[test]
fn slh_dsa_sha2_128s_vector_known_answer() -> Result<(), VectorTestError> {
    let v = load("slh_dsa_sha2_128s.json")?;
    let public_key = b64u_to_bytes(field_string(&v, "public_key")?)?;
    let secret_key = b64u_to_bytes(field_string(&v, "secret_key")?)?;
    let sk_seed = b64u_to_bytes(field_string(&v, "keygen_sk_seed")?)?;
    let sk_prf = b64u_to_bytes(field_string(&v, "keygen_sk_prf")?)?;
    let pk_seed = b64u_to_bytes(field_string(&v, "keygen_pk_seed")?)?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let expected_signature = b64u_to_bytes(field_string(&v, "signature")?)?;

    assert_eq!(
        field_string(&v, "secret_key_format")?,
        "fips-205-serialized-secret-key"
    );
    assert_eq!(public_key.len(), 32);
    assert_eq!(secret_key.len(), 64);
    assert_eq!(sk_seed.len(), 16);
    assert_eq!(sk_prf.len(), 16);
    assert_eq!(pk_seed.len(), 16);
    assert_eq!(expected_signature.len(), 7_856);

    let signature = sign_slh_dsa_sha2_128s(&secret_key, &message)
        .map_err(|_| VectorTestError::SlhDsaOperation)?;
    if signature != expected_signature {
        return Err(VectorTestError::SlhDsaSignatureMismatch);
    }
    verify_slh_dsa_sha2_128s(&public_key, &message, &expected_signature)
        .map_err(|_| VectorTestError::SlhDsaOperation)?;

    let mut tampered = expected_signature.clone();
    tampered[0] ^= 0x01;
    if verify_slh_dsa_sha2_128s(&public_key, &message, &tampered).is_ok() {
        return Err(VectorTestError::SlhDsaTamperAccepted);
    }

    Ok(())
}

#[test]
fn mlkem512_vector_known_answer() -> Result<(), VectorTestError> {
    let v = load("mlkem512.json")?;
    assert_eq!(field_string(&v, "secret_key_format")?, "fips-203-seed");
    assert_eq!(b64u_to_bytes(field_string(&v, "public_key")?)?.len(), 800);
    assert_eq!(b64u_to_bytes(field_string(&v, "secret_key")?)?.len(), 64);
    verify_mlkem_known_answer(&v, |ct, sk| {
        ml_kem_512_decapsulate(ct, sk).map_err(|_| VectorTestError::MlKemOperation)
    })
}

#[test]
fn mlkem1024_vector_known_answer() -> Result<(), VectorTestError> {
    let v = load("mlkem1024.json")?;
    assert_eq!(field_string(&v, "secret_key_format")?, "fips-203-seed");
    assert_eq!(b64u_to_bytes(field_string(&v, "public_key")?)?.len(), 1568);
    assert_eq!(b64u_to_bytes(field_string(&v, "secret_key")?)?.len(), 64);
    verify_mlkem_known_answer(&v, |ct, sk| {
        ml_kem_1024_decapsulate(ct, sk).map_err(|_| VectorTestError::MlKemOperation)
    })
}

#[test]
fn mlkem768_vector_known_answer() -> Result<(), VectorTestError> {
    let v = load("mlkem768.json")?;
    assert_eq!(field_string(&v, "secret_key_format")?, "fips-203-seed");
    assert_eq!(b64u_to_bytes(field_string(&v, "public_key")?)?.len(), 1184);
    assert_eq!(b64u_to_bytes(field_string(&v, "secret_key")?)?.len(), 64);
    verify_mlkem_known_answer(&v, |ct, sk| {
        ml_kem_768_decapsulate(ct, sk).map_err(|_| VectorTestError::MlKemOperation)
    })
}

/// Shared ML-KEM known-answer check, parameterized by the variant's
/// workspace `decapsulate`. Confirms the committed valid ciphertext
/// decapsulates to the committed shared secret, and the tampered
/// ciphertext yields the committed implicit-rejection secret, matching the
/// FIPS 203 behavior the noble oracle reproduces.
fn verify_mlkem_known_answer<F>(v: &Value, decapsulate: F) -> Result<(), VectorTestError>
where
    F: Fn(&[u8], &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, VectorTestError>,
{
    let sk = b64u_to_bytes(field_string(v, "secret_key")?)?;
    let ciphertext = b64u_to_bytes(field_string(v, "ciphertext")?)?;
    let shared_secret = b64u_to_bytes(field_string(v, "shared_secret")?)?;
    let tampered_ciphertext = b64u_to_bytes(field_string(v, "tampered_ciphertext")?)?;
    let tampered_shared_secret = b64u_to_bytes(field_string(v, "tampered_shared_secret")?)?;

    let derived = decapsulate(&ciphertext, &sk)?;
    if derived.as_slice() != shared_secret.as_slice() {
        return Err(VectorTestError::MlKemSharedSecretMismatch);
    }

    // Implicit rejection: a tampered ciphertext must not error and must not
    // reveal the real secret; it must yield the committed pseudorandom
    // secret every implementation agrees on.
    let rejected = decapsulate(&tampered_ciphertext, &sk)?;
    if rejected.as_slice() != tampered_shared_secret.as_slice() {
        return Err(VectorTestError::MlKemImplicitRejectionMismatch);
    }
    if rejected.as_slice() == shared_secret.as_slice() {
        return Err(VectorTestError::MlKemImplicitRejectionMismatch);
    }
    Ok(())
}
