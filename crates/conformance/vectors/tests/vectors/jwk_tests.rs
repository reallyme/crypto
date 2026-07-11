// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use envelopes_jwk::{
    ed25519_public_key_to_jwk, ed25519_public_key_to_jwk_jcs, mldsa44_public_key_to_jwk,
    mldsa44_public_key_to_jwk_jcs, mldsa65_public_key_to_jwk, mldsa65_public_key_to_jwk_jcs,
    mldsa87_public_key_to_jwk, mldsa87_public_key_to_jwk_jcs, mlkem1024_public_key_to_jwk,
    mlkem1024_public_key_to_jwk_jcs, mlkem512_public_key_to_jwk, mlkem512_public_key_to_jwk_jcs,
    mlkem768_public_key_to_jwk, mlkem768_public_key_to_jwk_jcs, p256_public_key_to_jwk,
    p256_public_key_to_jwk_jcs, secp256k1_public_key_to_jwk, secp256k1_public_key_to_jwk_jcs,
    slh_dsa_sha2_128s_public_key_to_jwk_jcs, x25519_public_key_to_jwk,
    x25519_public_key_to_jwk_jcs, x_wing_1024_public_key_to_jwk_jcs,
    x_wing_768_public_key_to_jwk_jcs, Jwk, JwkOptions,
};
use envelopes_jwk_multikey::jwk_to_multikey;
use serde_json::Value;

use crate::support::{b64u_to_bytes, field_array, field_string, load, VectorTestError};

fn jwk_options(key_use: &str) -> JwkOptions {
    JwkOptions {
        alg: true,
        use_sig: key_use == "sig",
        use_enc: key_use == "enc",
        kid: None,
    }
}

fn expected_jcs(alg: &str, public_key: &[u8]) -> Result<String, VectorTestError> {
    match alg {
        "Ed25519" => ed25519_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "X25519" => x25519_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        "P-256" => p256_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "secp256k1" => secp256k1_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "ML-DSA-44" => mldsa44_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "ML-DSA-65" => mldsa65_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "ML-DSA-87" => mldsa87_public_key_to_jwk_jcs(public_key, jwk_options("sig")),
        "ML-KEM-512" => mlkem512_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        "ML-KEM-768" => mlkem768_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        "ML-KEM-1024" => mlkem1024_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        "SLH-DSA-SHA2-128s" => {
            slh_dsa_sha2_128s_public_key_to_jwk_jcs(public_key, jwk_options("sig"))
        }
        "X-Wing-768" => x_wing_768_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        "X-Wing-1024" => x_wing_1024_public_key_to_jwk_jcs(public_key, jwk_options("enc")),
        _ => return Err(VectorTestError::JwkOperation),
    }
    .map_err(|_| VectorTestError::JwkOperation)
}

fn expected_jwk(alg: &str, public_key: &[u8]) -> Result<Option<Jwk>, VectorTestError> {
    let jwk = match alg {
        "Ed25519" => Some(Jwk::Okp(
            ed25519_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?
                .into(),
        )),
        "X25519" => Some(Jwk::Okp(
            x25519_public_key_to_jwk(public_key, jwk_options("enc"))
                .map_err(|_| VectorTestError::JwkOperation)?
                .into(),
        )),
        "P-256" => Some(Jwk::Ec(
            p256_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "secp256k1" => Some(Jwk::Ec(
            secp256k1_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "ML-DSA-44" => Some(Jwk::Akp(
            mldsa44_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "ML-DSA-65" => Some(Jwk::Akp(
            mldsa65_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "ML-DSA-87" => Some(Jwk::Akp(
            mldsa87_public_key_to_jwk(public_key, jwk_options("sig"))
                .map_err(|_| VectorTestError::JwkOperation)?
                .into(),
        )),
        "ML-KEM-512" => Some(Jwk::Akp(
            mlkem512_public_key_to_jwk(public_key, jwk_options("enc"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "ML-KEM-768" => Some(Jwk::Akp(
            mlkem768_public_key_to_jwk(public_key, jwk_options("enc"))
                .map_err(|_| VectorTestError::JwkOperation)?,
        )),
        "ML-KEM-1024" => Some(Jwk::Akp(
            mlkem1024_public_key_to_jwk(public_key, jwk_options("enc"))
                .map_err(|_| VectorTestError::JwkOperation)?
                .into(),
        )),
        "SLH-DSA-SHA2-128s" | "X-Wing-768" | "X-Wing-1024" => None,
        _ => return Err(VectorTestError::JwkOperation),
    };
    Ok(jwk)
}

#[test]
fn jwk_vectors_match_rust_envelope_contract() -> Result<(), VectorTestError> {
    let root = load("jwk.json")?;
    let vectors = field_array(&root, "vectors")?;
    assert_eq!(vectors.len(), 13);

    for vector in vectors {
        let alg = field_string(vector, "alg")?;
        let public_key = b64u_to_bytes(field_string(vector, "public_key")?)?;
        let public_key_length = vector
            .get("public_key_length")
            .and_then(Value::as_u64)
            .ok_or(VectorTestError::InvalidField)?;
        assert_eq!(
            u64::try_from(public_key.len()).map_err(|_| VectorTestError::InvalidField)?,
            public_key_length
        );
        assert_eq!(
            field_string(vector, "jwk_jcs")?,
            expected_jcs(alg, &public_key)?
        );

        let multikey_status = field_string(vector, "multikey_status")?;
        match (multikey_status, expected_jwk(alg, &public_key)?) {
            ("supported", Some(jwk)) => {
                let expected_multikey = field_string(vector, "multikey")?;
                let actual_multikey =
                    jwk_to_multikey(&jwk).map_err(|_| VectorTestError::JwkMultikeyOperation)?;
                assert_eq!(expected_multikey, actual_multikey);
            }
            ("multicodec-missing", None) => {
                if !matches!(vector.get("multikey"), Some(Value::Null)) {
                    return Err(VectorTestError::InvalidField);
                }
            }
            _ => return Err(VectorTestError::JwkMismatch),
        }
    }

    Ok(())
}
