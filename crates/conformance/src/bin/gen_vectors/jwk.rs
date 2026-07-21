// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn jwk_options(key_use: &'static str) -> JwkOptions {
    JwkOptions {
        alg: true,
        use_sig: key_use == "sig",
        use_enc: key_use == "enc",
        kid: None,
    }
}

fn supported_jwk_vector(
    alg: &'static str,
    public_key: &[u8],
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
    jwk: Jwk,
) -> Result<JwkVector, VectorGenError> {
    let multikey = jwk_to_multikey(&jwk).map_err(|_| VectorGenError::JwkMultikeyEncode)?;

    Ok(JwkVector {
        alg,
        public_key: b64u(public_key),
        public_key_length: public_key.len(),
        kty,
        crv,
        jwk_jcs,
        multikey: Some(multikey),
        multikey_status: "supported",
    })
}

fn pending_multicodec_jwk_vector(
    alg: &'static str,
    public_key: &[u8],
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
) -> JwkVector {
    JwkVector {
        alg,
        public_key: b64u(public_key),
        public_key_length: public_key.len(),
        kty,
        crv,
        jwk_jcs,
        multikey: None,
        multikey_status: "multicodec-missing",
    }
}

fn x_wing_public_key(keypair: XWingKeypairFn) -> Result<Vec<u8>, VectorGenError> {
    let (public_key, _secret_key) =
        keypair(&X_WING_SECRET_SEED).map_err(|_| VectorGenError::XWingOperation)?;
    Ok(public_key)
}

fn write_jwk_vector(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let sig_options = jwk_options("sig");
    let enc_options = jwk_options("enc");
    let x_wing_768_public = x_wing_public_key(generate_x_wing_768_keypair_derand)?;

    let vectors = vec![
        supported_jwk_vector(
            "Ed25519",
            &keys.ed25519_public,
            "OKP",
            "Ed25519",
            ed25519_public_key_to_jwk_jcs(&keys.ed25519_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Okp(
                ed25519_public_key_to_jwk(&keys.ed25519_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "X25519",
            &keys.x25519_public,
            "OKP",
            "X25519",
            x25519_public_key_to_jwk_jcs(&keys.x25519_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Okp(
                x25519_public_key_to_jwk(&keys.x25519_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "P-256",
            &keys.p256_public,
            "EC",
            "P-256",
            p256_public_key_to_jwk_jcs(&keys.p256_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Ec(
                p256_public_key_to_jwk(&keys.p256_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "secp256k1",
            &keys.secp256k1_public,
            "EC",
            "secp256k1",
            secp256k1_public_key_to_jwk_jcs(&keys.secp256k1_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Ec(
                secp256k1_public_key_to_jwk(&keys.secp256k1_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-44",
            &keys.ml_dsa_44_public,
            "AKP",
            "ML-DSA-44",
            mldsa44_public_key_to_jwk_jcs(&keys.ml_dsa_44_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa44_public_key_to_jwk(&keys.ml_dsa_44_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-65",
            &keys.ml_dsa_65_public,
            "AKP",
            "ML-DSA-65",
            mldsa65_public_key_to_jwk_jcs(&keys.ml_dsa_65_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa65_public_key_to_jwk(&keys.ml_dsa_65_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-DSA-87",
            &keys.ml_dsa_87_public,
            "AKP",
            "ML-DSA-87",
            mldsa87_public_key_to_jwk_jcs(&keys.ml_dsa_87_public, sig_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mldsa87_public_key_to_jwk(&keys.ml_dsa_87_public, sig_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-512",
            &keys.mlkem512_public,
            "AKP",
            "ML-KEM-512",
            mlkem512_public_key_to_jwk_jcs(&keys.mlkem512_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem512_public_key_to_jwk(&keys.mlkem512_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-768",
            &keys.mlkem768_public,
            "AKP",
            "ML-KEM-768",
            mlkem768_public_key_to_jwk_jcs(&keys.mlkem768_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem768_public_key_to_jwk(&keys.mlkem768_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?,
            ),
        )?,
        supported_jwk_vector(
            "ML-KEM-1024",
            &keys.mlkem1024_public,
            "AKP",
            "ML-KEM-1024",
            mlkem1024_public_key_to_jwk_jcs(&keys.mlkem1024_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
            Jwk::Akp(
                mlkem1024_public_key_to_jwk(&keys.mlkem1024_public, enc_options.clone())
                    .map_err(|_| VectorGenError::JwkEncode)?
                    .into(),
            ),
        )?,
        pending_multicodec_jwk_vector(
            "SLH-DSA-SHA2-128s",
            &keys.slh_dsa_sha2_128s_public,
            "AKP",
            "SLH-DSA-SHA2-128s",
            slh_dsa_sha2_128s_public_key_to_jwk_jcs(&keys.slh_dsa_sha2_128s_public, sig_options)
                .map_err(|_| VectorGenError::JwkEncode)?,
        ),
        pending_multicodec_jwk_vector(
            "X-Wing-768",
            &x_wing_768_public,
            "AKP",
            "X-Wing-768",
            x_wing_768_public_key_to_jwk_jcs(&x_wing_768_public, enc_options.clone())
                .map_err(|_| VectorGenError::JwkEncode)?,
        ),
    ];

    write_json(&dir.join("jwk.json"), &JwkVectors { vectors })
}
