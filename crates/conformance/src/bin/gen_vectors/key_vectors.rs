// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn write_key_vectors(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let p256_uncompressed =
        decompress_p256(&keys.p256_public).map_err(|_| VectorGenError::P256Decompress)?;
    let p256_peer_uncompressed =
        decompress_p256(&keys.p256_peer_public).map_err(|_| VectorGenError::P256Decompress)?;
    let p256_shared_secret = derive_p256_shared_secret(&keys.p256_secret, &keys.p256_peer_public)
        .map_err(|_| VectorGenError::P256Ecdh)?;
    let p256_peer_shared_secret =
        derive_p256_shared_secret(&keys.p256_peer_secret, &keys.p256_public)
            .map_err(|_| VectorGenError::P256Ecdh)?;
    if p256_shared_secret.as_slice() != p256_peer_shared_secret.as_slice() {
        return Err(VectorGenError::P256Ecdh);
    }
    let p256_signature = sign_p256_der_prehash(&keys.p256_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P256Sign)?;
    verify_p256_der_prehash(&p256_signature, SIGNATURE_MESSAGE, &p256_uncompressed)
        .map_err(|_| VectorGenError::P256SignInvariant)?;
    write_json(
        &dir.join("p256.json"),
        &P256Vector {
            alg: "ES256",
            curve: "P-256",
            secret_key: b64u(&keys.p256_secret),
            public_key_compressed: b64u(&keys.p256_public),
            public_key_uncompressed: b64u(&p256_uncompressed),
            ecdsa_message: b64u(SIGNATURE_MESSAGE),
            ecdsa_signature_der: b64u(&p256_signature),
            peer_secret_key: b64u(&keys.p256_peer_secret),
            peer_public_key_compressed: b64u(&keys.p256_peer_public),
            peer_public_key_uncompressed: b64u(&p256_peer_uncompressed),
            shared_secret: b64u(p256_shared_secret.as_slice()),
        },
    )?;

    let p384_uncompressed =
        decompress_p384(&keys.p384_public).map_err(|_| VectorGenError::P384Decompress)?;
    let p384_peer_uncompressed =
        decompress_p384(&keys.p384_peer_public).map_err(|_| VectorGenError::P384Decompress)?;
    let p384_shared_secret = derive_p384_shared_secret(&keys.p384_secret, &keys.p384_peer_public)
        .map_err(|_| VectorGenError::P384Keypair)?;
    let p384_peer_shared_secret =
        derive_p384_shared_secret(&keys.p384_peer_secret, &keys.p384_public)
            .map_err(|_| VectorGenError::P384Keypair)?;
    if p384_shared_secret.as_slice() != p384_peer_shared_secret.as_slice() {
        return Err(VectorGenError::P384Keypair);
    }
    let p384_signature = sign_p384_der_prehash(&keys.p384_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P384Sign)?;
    write_json(
        &dir.join("p384.json"),
        &Sec1EcdsaVector {
            alg: "ES384",
            curve: "P-384",
            secret_key: b64u(&keys.p384_secret),
            public_key_compressed: b64u(&keys.p384_public),
            public_key_uncompressed: b64u(&p384_uncompressed),
            message: b64u(SIGNATURE_MESSAGE),
            signature_der: b64u(&p384_signature),
            peer_secret_key: b64u(&keys.p384_peer_secret),
            peer_public_key_compressed: b64u(&keys.p384_peer_public),
            peer_public_key_uncompressed: b64u(&p384_peer_uncompressed),
            shared_secret: b64u(p384_shared_secret.as_slice()),
        },
    )?;

    let p521_uncompressed =
        decompress_p521(&keys.p521_public).map_err(|_| VectorGenError::P521Decompress)?;
    let p521_peer_uncompressed =
        decompress_p521(&keys.p521_peer_public).map_err(|_| VectorGenError::P521Decompress)?;
    let p521_shared_secret = derive_p521_shared_secret(&keys.p521_secret, &keys.p521_peer_public)
        .map_err(|_| VectorGenError::P521Keypair)?;
    let p521_peer_shared_secret =
        derive_p521_shared_secret(&keys.p521_peer_secret, &keys.p521_public)
            .map_err(|_| VectorGenError::P521Keypair)?;
    if p521_shared_secret.as_slice() != p521_peer_shared_secret.as_slice() {
        return Err(VectorGenError::P521Keypair);
    }
    let p521_signature = sign_p521_der_prehash(&keys.p521_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::P521Sign)?;
    write_json(
        &dir.join("p521.json"),
        &Sec1EcdsaVector {
            alg: "ES512",
            curve: "P-521",
            secret_key: b64u(&keys.p521_secret),
            public_key_compressed: b64u(&keys.p521_public),
            public_key_uncompressed: b64u(&p521_uncompressed),
            message: b64u(SIGNATURE_MESSAGE),
            signature_der: b64u(&p521_signature),
            peer_secret_key: b64u(&keys.p521_peer_secret),
            peer_public_key_compressed: b64u(&keys.p521_peer_public),
            peer_public_key_uncompressed: b64u(&p521_peer_uncompressed),
            shared_secret: b64u(p521_shared_secret.as_slice()),
        },
    )?;

    let ed25519_signature = sign_ed25519(&keys.ed25519_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::Ed25519Sign)?;
    verify_ed25519(&keys.ed25519_public, SIGNATURE_MESSAGE, &ed25519_signature)
        .map_err(|_| VectorGenError::Ed25519Verify)?;

    write_json(
        &dir.join("ed25519.json"),
        &Ed25519Vector {
            alg: "EdDSA",
            curve: "Ed25519",
            secret_key: b64u(&keys.ed25519_secret),
            public_key: b64u(&keys.ed25519_public),
            message: b64u(SIGNATURE_MESSAGE),
            signature: b64u(&ed25519_signature),
        },
    )?;

    let secp256k1_signature = sign_secp256k1(&keys.secp256k1_secret, SIGNATURE_MESSAGE)
        .map_err(|_| VectorGenError::Secp256k1Sign)?;
    // Refuse to emit a signature that does not verify (verify enforces low-S).
    verify_secp256k1(
        &secp256k1_signature,
        SIGNATURE_MESSAGE,
        &keys.secp256k1_public,
    )
    .map_err(|_| VectorGenError::Secp256k1Sign)?;
    write_json(
        &dir.join("secp256k1.json"),
        &Secp256k1Vector {
            alg: "ES256K",
            curve: "secp256k1",
            secret_key: b64u(&keys.secp256k1_secret),
            public_key_compressed: b64u(&keys.secp256k1_public),
            ecdsa_message: b64u(SIGNATURE_MESSAGE),
            ecdsa_signature_compact: b64u(&secp256k1_signature),
        },
    )?;

    let bip340_public_key = derive_bip340_schnorr_public_key(&BIP340_SCHNORR_SECRET)
        .map_err(|_| VectorGenError::Bip340Schnorr)?;
    let bip340_signature = sign_bip340_schnorr(
        &BIP340_SCHNORR_SECRET,
        &BIP340_SCHNORR_MESSAGE,
        &BIP340_SCHNORR_AUX_RAND,
    )
    .map_err(|_| VectorGenError::Bip340Schnorr)?;
    verify_bip340_schnorr(
        &bip340_signature,
        &BIP340_SCHNORR_MESSAGE,
        &bip340_public_key,
    )
    .map_err(|_| VectorGenError::Bip340Schnorr)?;
    write_json(
        &dir.join("bip340_schnorr.json"),
        &Bip340SchnorrVector {
            alg: "BIP-340",
            scheme: "BIP-340 Schnorr",
            curve: "secp256k1",
            public_key_format: "x-only",
            secret_key: b64u(&BIP340_SCHNORR_SECRET),
            public_key_xonly: b64u(&bip340_public_key),
            message: b64u(&BIP340_SCHNORR_MESSAGE),
            aux_rand: b64u(&BIP340_SCHNORR_AUX_RAND),
            signature: b64u(&bip340_signature),
        },
    )?;

    write_rsa_vector(dir)?;

    let x25519_shared_secret =
        derive_x25519_shared_secret(&keys.x25519_secret, &keys.x25519_peer_public)
            .map_err(|_| VectorGenError::X25519Derive)?;
    let x25519_peer_shared_secret =
        derive_x25519_shared_secret(&keys.x25519_peer_secret, &keys.x25519_public)
            .map_err(|_| VectorGenError::X25519Derive)?;
    if x25519_shared_secret != x25519_peer_shared_secret {
        return Err(VectorGenError::X25519Derive);
    }

    write_json(
        &dir.join("x25519.json"),
        &X25519Vector {
            alg: "X25519",
            curve: "X25519",
            secret_key: b64u(&keys.x25519_secret),
            public_key: b64u(&keys.x25519_public),
            peer_secret_key: b64u(&keys.x25519_peer_secret),
            peer_public_key: b64u(&keys.x25519_peer_public),
            shared_secret: b64u(&x25519_shared_secret),
        },
    )?;

    let ml_dsa_44_signature = sign_ml_dsa_vector::<MlDsa44>(&ML_DSA_44_SEED)?;
    write_json(
        &dir.join("ml_dsa_44.json"),
        &MlDsaVector {
            alg: "ML-DSA-44",
            scheme: "ML-DSA-44",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_44_secret),
            public_key: b64u(&keys.ml_dsa_44_public),
            public_key_length: keys.ml_dsa_44_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_44_signature),
        },
    )?;

    let ml_dsa_65_signature = sign_ml_dsa_vector::<MlDsa65>(&ML_DSA_65_SEED)?;
    write_json(
        &dir.join("ml_dsa_65.json"),
        &MlDsaVector {
            alg: "ML-DSA-65",
            scheme: "ML-DSA-65",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_65_secret),
            public_key: b64u(&keys.ml_dsa_65_public),
            public_key_length: keys.ml_dsa_65_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_65_signature),
        },
    )?;

    let ml_dsa_87_signature = sign_ml_dsa_vector::<MlDsa87>(&ML_DSA_87_SEED)?;
    write_json(
        &dir.join("ml_dsa_87.json"),
        &MlDsaVector {
            alg: "ML-DSA-87",
            scheme: "ML-DSA-87",
            secret_key_format: "fips-204-seed",
            secret_key: b64u(&keys.ml_dsa_87_secret),
            public_key: b64u(&keys.ml_dsa_87_public),
            public_key_length: keys.ml_dsa_87_public.len(),
            message: b64u(ML_DSA_MESSAGE),
            signature: b64u(&ml_dsa_87_signature),
        },
    )?;

    let slh_dsa_sha2_128s_signature =
        sign_slh_dsa_sha2_128s_vector(&keys.slh_dsa_sha2_128s_secret)?;
    write_json(
        &dir.join("slh_dsa_sha2_128s.json"),
        &SlhDsaVector {
            alg: "SLH-DSA-SHA2-128s",
            scheme: "SLH-DSA-SHA2-128s",
            hash: "SHA2",
            parameter_set: "128s",
            secret_key_format: "fips-205-serialized-secret-key",
            keygen_sk_seed: b64u(&SLH_DSA_SHA2_128S_SK_SEED),
            keygen_sk_prf: b64u(&SLH_DSA_SHA2_128S_SK_PRF),
            keygen_pk_seed: b64u(&SLH_DSA_SHA2_128S_PK_SEED),
            secret_key: b64u(&keys.slh_dsa_sha2_128s_secret),
            public_key: b64u(&keys.slh_dsa_sha2_128s_public),
            public_key_length: keys.slh_dsa_sha2_128s_public.len(),
            secret_key_length: keys.slh_dsa_sha2_128s_secret.len(),
            message: b64u(SLH_DSA_MESSAGE),
            signature: b64u(&slh_dsa_sha2_128s_signature),
            signature_length: slh_dsa_sha2_128s_signature.len(),
        },
    )?;

    let mlkem512 = mlkem512_kat(&keys.mlkem512_secret)?;
    write_json(
        &dir.join("mlkem512.json"),
        &MlKemVector {
            alg: "ML-KEM-512",
            scheme: "ML-KEM-512",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem512_secret),
            public_key: b64u(&keys.mlkem512_public),
            public_key_length: keys.mlkem512_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem512.ciphertext),
            shared_secret: b64u(&mlkem512.shared_secret),
            tampered_ciphertext: b64u(&mlkem512.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem512.tampered_shared_secret),
        },
    )?;

    let mlkem768 = mlkem768_kat(&keys.mlkem768_secret)?;
    write_json(
        &dir.join("mlkem768.json"),
        &MlKemVector {
            alg: "ML-KEM-768",
            scheme: "ML-KEM-768",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem768_secret),
            public_key: b64u(&keys.mlkem768_public),
            public_key_length: keys.mlkem768_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem768.ciphertext),
            shared_secret: b64u(&mlkem768.shared_secret),
            tampered_ciphertext: b64u(&mlkem768.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem768.tampered_shared_secret),
        },
    )?;

    let mlkem1024 = mlkem1024_kat(&keys.mlkem1024_secret)?;
    write_json(
        &dir.join("mlkem1024.json"),
        &MlKemVector {
            alg: "ML-KEM-1024",
            scheme: "ML-KEM-1024",
            secret_key_format: "fips-203-seed",
            secret_key: b64u(&keys.mlkem1024_secret),
            public_key: b64u(&keys.mlkem1024_public),
            public_key_length: keys.mlkem1024_public.len(),
            encaps_randomness: b64u(&ML_KEM_ENCAPS_RANDOMNESS),
            ciphertext: b64u(&mlkem1024.ciphertext),
            shared_secret: b64u(&mlkem1024.shared_secret),
            tampered_ciphertext: b64u(&mlkem1024.tampered_ciphertext),
            tampered_shared_secret: b64u(&mlkem1024.tampered_shared_secret),
        },
    )
}
