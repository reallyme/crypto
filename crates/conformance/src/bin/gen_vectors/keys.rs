// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn derive_ml_dsa_keypair<P: MlDsaParams>(
    seed_bytes: &[u8],
) -> Result<KeypairBytes, VectorGenError> {
    let seed = MlDsaSeed::try_from(seed_bytes).map_err(|_| VectorGenError::MlDsaSeed)?;
    let signing_key = MlDsaSigningKey::<P>::from_seed(&seed);
    let verifying_key = signing_key.verifying_key();

    Ok((
        verifying_key.to_bytes().to_vec(),
        signing_key.to_seed().to_vec(),
    ))
}

fn derive_mlkem512_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_512_SEED[..]).map_err(|_| VectorGenError::MlKem512Seed)?;
    let decapsulation_key = MlKem512DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

fn derive_mlkem768_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_768_SEED[..]).map_err(|_| VectorGenError::MlKem768Seed)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

fn derive_mlkem1024_keypair() -> Result<KeypairBytes, VectorGenError> {
    let seed =
        MlKemSeed::try_from(&ML_KEM_1024_SEED[..]).map_err(|_| VectorGenError::MlKem1024Seed)?;
    let decapsulation_key = MlKem1024DecapsulationKey::from_seed(seed);
    let public_key = decapsulation_key.encapsulation_key().to_bytes();
    let secret_seed = decapsulation_key.to_bytes();

    Ok((
        public_key.as_slice().to_vec(),
        secret_seed.as_slice().to_vec(),
    ))
}

/// Deterministic ML-DSA signature over [`ML_DSA_MESSAGE`], using the
/// FIPS 204 deterministic variant with an empty context — the same mode
/// every runtime lane must reproduce byte-for-byte.
fn sign_ml_dsa_vector<P: MlDsaParams>(seed_bytes: &[u8]) -> Result<Vec<u8>, VectorGenError> {
    let seed = MlDsaSeed::try_from(seed_bytes).map_err(|_| VectorGenError::MlDsaSeed)?;
    let signing_key = MlDsaSigningKey::<P>::from_seed(&seed);
    // `try_sign` is ML-DSA's deterministic, empty-context signing mode, so
    // every runtime lane must reproduce this signature bit-for-bit.
    let signature = MlDsaSigner::try_sign(&signing_key, ML_DSA_MESSAGE)
        .map_err(|_| VectorGenError::MlDsaSign)?;
    Ok(signature.to_bytes().to_vec())
}

fn derive_slh_dsa_sha2_128s_vector_keypair() -> Result<KeypairBytes, VectorGenError> {
    let (public_key, secret_key) = derive_slh_dsa_sha2_128s_keypair(
        &SLH_DSA_SHA2_128S_SK_SEED,
        &SLH_DSA_SHA2_128S_SK_PRF,
        &SLH_DSA_SHA2_128S_PK_SEED,
    )
    .map_err(|_| VectorGenError::SlhDsaOperation)?;

    Ok((public_key, secret_key.to_vec()))
}

fn sign_slh_dsa_sha2_128s_vector(secret_key: &[u8]) -> Result<Vec<u8>, VectorGenError> {
    sign_slh_dsa_sha2_128s(secret_key, SLH_DSA_MESSAGE).map_err(|_| VectorGenError::SlhDsaOperation)
}

/// One byte flipped in a copy of `ciphertext`, used to exercise ML-KEM
/// implicit rejection.
fn tamper_first_byte(ciphertext: &[u8]) -> Vec<u8> {
    let mut tampered = ciphertext.to_vec();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
    }
    tampered
}

/// Computes the deterministic ML-KEM-512 known-answer data: encapsulate to
/// the vector public key with fixed randomness, then decapsulate a tampered
/// ciphertext to capture the implicit-rejection secret.
fn mlkem512_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem512Seed)?;
    let decapsulation_key = MlKem512DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem512Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem512Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

/// ML-KEM-768 counterpart of [`mlkem512_kat`].
fn mlkem768_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem768Seed)?;
    let decapsulation_key = MlKem768DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem768Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem768Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

/// ML-KEM-1024 counterpart of [`mlkem768_kat`].
fn mlkem1024_kat(secret_seed: &[u8]) -> Result<MlKemKat, VectorGenError> {
    let seed = MlKemSeed::try_from(secret_seed).map_err(|_| VectorGenError::MlKem1024Seed)?;
    let decapsulation_key = MlKem1024DecapsulationKey::from_seed(seed);
    let randomness = MlKemB32::try_from(&ML_KEM_ENCAPS_RANDOMNESS[..])
        .map_err(|_| VectorGenError::MlKem1024Seed)?;

    let (ciphertext, shared_secret) = decapsulation_key
        .encapsulation_key()
        .encapsulate_deterministic(&randomness);
    let ciphertext = ciphertext.as_slice().to_vec();
    let shared_secret = shared_secret.as_slice().to_vec();

    let tampered_ciphertext = tamper_first_byte(&ciphertext);
    let tampered = MlKem1024Ciphertext::try_from(tampered_ciphertext.as_slice())
        .map_err(|_| VectorGenError::MlKemCiphertext)?;
    let tampered_shared_secret = decapsulation_key.decapsulate(&tampered).as_slice().to_vec();
    if tampered_shared_secret == shared_secret {
        return Err(VectorGenError::MlKemImplicitRejection);
    }

    Ok(MlKemKat {
        ciphertext,
        shared_secret,
        tampered_ciphertext,
        tampered_shared_secret,
    })
}

fn generate_keys() -> Result<GeneratedKeys, VectorGenError> {
    let p256_secret_key =
        P256SecretKey::from_slice(&P256_SECRET).map_err(|_| VectorGenError::P256Keypair)?;
    let p256_signing_key = P256SigningKey::from(&p256_secret_key);
    let p256_public = p256_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p256_secret = p256_secret_key.to_bytes().to_vec();
    let p256_peer_secret_key =
        P256SecretKey::from_slice(&P256_PEER_SECRET).map_err(|_| VectorGenError::P256Keypair)?;
    let p256_peer_signing_key = P256SigningKey::from(&p256_peer_secret_key);
    let p256_peer_public = p256_peer_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p256_peer_secret = p256_peer_secret_key.to_bytes().to_vec();

    let p384_secret_key =
        P384SecretKey::from_slice(&P384_SECRET).map_err(|_| VectorGenError::P384Keypair)?;
    let p384_signing_key = P384SigningKey::from(&p384_secret_key);
    let p384_public = p384_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p384_secret = p384_secret_key.to_bytes().to_vec();
    let p384_peer_secret_key =
        P384SecretKey::from_slice(&P384_PEER_SECRET).map_err(|_| VectorGenError::P384Keypair)?;
    let p384_peer_signing_key = P384SigningKey::from(&p384_peer_secret_key);
    let p384_peer_public = p384_peer_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p384_peer_secret = p384_peer_secret_key.to_bytes().to_vec();

    let p521_secret_key =
        P521SecretKey::from_slice(&P521_SECRET).map_err(|_| VectorGenError::P521Keypair)?;
    let p521_signing_key = P521SigningKey::from(&p521_secret_key);
    let p521_public = p521_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p521_secret = p521_secret_key.to_bytes().to_vec();
    let p521_peer_secret_key =
        P521SecretKey::from_slice(&P521_PEER_SECRET).map_err(|_| VectorGenError::P521Keypair)?;
    let p521_peer_signing_key = P521SigningKey::from(&p521_peer_secret_key);
    let p521_peer_public = p521_peer_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let p521_peer_secret = p521_peer_secret_key.to_bytes().to_vec();

    let ed25519_signing_key = Ed25519SigningKey::from_bytes(&ED25519_SECRET);
    let ed25519_public = ed25519_signing_key.verifying_key().to_bytes().to_vec();
    let ed25519_secret = ED25519_SECRET.to_vec();

    let secp256k1_signing_key = Secp256k1SigningKey::from_slice(&SECP256K1_SECRET)
        .map_err(|_| VectorGenError::Secp256k1Keypair)?;
    let secp256k1_public = secp256k1_signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    let secp256k1_secret = SECP256K1_SECRET.to_vec();

    let x25519_secret_key = X25519StaticSecret::from(X25519_SECRET);
    let x25519_public_key = X25519PublicKey::from(&x25519_secret_key);
    let x25519_peer_secret_key = X25519StaticSecret::from(X25519_PEER_SECRET);
    let x25519_peer_public_key = X25519PublicKey::from(&x25519_peer_secret_key);
    let x25519_public = x25519_public_key.as_bytes().to_vec();
    let x25519_secret = X25519_SECRET.to_vec();
    let x25519_peer_public = x25519_peer_public_key.as_bytes().to_vec();
    let x25519_peer_secret = X25519_PEER_SECRET.to_vec();
    let (ml_dsa_44_public, ml_dsa_44_secret) = derive_ml_dsa_keypair::<MlDsa44>(&ML_DSA_44_SEED)?;
    let (ml_dsa_65_public, ml_dsa_65_secret) = derive_ml_dsa_keypair::<MlDsa65>(&ML_DSA_65_SEED)?;
    let (ml_dsa_87_public, ml_dsa_87_secret) = derive_ml_dsa_keypair::<MlDsa87>(&ML_DSA_87_SEED)?;
    let (slh_dsa_sha2_128s_public, slh_dsa_sha2_128s_secret) =
        derive_slh_dsa_sha2_128s_vector_keypair()?;
    let (mlkem512_public, mlkem512_secret) = derive_mlkem512_keypair()?;
    let (mlkem768_public, mlkem768_secret) = derive_mlkem768_keypair()?;
    let (mlkem1024_public, mlkem1024_secret) = derive_mlkem1024_keypair()?;

    Ok(GeneratedKeys {
        p256_public,
        p256_secret,
        p256_peer_public,
        p256_peer_secret,
        p384_public,
        p384_secret,
        p384_peer_public,
        p384_peer_secret,
        p521_public,
        p521_secret,
        p521_peer_public,
        p521_peer_secret,
        ed25519_public,
        ed25519_secret,
        secp256k1_public,
        secp256k1_secret,
        x25519_public,
        x25519_secret,
        x25519_peer_public,
        x25519_peer_secret,
        ml_dsa_44_public,
        ml_dsa_44_secret,
        ml_dsa_65_public,
        ml_dsa_65_secret,
        ml_dsa_87_public,
        ml_dsa_87_secret,
        slh_dsa_sha2_128s_public,
        slh_dsa_sha2_128s_secret,
        mlkem512_public,
        mlkem512_secret,
        mlkem768_public,
        mlkem768_secret,
        mlkem1024_public,
        mlkem1024_secret,
    })
}
