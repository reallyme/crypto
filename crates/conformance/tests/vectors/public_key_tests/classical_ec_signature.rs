// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
