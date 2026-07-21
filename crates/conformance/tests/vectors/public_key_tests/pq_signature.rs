// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
