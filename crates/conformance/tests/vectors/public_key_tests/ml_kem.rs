// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
