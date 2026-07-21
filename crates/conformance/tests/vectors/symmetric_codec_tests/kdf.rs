// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn kmac256_vector_matches_workspace_primitive() -> Result<(), VectorTestError> {
    let v = load("kmac256.json")?;
    assert_eq!(field_string(&v, "alg")?, "KMAC256");
    let key = b64u_to_bytes(field_string(&v, "key")?)?;
    let context = b64u_to_bytes(field_string(&v, "context")?)?;
    let customization = b64u_to_bytes(field_string(&v, "customization")?)?;
    let derived_key = b64u_to_bytes(field_string(&v, "derived_key")?)?;
    let output_length = v
        .get("output_length")
        .and_then(serde_json::Value::as_u64)
        .ok_or(VectorTestError::InvalidField)?;

    let output_length =
        usize::try_from(output_length).map_err(|_| VectorTestError::InvalidField)?;
    let key = Kmac256Key::from_slice(&key).map_err(|_| VectorTestError::InvalidField)?;
    let derived = derive_kmac256(&key, &context, &customization, output_length)
        .map_err(|_| VectorTestError::InvalidField)?;
    assert_eq!(derived.as_bytes(), derived_key);
    Ok(())
}

fn verify_pbkdf2_case(v: &Value, field_name: &str, prf: Pbkdf2Prf) -> Result<(), VectorTestError> {
    let case = object_field(v, field_name)?;
    let password_bytes = b64u_to_bytes(field_string(case, "password")?)?;
    let salt_bytes = b64u_to_bytes(field_string(case, "salt")?)?;
    let derived_key = b64u_to_bytes(field_string(case, "derived_key")?)?;
    let iterations = case
        .get("iterations")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;
    let output_len = case
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    let password =
        Pbkdf2Password::from_slice(&password_bytes, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let salt = Pbkdf2Salt::from_slice(&salt_bytes, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let iterations =
        Pbkdf2Iterations::from_u32(iterations, prf).map_err(|_| VectorTestError::Pbkdf2)?;
    let output = derive_pbkdf2_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len,
    })
    .map_err(|_| VectorTestError::Pbkdf2)?;

    assert_eq!(output.as_bytes(), derived_key);
    Ok(())
}

#[test]
fn pbkdf2_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("pbkdf2.json")?;
    assert_eq!(
        field_string(object_field(&v, "pbkdf2_hmac_sha256")?, "alg")?,
        "PBKDF2-HMAC-SHA-256"
    );
    assert_eq!(
        field_string(object_field(&v, "pbkdf2_hmac_sha512")?, "alg")?,
        "PBKDF2-HMAC-SHA-512"
    );
    verify_pbkdf2_case(&v, "pbkdf2_hmac_sha256", Pbkdf2Prf::HmacSha256)?;
    verify_pbkdf2_case(&v, "pbkdf2_hmac_sha512", Pbkdf2Prf::HmacSha512)?;
    Ok(())
}

fn verify_hkdf_vector(
    file_name: &str,
    suite: HkdfSuite,
    expected_algorithm: &str,
    expected_hash: &str,
) -> Result<(), VectorTestError> {
    let v = load(file_name)?;
    assert_eq!(field_string(&v, "alg")?, expected_algorithm);
    assert_eq!(field_string(&v, "hash")?, expected_hash);

    let ikm_bytes = b64u_to_bytes(field_string(&v, "ikm")?)?;
    let salt_bytes = b64u_to_bytes(field_string(&v, "salt")?)?;
    let info_bytes = b64u_to_bytes(field_string(&v, "info")?)?;
    let okm = b64u_to_bytes(field_string(&v, "okm")?)?;
    let output_len = v
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    // The shared HKDF vector is the RFC 5869 L=42 case; the derive API is
    // const-generic on the output length, so pin it and reject drift.
    if output_len != 42 || okm.len() != 42 {
        return Err(VectorTestError::Hkdf);
    }

    let ikm = HkdfInputKeyMaterial::from_slice(&ikm_bytes);
    let salt = HkdfSalt::from_slice(&salt_bytes);
    let info = HkdfInfo::from_slice(&info_bytes);
    let output = hkdf_derive::<42>(&DeriveRequest {
        suite,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| VectorTestError::Hkdf)?;

    assert_eq!(output.as_bytes(), okm.as_slice());
    Ok(())
}

#[test]
fn hkdf_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    verify_hkdf_vector("hkdf.json", HkdfSuite::Sha2_256, "HKDF-SHA256", "SHA-256")?;
    verify_hkdf_vector(
        "hkdf_sha384.json",
        HkdfSuite::Sha2_384,
        "HKDF-SHA384",
        "SHA-384",
    )
}

#[test]
fn jwa_concat_kdf_vector_matches_rfc7518_appendix_c() -> Result<(), VectorTestError> {
    let v = load("concat_kdf.json")?;
    assert_eq!(field_string(&v, "alg")?, "JWA-CONCAT-KDF-SHA256");
    assert_eq!(field_string(&v, "profile")?, "ECDH-ES+A128GCM");

    let shared_secret_bytes = b64u_to_bytes(field_string(&v, "shared_secret")?)?;
    let algorithm_id_bytes = b64u_to_bytes(field_string(&v, "algorithm_id")?)?;
    let party_u_info_bytes = b64u_to_bytes(field_string(&v, "party_u_info")?)?;
    let party_v_info_bytes = b64u_to_bytes(field_string(&v, "party_v_info")?)?;
    let derived_key = b64u_to_bytes(field_string(&v, "derived_key")?)?;
    let output_len = v
        .get("output_len")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(VectorTestError::InvalidField)?;

    if output_len != 16 || derived_key.len() != 16 {
        return Err(VectorTestError::ConcatKdf);
    }

    let shared_secret = JwaSharedSecret::from_slice(&shared_secret_bytes)
        .map_err(|_| VectorTestError::ConcatKdf)?;
    let algorithm_id =
        JwaAlgorithmId::from_slice(&algorithm_id_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let party_u_info =
        JwaPartyInfo::from_slice(&party_u_info_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let party_v_info =
        JwaPartyInfo::from_slice(&party_v_info_bytes).map_err(|_| VectorTestError::ConcatKdf)?;
    let output = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    })
    .map_err(|_| VectorTestError::ConcatKdf)?;

    assert_eq!(output.as_bytes(), derived_key.as_slice());
    Ok(())
}

#[test]
fn argon2id_vector_matches_workspace_primitive() -> Result<(), VectorTestError> {
    let v = load("argon2id.json")?;
    assert_eq!(field_string(&v, "alg")?, "Argon2id");
    // The committed vector pins the Argon2id V1 cost profile.
    assert_eq!(
        v.get("kdf_version").and_then(Value::as_u64),
        Some(1),
        "kdf_version"
    );
    assert_eq!(
        v.get("memory_cost_kib").and_then(Value::as_u64),
        Some(262_144),
        "memory_cost_kib"
    );
    assert_eq!(
        v.get("time_cost").and_then(Value::as_u64),
        Some(3),
        "time_cost"
    );
    assert_eq!(
        v.get("parallelism").and_then(Value::as_u64),
        Some(1),
        "parallelism"
    );

    let secret_bytes = b64u_to_bytes(field_string(&v, "secret")?)?;
    let salt_bytes = b64u_to_bytes(field_string(&v, "salt")?)?;
    let derived_key = b64u_to_bytes(field_string(&v, "derived_key")?)?;

    let profile = Argon2Profile::V1;
    let secret =
        Argon2Secret::from_slice(&secret_bytes, profile).map_err(|_| VectorTestError::Argon2id)?;
    let salt =
        Argon2Salt::from_slice(&salt_bytes, profile).map_err(|_| VectorTestError::Argon2id)?;
    let derived = argon2id_derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    })
    .map_err(|_| VectorTestError::Argon2id)?;

    assert_eq!(derived.as_bytes().as_slice(), derived_key.as_slice());
    Ok(())
}
