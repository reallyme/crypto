// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn verify_hmac_case(
    v: &Value,
    field_name: &str,
    algorithm: MacAlgorithm,
) -> Result<(), VectorTestError> {
    let case = object_field(v, field_name)?;
    let key_bytes = b64u_to_bytes(field_string(case, "key")?)?;
    let message = b64u_to_bytes(field_string(case, "message")?)?;
    let tag = b64u_to_bytes(field_string(case, "tag")?)?;
    let key = HmacKey::from_slice(&key_bytes).map_err(|_| VectorTestError::HmacKey)?;
    let recomputed = hmac_authenticate(algorithm, &key, &message)
        .map_err(|_| VectorTestError::HmacAuthenticate)?;

    assert_eq!(tag, recomputed.as_bytes());
    hmac_verify(algorithm, &key, &message, &tag).map_err(|_| VectorTestError::HmacVerify)?;

    let mut tampered = tag;
    tampered[0] ^= 0x01;
    if hmac_verify(algorithm, &key, &message, &tampered).is_ok() {
        return Err(VectorTestError::HmacTamperAccepted);
    }

    Ok(())
}

#[test]
fn hmac_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("hmac.json")?;
    verify_hmac_case(&v, "hmac_sha256", MacAlgorithm::HmacSha256)?;
    verify_hmac_case(&v, "hmac_sha384", MacAlgorithm::HmacSha384)?;
    verify_hmac_case(&v, "hmac_sha512", MacAlgorithm::HmacSha512)?;
    Ok(())
}

#[test]
fn hash_vectors_match_workspace_primitives() -> Result<(), VectorTestError> {
    let v = load("hashes.json")?;
    let message = b64u_to_bytes(field_string(&v, "message")?)?;
    let sha2 = b64u_to_bytes(field_string(&v, "sha2_256")?)?;
    let sha2_384 = b64u_to_bytes(field_string(&v, "sha2_384")?)?;
    let sha2_512 = b64u_to_bytes(field_string(&v, "sha2_512")?)?;
    let sha3_224 = b64u_to_bytes(field_string(&v, "sha3_224")?)?;
    let sha3 = b64u_to_bytes(field_string(&v, "sha3_256")?)?;
    let sha3_384 = b64u_to_bytes(field_string(&v, "sha3_384")?)?;
    let sha3_512 = b64u_to_bytes(field_string(&v, "sha3_512")?)?;

    assert_eq!(sha2, sha2_256_digest(&message).as_bytes());
    assert_eq!(sha2_384, digest_sha2_384(&message).as_bytes());
    assert_eq!(sha2_512, digest_sha2_512(&message).as_bytes());
    assert_eq!(sha3_224, digest_sha3_224(&message).as_bytes());
    assert_eq!(sha3, sha3_256_digest(&message).as_bytes());
    assert_eq!(sha3_384, digest_sha3_384(&message).as_bytes());
    assert_eq!(sha3_512, digest_sha3_512(&message).as_bytes());
    Ok(())
}
