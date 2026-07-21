// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
