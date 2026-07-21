// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn write_kmac_vector(dir: &Path) -> Result<(), VectorGenError> {
    // NIST SP 800-185 KMAC256 sample with a 256-bit key, 4-byte message, and
    // "My Tagged Application" customization string.
    let key_bytes: Vec<u8> = (0x40..=0x5f).collect();
    let context = [0x00, 0x01, 0x02, 0x03];
    let customization = b"My Tagged Application";
    let key = Kmac256Key::from_slice(&key_bytes).map_err(|_| VectorGenError::Kmac)?;
    let derived =
        derive_kmac256(&key, &context, customization, 64).map_err(|_| VectorGenError::Kmac)?;
    write_json(
        &dir.join("kmac256.json"),
        &KmacVector {
            alg: "KMAC256",
            key: b64u(&key_bytes),
            context: b64u(&context),
            customization: b64u(customization),
            output_length: 64,
            derived_key: b64u(derived.as_bytes()),
        },
    )
}

fn chacha20_poly1305_vector() -> Result<ChaCha20Poly1305Vector, VectorGenError> {
    let key =
        ChaCha20Poly1305Key::from_slice(&CHACHA_KEY).map_err(|_| VectorGenError::ChaChaKey)?;
    let nonce = ChaCha20Poly1305Nonce::from_slice(&CHACHA_NONCE)
        .map_err(|_| VectorGenError::ChaChaNonce)?;
    let ciphertext = chacha_encrypt(&ChaChaEncryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        plaintext: CHACHA_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::ChaChaEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::ChaChaCiphertext)?;
    let decrypted = chacha_decrypt(&ChaChaDecryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::ChaChaDecrypt)?;

    if decrypted != CHACHA_PLAINTEXT {
        return Err(VectorGenError::ChaChaDecrypt);
    }

    Ok(ChaCha20Poly1305Vector {
        alg: "ChaCha20-Poly1305",
        key: b64u(&CHACHA_KEY),
        nonce: b64u(&CHACHA_NONCE),
        aad: b64u(CHACHA_AAD),
        plaintext: b64u(CHACHA_PLAINTEXT),
        ciphertext_with_tag: b64u(&ciphertext_bytes),
    })
}

fn xchacha20_poly1305_vector() -> Result<ChaCha20Poly1305Vector, VectorGenError> {
    let key =
        ChaCha20Poly1305Key::from_slice(&CHACHA_KEY).map_err(|_| VectorGenError::ChaChaKey)?;
    let nonce = XChaCha20Poly1305Nonce::from_slice(&XCHACHA_NONCE)
        .map_err(|_| VectorGenError::ChaChaNonce)?;
    let ciphertext = encrypt_xchacha20_poly1305(&XChaCha20Poly1305EncryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        plaintext: CHACHA_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::ChaChaEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = ChaChaCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::ChaChaCiphertext)?;
    let decrypted = decrypt_xchacha20_poly1305(&XChaCha20Poly1305DecryptRequest {
        key: &key,
        nonce,
        aad: CHACHA_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::ChaChaDecrypt)?;

    if decrypted != CHACHA_PLAINTEXT {
        return Err(VectorGenError::ChaChaDecrypt);
    }

    Ok(ChaCha20Poly1305Vector {
        alg: "XChaCha20-Poly1305",
        key: b64u(&CHACHA_KEY),
        nonce: b64u(&XCHACHA_NONCE),
        aad: b64u(CHACHA_AAD),
        plaintext: b64u(CHACHA_PLAINTEXT),
        ciphertext_with_tag: b64u(&ciphertext_bytes),
    })
}

fn write_chacha20_poly1305_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("chacha20poly1305.json"),
        &ChaCha20Poly1305Vectors {
            chacha20_poly1305: chacha20_poly1305_vector()?,
            xchacha20_poly1305: xchacha20_poly1305_vector()?,
        },
    )
}

fn hmac_vector(
    algorithm: MacAlgorithm,
    alg_name: &'static str,
) -> Result<HmacVector, VectorGenError> {
    let key = HmacKey::from_slice(&HMAC_KEY).map_err(|_| VectorGenError::HmacKey)?;
    let tag = hmac_authenticate(algorithm, &key, HMAC_MESSAGE)
        .map_err(|_| VectorGenError::HmacAuthenticate)?;

    Ok(HmacVector {
        alg: alg_name,
        key: b64u(&HMAC_KEY),
        message: b64u(HMAC_MESSAGE),
        tag: b64u(tag.as_bytes()),
    })
}

fn write_hmac_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("hmac.json"),
        &HmacVectors {
            hmac_sha256: hmac_vector(MacAlgorithm::HmacSha256, "HMAC-SHA-256")?,
            hmac_sha384: hmac_vector(MacAlgorithm::HmacSha384, "HMAC-SHA-384")?,
            hmac_sha512: hmac_vector(MacAlgorithm::HmacSha512, "HMAC-SHA-512")?,
        },
    )
}

// RFC 5869 HKDF-SHA-256 Test Case 1. The workspace `derive` is raw
// (Extract-then-Expand, no domain prefix), so this reproduces the published
// value and is the same output every lane's raw HKDF must produce.
const HKDF_IKM: &[u8] = &[0x0b; 22];
const HKDF_SALT: &[u8] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const HKDF_INFO: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
const HKDF_OKM_RFC5869: [u8; 42] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
];
const HKDF_SHA384_OKM: [u8; 42] = [
    0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05, 0x30, 0x90, 0x76, 0xa4, 0x4b, 0x3a, 0x9f, 0x38,
    0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc, 0xbf, 0x36, 0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7,
    0x48, 0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20, 0x4f, 0xc5,
];

fn write_hkdf_vector(dir: &Path) -> Result<(), VectorGenError> {
    let ikm = HkdfInputKeyMaterial::from_slice(HKDF_IKM);
    let salt = HkdfSalt::from_slice(HKDF_SALT);
    let info = HkdfInfo::from_slice(HKDF_INFO);
    let output = hkdf_derive::<42>(&DeriveRequest {
        suite: HkdfSuite::Sha2_256,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| VectorGenError::Hkdf)?;
    // Refuse to emit a vector that does not match the published RFC 5869 value.
    if output.as_bytes() != &HKDF_OKM_RFC5869 {
        return Err(VectorGenError::Hkdf);
    }
    write_json(
        &dir.join("hkdf.json"),
        &HkdfVector {
            alg: "HKDF-SHA256",
            hash: "SHA-256",
            ikm: b64u(HKDF_IKM),
            salt: b64u(HKDF_SALT),
            info: b64u(HKDF_INFO),
            output_len: 42,
            okm: b64u(output.as_bytes()),
        },
    )?;

    let sha384_output = hkdf_derive::<42>(&DeriveRequest {
        suite: HkdfSuite::Sha2_384,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| VectorGenError::Hkdf)?;
    if sha384_output.as_bytes() != &HKDF_SHA384_OKM {
        return Err(VectorGenError::Hkdf);
    }
    write_json(
        &dir.join("hkdf_sha384.json"),
        &HkdfVector {
            alg: "HKDF-SHA384",
            hash: "SHA-384",
            ikm: b64u(HKDF_IKM),
            salt: b64u(HKDF_SALT),
            info: b64u(HKDF_INFO),
            output_len: 42,
            okm: b64u(sha384_output.as_bytes()),
        },
    )
}

fn pbkdf2_vector(
    prf: Pbkdf2Prf,
    alg: &'static str,
    output_len: usize,
) -> Result<Pbkdf2Vector, VectorGenError> {
    let password =
        Pbkdf2Password::from_slice(PBKDF2_PASSWORD, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let salt = Pbkdf2Salt::from_slice(PBKDF2_SALT, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let iterations =
        Pbkdf2Iterations::from_u32(PBKDF2_ITERATIONS, prf).map_err(|_| VectorGenError::Pbkdf2)?;
    let derived = derive_pbkdf2_key(&Pbkdf2Request {
        prf,
        password: &password,
        salt: &salt,
        iterations,
        output_len,
    })
    .map_err(|_| VectorGenError::Pbkdf2)?;

    Ok(Pbkdf2Vector {
        alg,
        password: b64u(PBKDF2_PASSWORD),
        salt: b64u(PBKDF2_SALT),
        iterations: PBKDF2_ITERATIONS,
        output_len,
        derived_key: b64u(derived.as_bytes()),
    })
}

fn write_pbkdf2_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("pbkdf2.json"),
        &Pbkdf2Vectors {
            pbkdf2_hmac_sha256: pbkdf2_vector(Pbkdf2Prf::HmacSha256, "PBKDF2-HMAC-SHA-256", 32)?,
            pbkdf2_hmac_sha512: pbkdf2_vector(Pbkdf2Prf::HmacSha512, "PBKDF2-HMAC-SHA-512", 64)?,
        },
    )
}

fn write_hash_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("hashes.json"),
        &HashVector {
            message: b64u(HASH_MESSAGE),
            sha2_256: b64u(sha2_256_digest(HASH_MESSAGE).as_bytes()),
            sha2_384: b64u(digest_sha2_384(HASH_MESSAGE).as_bytes()),
            sha2_512: b64u(digest_sha2_512(HASH_MESSAGE).as_bytes()),
            sha3_224: b64u(digest_sha3_224(HASH_MESSAGE).as_bytes()),
            sha3_256: b64u(sha3_256_digest(HASH_MESSAGE).as_bytes()),
            sha3_384: b64u(digest_sha3_384(HASH_MESSAGE).as_bytes()),
            sha3_512: b64u(digest_sha3_512(HASH_MESSAGE).as_bytes()),
        },
    )
}

fn write_operation_response_vector(dir: &Path) -> Result<(), VectorGenError> {
    let request = CryptoOperationRequest {
        operation: Some(CryptoOperation::Hash(Box::new(CryptoHashRequest {
            algorithm: MessageField::some(CryptoAlgorithmIdentifier {
                algorithm: Some(ProtoAlgorithmBranch::Hash(EnumValue::from(
                    HashAlgorithm::HASH_ALGORITHM_SHA2_256,
                ))),
                __buffa_unknown_fields: Default::default(),
            }),
            input: b"abc".to_vec(),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };
    let request_protobuf = request.encode_to_vec();
    let request_json =
        serde_json::to_string(&request).map_err(|_| VectorGenError::SerializeJson)?;
    let malformed_protobuf = [0xff_u8, 0xff, 0xff];
    let malformed_json =
        r#"{"hash":{"algorithm":{"hash":"HASH_ALGORITHM_SHA2_256"},"input":"***"}}"#;

    write_json(
        &dir.join("operation_response.json"),
        &OperationResponseVectors {
            schema_version: 1,
            request_protobuf: b64u(&request_protobuf),
            request_json: b64u(request_json.as_bytes()),
            operation_response: b64u(process_operation_response(&request_protobuf).as_slice()),
            malformed_protobuf: b64u(&malformed_protobuf),
            malformed_protobuf_response: b64u(
                process_operation_response(&malformed_protobuf).as_slice(),
            ),
            malformed_json: b64u(malformed_json.as_bytes()),
            malformed_json_response: b64u(
                process_operation_response_json(malformed_json.as_bytes()).as_slice(),
            ),
        },
    )
}
