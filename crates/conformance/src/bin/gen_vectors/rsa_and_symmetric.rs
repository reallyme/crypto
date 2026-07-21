// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

const RSA_PUBLIC_KEY_DER_B64: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const RSA_MESSAGE_B64: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const RSA_PKCS1V15_SHA1_B64: &str = "hA_Xs2jYATVjBo9PtGmi-tr0fVJH57-QmUHvtZp2daMI_xk5XdMu4XYHRhCuP5LpHpjxJr2HvrM1ovdXq8bxfBDQkyR8fQgJcxs9lzCX4e9G5gu-cx1wo-YEoco6OGO6FZRoGHJgiUJ1gp6AbihXQYmzwkP4lJPeZTgTqfCzW9OURB6f-VWbxnWN9ALmIAboMmsMTBcJ4kEVQqK0EH5uRrGqF5R2QONNntmwYLByM3mIwyFGhm5RksGN4Xpz1b140xQLHIg6NdJS9x3okC2PEGyQ0l-1o1ct7yrqsnGcRoDkVLzpXQj_CjBAMQ7Vmmnb0yC11VuzlYBel3RFZM_dpA";
const RSA_PKCS1V15_SHA256_B64: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const RSA_PKCS1V15_SHA384_B64: &str = "UPPRJw8CyERJsI7PW5_9WbhZmmIe2wie3bt1FuZz_8ShFfgaFXwQfwn_YS4QtkPEAn6q438r05M25U-IYQXaDiisXSocMxRE06nqMvvrCgO6p6O-2_xWW8V8xhDox1aPqWdp54Ba6A0s3dywUe5zQpOAL-xQ8KLIZpIE118xKwhouFMGZBvCNJDDMMVTxIyp-EpThhiE5EFxL5vp9hVx4euaEfgQhw5MXnJmxKW4Pt9sSdMlvoP8aFrW5st9rLfvknJz4EwgIVevM5XYaWsrjZfJOKY5CmCVmvW-evOMjumMRRU9t2OOOf5NHszKzK3qtUvzCbXUz8F1FNFJeZ_GaA";
const RSA_PKCS1V15_SHA512_B64: &str = "MQ0UP3caVxnjq72kvCzRSvEbk2msNM0l76lv84OPjuA7Xu0EAb6H4WjoDnwqCy1aJe0wZQVVXEQyT8ch3AmDsY7_zCYlayZ8147Jno7n7qda8D0d8Q9SWZRK3Ir4HW6Ex5psmZaAhqSMAnku6On8oWIuofGKOOgMVn7AYDeehlh3f5NscqAtrEebrZ47B-d6XDHuyAe4zxsJPbBj0ef1vvRAA6wXnPIJ7Kvmajb8P4N8dCcjwjA7P9VbyZz_fY2HNpyAGAEFkjOO8uo05u30cHn6TLSYTCsKH2PCqkgH_-UEgjgp8IdBl5PzIHYac8wffRQ39G8LMZR07cll8HaPGA";
const RSA_PSS_SHA1_B64: &str = "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvEmi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABlkE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRKS-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4epH8U6dPriTdtFa2g_Tw";
const RSA_PSS_SHA256_B64: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
const RSA_PSS_SHA384_B64: &str = "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyoNUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQpmekoLB7ZHP6enlefBQ";
const RSA_PSS_SHA512_B64: &str = "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3BaGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2KoOKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVcLzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGxIf44p7HJX75J-WxE0Q";

fn write_rsa_vector(dir: &Path) -> Result<(), VectorGenError> {
    let public_der_bytes = decode_rsa_vector_field(RSA_PUBLIC_KEY_DER_B64)?;
    let message = decode_rsa_vector_field(RSA_MESSAGE_B64)?;
    let pkcs1v15_sha1_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA1_B64)?;
    let pkcs1v15_sha256_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA256_B64)?;
    let pkcs1v15_sha384_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA384_B64)?;
    let pkcs1v15_sha512_signature = decode_rsa_vector_field(RSA_PKCS1V15_SHA512_B64)?;
    let pss_sha256_signature = decode_rsa_vector_field(RSA_PSS_SHA256_B64)?;
    let pss_sha1_signature = decode_rsa_vector_field(RSA_PSS_SHA1_B64)?;
    let pss_sha384_signature = decode_rsa_vector_field(RSA_PSS_SHA384_B64)?;
    let pss_sha512_signature = decode_rsa_vector_field(RSA_PSS_SHA512_B64)?;

    let pkcs1v15_cases: [(RsaHash, &[u8]); 4] = [
        (RsaHash::Sha1, &pkcs1v15_sha1_signature),
        (RsaHash::Sha256, &pkcs1v15_sha256_signature),
        (RsaHash::Sha384, &pkcs1v15_sha384_signature),
        (RsaHash::Sha512, &pkcs1v15_sha512_signature),
    ];
    for (hash, signature) in pkcs1v15_cases {
        verify_rsa_pkcs1v15(
            &public_der_bytes,
            RsaPublicKeyDerEncoding::Pkcs1,
            hash,
            &message,
            signature,
        )
        .map_err(|_| VectorGenError::RsaVerify)?;
    }

    let pss_cases: [(RsaHash, usize, &[u8]); 4] = [
        (RsaHash::Sha256, 32, &pss_sha256_signature),
        (RsaHash::Sha1, 20, &pss_sha1_signature),
        (RsaHash::Sha384, 48, &pss_sha384_signature),
        (RsaHash::Sha512, 64, &pss_sha512_signature),
    ];
    for (hash, salt_len, signature) in pss_cases {
        verify_rsa_pss(
            &public_der_bytes,
            RsaPublicKeyDerEncoding::Pkcs1,
            RsaPssParams {
                message_hash: hash,
                mgf1_hash: hash,
                salt_len,
            },
            &message,
            signature,
        )
        .map_err(|_| VectorGenError::RsaVerify)?;
    }

    write_json(
        &dir.join("rsa.json"),
        &RsaVector {
            alg: "RSA",
            key_format: "PKCS1-DER-RSAPublicKey",
            public_key_der: RSA_PUBLIC_KEY_DER_B64.to_owned(),
            message: RSA_MESSAGE_B64.to_owned(),
            pkcs1v15_sha1_signature: RSA_PKCS1V15_SHA1_B64.to_owned(),
            pkcs1v15_sha256_signature: RSA_PKCS1V15_SHA256_B64.to_owned(),
            pkcs1v15_sha384_signature: RSA_PKCS1V15_SHA384_B64.to_owned(),
            pkcs1v15_sha512_signature: RSA_PKCS1V15_SHA512_B64.to_owned(),
            pss_sha256_mgf1_sha256_salt_len: 32,
            pss_sha256_mgf1_sha256_signature: RSA_PSS_SHA256_B64.to_owned(),
            pss_sha1_mgf1_sha1_salt_len: 20,
            pss_sha1_mgf1_sha1_signature: RSA_PSS_SHA1_B64.to_owned(),
            pss_sha384_mgf1_sha384_salt_len: 48,
            pss_sha384_mgf1_sha384_signature: RSA_PSS_SHA384_B64.to_owned(),
            pss_sha512_mgf1_sha512_salt_len: 64,
            pss_sha512_mgf1_sha512_signature: RSA_PSS_SHA512_B64.to_owned(),
        },
    )
}

fn decode_rsa_vector_field(value: &str) -> Result<Vec<u8>, VectorGenError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VectorGenError::RsaVectorDecode)
}

fn x_wing_vector(
    alg: &'static str,
    keypair: XWingKeypairFn,
    encapsulate: XWingEncapsulateFn,
) -> Result<XWingVector, VectorGenError> {
    let (public_key, secret_key) =
        keypair(&X_WING_SECRET_SEED).map_err(|_| VectorGenError::XWingOperation)?;
    let (ciphertext, shared_secret) = encapsulate(&public_key, &X_WING_ENCAPS_SEED)
        .map_err(|_| VectorGenError::XWingOperation)?;

    Ok(XWingVector {
        alg,
        scheme: alg,
        secret_key_format: "x-wing-seed",
        secret_key: b64u(&secret_key),
        public_key: b64u(&public_key),
        public_key_length: public_key.len(),
        encaps_seed: b64u(&X_WING_ENCAPS_SEED),
        ciphertext: b64u(&ciphertext),
        ciphertext_length: ciphertext.len(),
        shared_secret: b64u(&shared_secret),
    })
}

fn write_x_wing_vector(dir: &Path) -> Result<(), VectorGenError> {
    write_json(
        &dir.join("x_wing.json"),
        &XWingVectors {
            x_wing_768: x_wing_vector(
                "X-Wing-768",
                generate_x_wing_768_keypair_derand,
                x_wing_768_encapsulate_derand,
            )?,
        },
    )
}

fn hpke_case(
    alg: &'static str,
    suite: HpkeSuite,
    recipient_secret_key: &[u8],
    recipient_public_key: &[u8],
    encaps_seed: &[u8],
) -> Result<HpkeVector, VectorGenError> {
    let sealed = hpke_seal_base_derand(&HpkeDerandSealRequest {
        suite,
        recipient_public_key,
        encapsulation_randomness: encaps_seed,
        info: HPKE_INFO,
        aad: HPKE_AAD,
        plaintext: HPKE_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::HpkeOperation)?;

    let opened = hpke_open_base(&HpkeOpenRequest {
        suite,
        encapsulated_key: &sealed.encapsulated_key,
        recipient_private_key: recipient_secret_key,
        info: HPKE_INFO,
        aad: HPKE_AAD,
        ciphertext: &sealed.ciphertext,
    })
    .map_err(|_| VectorGenError::HpkeOperation)?;
    if opened.plaintext.as_slice() != HPKE_PLAINTEXT {
        return Err(VectorGenError::HpkeOperation);
    }

    let mut tampered_ciphertext = sealed.ciphertext.clone();
    if let Some(first) = tampered_ciphertext.first_mut() {
        *first ^= 0x01;
    }

    Ok(HpkeVector {
        alg,
        mode: "base",
        kem_id: suite.kem_id(),
        kdf_id: suite.kdf_id(),
        aead_id: suite.aead_id(),
        recipient_secret_key: b64u(recipient_secret_key),
        recipient_public_key: b64u(recipient_public_key),
        encaps_seed: b64u(encaps_seed),
        info: b64u(HPKE_INFO),
        aad: b64u(HPKE_AAD),
        plaintext: b64u(HPKE_PLAINTEXT),
        encapsulated_key: b64u(&sealed.encapsulated_key),
        ciphertext: b64u(&sealed.ciphertext),
        tampered_ciphertext: b64u(&tampered_ciphertext),
    })
}

fn write_hpke_vector(dir: &Path, keys: &GeneratedKeys) -> Result<(), VectorGenError> {
    let p256_public =
        decompress_p256(&keys.p256_public).map_err(|_| VectorGenError::P256Decompress)?;
    write_json(
        &dir.join("hpke.json"),
        &HpkeVectors {
            p256_sha256_aes256gcm: hpke_case(
                "HPKE-P256-SHA256-AES256GCM",
                crypto_hpke::HPKE_DHKEM_P256_HKDF_SHA256_AES256GCM,
                &keys.p256_secret,
                &p256_public,
                &HPKE_P256_ENCAPS_SEED,
            )?,
            x25519_sha256_chacha20poly1305: hpke_case(
                "HPKE-X25519-SHA256-CHACHA20POLY1305",
                crypto_hpke::HPKE_DHKEM_X25519_HKDF_SHA256_CHACHA20POLY1305,
                &keys.x25519_secret,
                &keys.x25519_public,
                &HPKE_X25519_ENCAPS_SEED,
            )?,
        },
    )
}

fn write_aes_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes256GcmKey::from_slice(&AES_KEY).map_err(|_| VectorGenError::AesKey)?;
    let nonce = Aes256GcmNonce::from_slice(&AES_NONCE).map_err(|_| VectorGenError::AesNonce)?;
    let ciphertext = encrypt(&EncryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        plaintext: AES_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesCiphertext)?;
    let decrypted = decrypt(&DecryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesDecrypt)?;

    if decrypted != AES_PLAINTEXT {
        return Err(VectorGenError::AesDecrypt);
    }

    write_json(
        &dir.join("aes256gcm.json"),
        &AesGcmVector {
            alg: "AES-256-GCM",
            key: b64u(&AES_KEY),
            nonce: b64u(&AES_NONCE),
            aad: b64u(AES_AAD),
            plaintext: b64u(AES_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_aes128_gcm_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes128GcmKey::from_slice(&AES_128_KEY).map_err(|_| VectorGenError::AesKey)?;
    let nonce = Aes128GcmNonce::from_slice(&AES_NONCE).map_err(|_| VectorGenError::AesNonce)?;
    let ciphertext = encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        plaintext: AES_128_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesCiphertext)?;
    let decrypted = decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesDecrypt)?;

    if decrypted != AES_128_PLAINTEXT {
        return Err(VectorGenError::AesDecrypt);
    }

    write_json(
        &dir.join("aes128gcm.json"),
        &AesGcmVector {
            alg: "AES-128-GCM",
            key: b64u(&AES_128_KEY),
            nonce: b64u(&AES_NONCE),
            aad: b64u(AES_AAD),
            plaintext: b64u(AES_128_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_aes192_gcm_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes192GcmKey::from_slice(&AES_192_KEY).map_err(|_| VectorGenError::AesKey)?;
    let nonce = Aes192GcmNonce::from_slice(&AES_NONCE).map_err(|_| VectorGenError::AesNonce)?;
    let ciphertext = encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        plaintext: AES_192_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesEncrypt)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = CiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesCiphertext)?;
    let decrypted = decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
        key: &key,
        nonce,
        aad: AES_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesDecrypt)?;

    if decrypted != AES_192_PLAINTEXT {
        return Err(VectorGenError::AesDecrypt);
    }

    write_json(
        &dir.join("aes192gcm.json"),
        &AesGcmVector {
            alg: "AES-192-GCM",
            key: b64u(&AES_192_KEY),
            nonce: b64u(&AES_NONCE),
            aad: b64u(AES_AAD),
            plaintext: b64u(AES_192_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_concat_kdf_vector(dir: &Path) -> Result<(), VectorGenError> {
    let shared_secret =
        JwaSharedSecret::from_slice(&CONCAT_KDF_Z).map_err(|_| VectorGenError::ConcatKdf)?;
    let algorithm_id = JwaAlgorithmId::from_slice(CONCAT_KDF_ALGORITHM_ID)
        .map_err(|_| VectorGenError::ConcatKdf)?;
    let party_u_info =
        JwaPartyInfo::from_slice(CONCAT_KDF_PARTY_U_INFO).map_err(|_| VectorGenError::ConcatKdf)?;
    let party_v_info =
        JwaPartyInfo::from_slice(CONCAT_KDF_PARTY_V_INFO).map_err(|_| VectorGenError::ConcatKdf)?;
    let derived_key = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    })
    .map_err(|_| VectorGenError::ConcatKdf)?;

    write_json(
        &dir.join("concat_kdf.json"),
        &ConcatKdfVector {
            alg: "JWA-CONCAT-KDF-SHA256",
            profile: "ECDH-ES+A128GCM",
            shared_secret: b64u(&CONCAT_KDF_Z),
            algorithm_id: b64u(CONCAT_KDF_ALGORITHM_ID),
            party_u_info: b64u(CONCAT_KDF_PARTY_U_INFO),
            party_v_info: b64u(CONCAT_KDF_PARTY_V_INFO),
            output_len: 16,
            derived_key: b64u(derived_key.as_bytes()),
        },
    )
}

fn write_aes_gcm_siv_vector(dir: &Path) -> Result<(), VectorGenError> {
    let key = Aes256GcmSivKey::from_slice(&GCM_SIV_KEY).map_err(|_| VectorGenError::AesGcmSiv)?;
    let nonce =
        Aes256GcmSivNonce::from_slice(&GCM_SIV_NONCE).map_err(|_| VectorGenError::AesGcmSiv)?;
    let ciphertext = gcm_siv_encrypt(&GcmSivEncryptRequest {
        key: &key,
        nonce,
        aad: GCM_SIV_AAD,
        plaintext: GCM_SIV_PLAINTEXT,
    })
    .map_err(|_| VectorGenError::AesGcmSiv)?;
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();
    let ciphertext_for_decrypt = GcmSivCiphertextWithTag::from_vec(ciphertext_bytes.clone())
        .map_err(|_| VectorGenError::AesGcmSiv)?;
    let decrypted = gcm_siv_decrypt(&GcmSivDecryptRequest {
        key: &key,
        nonce,
        aad: GCM_SIV_AAD,
        ciphertext: &ciphertext_for_decrypt,
    })
    .map_err(|_| VectorGenError::AesGcmSiv)?;
    if decrypted != GCM_SIV_PLAINTEXT {
        return Err(VectorGenError::AesGcmSiv);
    }

    write_json(
        &dir.join("aes256gcmsiv.json"),
        &AesGcmSivVector {
            alg: "AES-256-GCM-SIV",
            key: b64u(&GCM_SIV_KEY),
            nonce: b64u(&GCM_SIV_NONCE),
            aad: b64u(GCM_SIV_AAD),
            plaintext: b64u(GCM_SIV_PLAINTEXT),
            ciphertext_with_tag: b64u(&ciphertext_bytes),
        },
    )
}

fn write_argon2id_vector(dir: &Path) -> Result<(), VectorGenError> {
    let profile = Argon2Profile::V1;
    let secret =
        Argon2Secret::from_slice(ARGON2ID_SECRET, profile).map_err(|_| VectorGenError::Argon2id)?;
    let salt =
        Argon2Salt::from_slice(&ARGON2ID_SALT, profile).map_err(|_| VectorGenError::Argon2id)?;
    let derived = argon2id_derive_key(&DeriveKeyRequest {
        profile,
        secret: &secret,
        salt: &salt,
    })
    .map_err(|_| VectorGenError::Argon2id)?;

    write_json(
        &dir.join("argon2id.json"),
        &Argon2idVector {
            alg: "Argon2id",
            kdf_version: 1,
            memory_cost_kib: 262_144,
            time_cost: 3,
            parallelism: 1,
            secret: b64u(ARGON2ID_SECRET),
            salt: b64u(&ARGON2ID_SALT),
            derived_key: b64u(derived.as_bytes()),
        },
    )
}

fn write_aes_kw_vector(
    dir: &Path,
    file_name: &str,
    alg: &'static str,
    kek: &[u8],
    key_data: &[u8],
    wrap: impl FnOnce(&[u8]) -> Result<crypto_aes_kw::AesKwWrappedKey, crypto_core::CryptoError>,
    unwrap: impl FnOnce(&[u8]) -> Result<crypto_aes_kw::AesKwKeyData, crypto_core::CryptoError>,
) -> Result<(), VectorGenError> {
    let wrapped = wrap(key_data).map_err(|_| VectorGenError::AesKw)?;
    let unwrapped = unwrap(wrapped.as_bytes()).map_err(|_| VectorGenError::AesKw)?;
    if unwrapped.as_bytes() != key_data {
        return Err(VectorGenError::AesKw);
    }

    write_json(
        &dir.join(file_name),
        &AesKwVector {
            alg,
            kek: b64u(kek),
            key_data: b64u(key_data),
            wrapped_key: b64u(wrapped.as_bytes()),
        },
    )
}

fn write_aes_kw_vectors(dir: &Path) -> Result<(), VectorGenError> {
    let kek128 = &AES_KEY[..16];
    let kek192 = &AES_KEY[..24];
    let kek256 = &AES_KEY;
    let aes128 = Aes128KwKek::from_slice(kek128).map_err(|_| VectorGenError::AesKw)?;
    let aes192 = Aes192KwKek::from_slice(kek192).map_err(|_| VectorGenError::AesKw)?;
    let aes256 = Aes256KwKek::from_slice(kek256).map_err(|_| VectorGenError::AesKw)?;
    write_aes_kw_vector(
        dir,
        "aes128kw.json",
        "AES-128-KW",
        kek128,
        &AES_KW_128_BIT_KEY_DATA,
        |key_data| wrap_key_aes128(&aes128, key_data),
        |wrapped| unwrap_key_aes128(&aes128, wrapped),
    )?;
    write_aes_kw_vector(
        dir,
        "aes192kw.json",
        "AES-192-KW",
        kek192,
        &AES_KW_128_BIT_KEY_DATA,
        |key_data| wrap_key_aes192(&aes192, key_data),
        |wrapped| unwrap_key_aes192(&aes192, wrapped),
    )?;
    write_aes_kw_vector(
        dir,
        "aes256kw.json",
        "AES-256-KW",
        kek256,
        &AES_KW_256_BIT_KEY_DATA,
        |key_data| wrap_key_aes256(&aes256, key_data),
        |wrapped| unwrap_key_aes256(&aes256, wrapped),
    )
}
