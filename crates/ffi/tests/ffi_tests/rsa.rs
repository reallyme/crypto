// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn rsa_ffi_verifies_pkcs1v15_and_pss() -> Result<(), crypto_core::CryptoError> {
    let public_der = decode_base64url(RSA_PUBLIC_KEY_DER)?;
    let message = decode_base64url(RSA_MESSAGE)?;
    let pkcs1_signature = decode_base64url(RSA_PKCS1V15_SHA256_SIGNATURE)?;
    let pkcs1_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pkcs1v15(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            rsa_ffi::RSA_HASH_SHA256,
            message.as_ptr(),
            message.len(),
            pkcs1_signature.as_ptr(),
            pkcs1_signature.len(),
        )
    };
    assert_eq!(pkcs1_status, status::CRYPTO_OK);

    let pss_signature = decode_base64url(RSA_PSS_SHA256_SIGNATURE)?;
    let pss_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pss(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            rsa_ffi::RSA_HASH_SHA256,
            rsa_ffi::RSA_HASH_SHA256,
            32,
            message.as_ptr(),
            message.len(),
            pss_signature.as_ptr(),
            pss_signature.len(),
        )
    };
    assert_eq!(pss_status, status::CRYPTO_OK);
    let bad_suite_status = unsafe {
        rsa_ffi::rm_crypto_rsa_verify_pkcs1v15(
            public_der.as_ptr(),
            public_der.len(),
            rsa_ffi::RSA_PUBLIC_KEY_ENCODING_PKCS1_DER,
            99,
            message.as_ptr(),
            message.len(),
            pkcs1_signature.as_ptr(),
            pkcs1_signature.len(),
        )
    };
    assert_eq!(bad_suite_status, status::CRYPTO_INVALID_ARGUMENT);
    Ok(())
}

const RSA_PUBLIC_KEY_DER: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const RSA_MESSAGE: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const RSA_PKCS1V15_SHA256_SIGNATURE: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const RSA_PSS_SHA256_SIGNATURE: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
