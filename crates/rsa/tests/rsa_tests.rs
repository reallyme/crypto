// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RSA verification tests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto_core::CryptoError;
use crypto_rsa::{
    verify_rsa_pkcs1v15, verify_rsa_pss, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding,
};

const PUBLIC_KEY_DER: &str = "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB";
const MESSAGE: &str = "UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg";
const PKCS1V15_SHA1: &str = "hA_Xs2jYATVjBo9PtGmi-tr0fVJH57-QmUHvtZp2daMI_xk5XdMu4XYHRhCuP5LpHpjxJr2HvrM1ovdXq8bxfBDQkyR8fQgJcxs9lzCX4e9G5gu-cx1wo-YEoco6OGO6FZRoGHJgiUJ1gp6AbihXQYmzwkP4lJPeZTgTqfCzW9OURB6f-VWbxnWN9ALmIAboMmsMTBcJ4kEVQqK0EH5uRrGqF5R2QONNntmwYLByM3mIwyFGhm5RksGN4Xpz1b140xQLHIg6NdJS9x3okC2PEGyQ0l-1o1ct7yrqsnGcRoDkVLzpXQj_CjBAMQ7Vmmnb0yC11VuzlYBel3RFZM_dpA";
const PKCS1V15_SHA256: &str = "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw";
const PKCS1V15_SHA384: &str = "UPPRJw8CyERJsI7PW5_9WbhZmmIe2wie3bt1FuZz_8ShFfgaFXwQfwn_YS4QtkPEAn6q438r05M25U-IYQXaDiisXSocMxRE06nqMvvrCgO6p6O-2_xWW8V8xhDox1aPqWdp54Ba6A0s3dywUe5zQpOAL-xQ8KLIZpIE118xKwhouFMGZBvCNJDDMMVTxIyp-EpThhiE5EFxL5vp9hVx4euaEfgQhw5MXnJmxKW4Pt9sSdMlvoP8aFrW5st9rLfvknJz4EwgIVevM5XYaWsrjZfJOKY5CmCVmvW-evOMjumMRRU9t2OOOf5NHszKzK3qtUvzCbXUz8F1FNFJeZ_GaA";
const PKCS1V15_SHA512: &str = "MQ0UP3caVxnjq72kvCzRSvEbk2msNM0l76lv84OPjuA7Xu0EAb6H4WjoDnwqCy1aJe0wZQVVXEQyT8ch3AmDsY7_zCYlayZ8147Jno7n7qda8D0d8Q9SWZRK3Ir4HW6Ex5psmZaAhqSMAnku6On8oWIuofGKOOgMVn7AYDeehlh3f5NscqAtrEebrZ47B-d6XDHuyAe4zxsJPbBj0ef1vvRAA6wXnPIJ7Kvmajb8P4N8dCcjwjA7P9VbyZz_fY2HNpyAGAEFkjOO8uo05u30cHn6TLSYTCsKH2PCqkgH_-UEgjgp8IdBl5PzIHYac8wffRQ39G8LMZR07cll8HaPGA";
const PSS_SHA1: &str = "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvEmi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABlkE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRKS-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4epH8U6dPriTdtFa2g_Tw";
const PSS_SHA256: &str = "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw";
const PSS_SHA384: &str = "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyoNUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQpmekoLB7ZHP6enlefBQ";
const PSS_SHA512: &str = "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3BaGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2KoOKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVcLzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGxIf44p7HJX75J-WxE0Q";

#[test]
fn pkcs1v15_known_answer_signatures_verify() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let message = decode(MESSAGE)?;
    for (hash, signature) in pkcs1v15_cases()? {
        verify_rsa_pkcs1v15(
            &public_der,
            RsaPublicKeyDerEncoding::Pkcs1,
            hash,
            &message,
            &signature,
        )?;
    }
    Ok(())
}

#[test]
fn pss_known_answer_signatures_verify() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let message = decode(MESSAGE)?;
    for (hash, salt_len, signature) in pss_cases()? {
        verify_rsa_pss(
            &public_der,
            RsaPublicKeyDerEncoding::Pkcs1,
            RsaPssParams {
                message_hash: hash,
                mgf1_hash: hash,
                salt_len,
            },
            &message,
            &signature,
        )?;
    }
    Ok(())
}

#[test]
fn spki_public_key_encoding_verifies_same_signatures() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let spki_der = build_spki_der(&public_der)?;
    let message = decode(MESSAGE)?;
    let pkcs1v15_signature = decode(PKCS1V15_SHA256)?;
    let pss_signature = decode(PSS_SHA256)?;

    verify_rsa_pkcs1v15(
        &spki_der,
        RsaPublicKeyDerEncoding::Spki,
        RsaHash::Sha256,
        &message,
        &pkcs1v15_signature,
    )?;
    verify_rsa_pss(
        &spki_der,
        RsaPublicKeyDerEncoding::Spki,
        RsaPssParams {
            message_hash: RsaHash::Sha256,
            mgf1_hash: RsaHash::Sha256,
            salt_len: 32,
        },
        &message,
        &pss_signature,
    )?;

    Ok(())
}

#[test]
fn pkcs1v15_rejects_tampered_message_and_signature() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let message = decode(MESSAGE)?;
    let mut signature = decode(PKCS1V15_SHA384)?;

    assert!(verify_rsa_pkcs1v15(
        &public_der,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha384,
        b"tampered",
        &signature,
    )
    .is_err());

    let first = signature.first_mut().ok_or(CryptoError::InvalidKey)?;
    *first ^= 0x01;
    assert!(verify_rsa_pkcs1v15(
        &public_der,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha384,
        &message,
        &signature,
    )
    .is_err());

    Ok(())
}

#[test]
fn pss_rejects_wrong_salt_length_and_tampering() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let message = decode(MESSAGE)?;
    let mut signature = decode(PSS_SHA256)?;
    let params = RsaPssParams {
        message_hash: RsaHash::Sha256,
        mgf1_hash: RsaHash::Sha256,
        salt_len: 31,
    };

    assert!(verify_rsa_pss(
        &public_der,
        RsaPublicKeyDerEncoding::Pkcs1,
        params,
        &message,
        &signature,
    )
    .is_err());

    let last = signature.last_mut().ok_or(CryptoError::InvalidKey)?;
    *last ^= 0x01;
    let correct_params = RsaPssParams {
        salt_len: 32,
        ..params
    };
    assert!(verify_rsa_pss(
        &public_der,
        RsaPublicKeyDerEncoding::Pkcs1,
        correct_params,
        &message,
        &signature,
    )
    .is_err());

    Ok(())
}

#[test]
fn invalid_key_and_signature_lengths_are_rejected() -> Result<(), CryptoError> {
    let public_der = decode(PUBLIC_KEY_DER)?;
    let message = decode(MESSAGE)?;
    let signature = decode(PKCS1V15_SHA256)?;

    assert!(verify_rsa_pkcs1v15(
        public_der.get(..8).ok_or(CryptoError::InvalidKey)?,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha256,
        &message,
        &signature,
    )
    .is_err());

    assert!(verify_rsa_pkcs1v15(
        &public_der,
        RsaPublicKeyDerEncoding::Pkcs1,
        RsaHash::Sha256,
        &message,
        signature
            .get(..signature.len().saturating_sub(1))
            .ok_or(CryptoError::InvalidKey)?,
    )
    .is_err());

    Ok(())
}

fn pkcs1v15_cases() -> Result<[(RsaHash, Vec<u8>); 4], CryptoError> {
    Ok([
        (RsaHash::Sha1, decode(PKCS1V15_SHA1)?),
        (RsaHash::Sha256, decode(PKCS1V15_SHA256)?),
        (RsaHash::Sha384, decode(PKCS1V15_SHA384)?),
        (RsaHash::Sha512, decode(PKCS1V15_SHA512)?),
    ])
}

fn pss_cases() -> Result<[(RsaHash, usize, Vec<u8>); 4], CryptoError> {
    Ok([
        (RsaHash::Sha256, 32, decode(PSS_SHA256)?),
        (RsaHash::Sha1, 20, decode(PSS_SHA1)?),
        (RsaHash::Sha384, 48, decode(PSS_SHA384)?),
        (RsaHash::Sha512, 64, decode(PSS_SHA512)?),
    ])
}

fn decode(value: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidKey)
}

fn build_spki_der(pkcs1_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    const RSA_ENCRYPTION_ALGORITHM_IDENTIFIER: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    let bit_string_content_len = pkcs1_der
        .len()
        .checked_add(1)
        .ok_or(CryptoError::InvalidKey)?;
    let bit_string_len_len = der_length_len(bit_string_content_len)?;
    let bit_string_total_len = 1usize
        .checked_add(bit_string_len_len)
        .and_then(|value| value.checked_add(bit_string_content_len))
        .ok_or(CryptoError::InvalidKey)?;
    let sequence_content_len = RSA_ENCRYPTION_ALGORITHM_IDENTIFIER
        .len()
        .checked_add(bit_string_total_len)
        .ok_or(CryptoError::InvalidKey)?;

    let mut der = Vec::new();
    der.push(0x30);
    append_der_length(&mut der, sequence_content_len)?;
    der.extend_from_slice(RSA_ENCRYPTION_ALGORITHM_IDENTIFIER);
    der.push(0x03);
    append_der_length(&mut der, bit_string_content_len)?;
    der.push(0x00);
    der.extend_from_slice(pkcs1_der);
    Ok(der)
}

fn append_der_length(out: &mut Vec<u8>, len: usize) -> Result<(), CryptoError> {
    if len < 0x80 {
        out.push(u8::try_from(len).map_err(|_| CryptoError::InvalidKey)?);
        return Ok(());
    }

    let mut started = false;
    let mut bytes = Vec::new();
    for shift in [24u32, 16, 8, 0] {
        let value = (len >> shift) & 0xff;
        if value != 0 || started {
            started = true;
            bytes.push(u8::try_from(value).map_err(|_| CryptoError::InvalidKey)?);
        }
    }
    let len_of_len = u8::try_from(bytes.len()).map_err(|_| CryptoError::InvalidKey)?;
    out.push(0x80 | len_of_len);
    out.extend_from_slice(&bytes);
    Ok(())
}

fn der_length_len(len: usize) -> Result<usize, CryptoError> {
    if len < 0x80 {
        return Ok(1);
    }

    let mut count = 0usize;
    let mut started = false;
    for shift in [24u32, 16, 8, 0] {
        let value = (len >> shift) & 0xff;
        if value != 0 || started {
            started = true;
            count = count.checked_add(1).ok_or(CryptoError::InvalidKey)?;
        }
    }
    count.checked_add(1).ok_or(CryptoError::InvalidKey)
}
