// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn verify_aes_kw_vector(
    file_name: &str,
    alg: &str,
    kek_len: usize,
    key_data_len: usize,
) -> Result<(), VectorTestError> {
    let v = load(file_name)?;
    let kek_bytes = b64u_to_bytes(field_string(&v, "kek")?)?;
    let key_data = b64u_to_bytes(field_string(&v, "key_data")?)?;
    let wrapped_key = b64u_to_bytes(field_string(&v, "wrapped_key")?)?;

    assert_eq!(field_string(&v, "alg")?, alg);
    assert_eq!(kek_bytes.len(), kek_len);
    assert_eq!(key_data.len(), key_data_len);
    assert_eq!(wrapped_key.len(), key_data_len + 8);

    let wrapped = match alg {
        "AES-128-KW" => {
            let kek = Aes128KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            wrap_key_aes128(&kek, &key_data).map_err(|_| VectorTestError::AesKw)?
        }
        "AES-192-KW" => {
            let kek = Aes192KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            wrap_key_aes192(&kek, &key_data).map_err(|_| VectorTestError::AesKw)?
        }
        "AES-256-KW" => {
            let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            wrap_key_aes256(&kek, &key_data).map_err(|_| VectorTestError::AesKw)?
        }
        _ => return Err(VectorTestError::AesKw),
    };
    assert_eq!(wrapped.as_bytes(), wrapped_key);
    let unwrapped = match alg {
        "AES-128-KW" => {
            let kek = Aes128KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes128(&kek, &wrapped_key).map_err(|_| VectorTestError::AesKw)?
        }
        "AES-192-KW" => {
            let kek = Aes192KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes192(&kek, &wrapped_key).map_err(|_| VectorTestError::AesKw)?
        }
        "AES-256-KW" => {
            let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes256(&kek, &wrapped_key).map_err(|_| VectorTestError::AesKw)?
        }
        _ => return Err(VectorTestError::AesKw),
    };
    assert_eq!(unwrapped.as_bytes(), key_data);

    let mut tampered = wrapped_key;
    tampered[0] ^= 0x01;
    let tamper_accepted = match alg {
        "AES-128-KW" => {
            let kek = Aes128KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes128(&kek, &tampered).is_ok()
        }
        "AES-192-KW" => {
            let kek = Aes192KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes192(&kek, &tampered).is_ok()
        }
        "AES-256-KW" => {
            let kek = Aes256KwKek::from_slice(&kek_bytes).map_err(|_| VectorTestError::AesKw)?;
            unwrap_key_aes256(&kek, &tampered).is_ok()
        }
        _ => return Err(VectorTestError::AesKw),
    };
    if tamper_accepted {
        return Err(VectorTestError::AesKwTamperAccepted);
    }

    Ok(())
}

#[test]
fn aes_kw_vectors_wrap_unwrap_and_reject_tampering() -> Result<(), VectorTestError> {
    verify_aes_kw_vector("aes128kw.json", "AES-128-KW", 16, 16)?;
    verify_aes_kw_vector("aes192kw.json", "AES-192-KW", 24, 16)?;
    verify_aes_kw_vector("aes256kw.json", "AES-256-KW", 32, 32)
}
