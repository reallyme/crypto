// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

#[cfg(all(feature = "aes", feature = "hkdf", feature = "hmac", feature = "p384"))]
#[test]
fn requested_v030_facades_are_executable_and_fail_closed() {
    use reallyme_crypto::aes256_gcm::{
        aes256_gcm_decrypt, aes256_gcm_encrypt, Aes256GcmKey, Aes256GcmNonce,
    };
    use reallyme_crypto::hkdf::{
        expand_sha384, extract_sha384, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt,
    };
    use reallyme_crypto::hmac::{authenticate, verify as verify_hmac, HmacKey};
    use reallyme_crypto::p384::{generate_p384_keypair, sign, verify};
    use reallyme_crypto::MacAlgorithm;

    let hmac_key = HmacKey::from_slice(&[0x0b; 20]).unwrap();
    let hmac_tag = authenticate(MacAlgorithm::HmacSha384, &hmac_key, b"Hi There").unwrap();
    assert_eq!(hmac_tag.as_bytes().len(), 48);
    verify_hmac(
        MacAlgorithm::HmacSha384,
        &hmac_key,
        b"Hi There",
        hmac_tag.as_bytes(),
    )
    .unwrap();

    let ikm = HkdfInputKeyMaterial::from_slice(b"input keying material");
    let salt = HkdfSalt::from_slice(b"salt");
    let info = HkdfInfo::from_slice(b"MLS 1.0 test context");
    let prk = extract_sha384(Some(&salt), &ikm).unwrap();
    let output = expand_sha384::<32>(&prk, &info).unwrap();
    assert_ne!(output.as_bytes(), &[0u8; 32]);

    let aead_key = Aes256GcmKey::from_slice(&[0x41; 32]).unwrap();
    let nonce = Aes256GcmNonce::from_slice(&[0x24; 12]).unwrap();
    let ciphertext = aes256_gcm_encrypt(&aead_key, nonce, b"context", b"secret payload").unwrap();
    let plaintext = aes256_gcm_decrypt(&aead_key, nonce, b"context", &ciphertext).unwrap();
    assert_eq!(plaintext, b"secret payload");

    let (public_key, secret_key) = generate_p384_keypair().unwrap();
    let signature = sign(&secret_key, b"MLS signed content").unwrap();
    verify(&public_key, b"MLS signed content", &signature).unwrap();
    assert!(verify(&public_key, b"tampered content", &signature).is_err());
}
