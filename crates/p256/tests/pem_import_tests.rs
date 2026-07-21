// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![cfg(feature = "native")]

use codec_pem::{encode_pem, PemEncodeOptions, PemLabel};
use crypto_p256::{
    compressed_public_key_from_private_key, generate_p256_keypair_from_secret_key,
    private_key_from_pem, private_key_from_pkcs8_der, private_key_from_pkcs8_pem,
    private_key_from_sec1_der, private_key_from_sec1_pem, public_key_from_spki_der,
    public_key_from_spki_pem,
};
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;

const SEC1_PRIVATE_KEY_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIOgPgBUgYyf6m41b5IRklKSREgDo3I44nxKH/E++HkiYoAoGCCqGSM49\n\
AwEHoUQDQgAEUJG3pn7PaQ+/lGOs0+lv90XlK4cAZ63VYQGkC8pyM9o2X+4OgR3p\n\
mOIRWJJrKvGAQrFT5T1NhwZrafAHMBBblw==\n\
-----END EC PRIVATE KEY-----\n";

const SPKI_PUBLIC_KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUJG3pn7PaQ+/lGOs0+lv90XlK4cA\n\
Z63VYQGkC8pyM9o2X+4OgR3pmOIRWJJrKvGAQrFT5T1NhwZrafAHMBBblw==\n\
-----END PUBLIC KEY-----\n";

#[test]
fn imports_sec1_private_key_and_spki_public_key() {
    let secret = private_key_from_sec1_pem(SEC1_PRIVATE_KEY_PEM).unwrap();
    let secret_via_auto = private_key_from_pem(SEC1_PRIVATE_KEY_PEM).unwrap();
    let public_from_secret = compressed_public_key_from_private_key(&secret).unwrap();
    let public_from_spki = public_key_from_spki_pem(SPKI_PUBLIC_KEY_PEM).unwrap();

    assert_eq!(*secret, *secret_via_auto);
    assert_eq!(public_from_secret, public_from_spki);
}

#[test]
fn imports_pkcs8_private_key_pem() {
    let mut scalar = [0u8; 32];
    scalar[31] = 7;
    let secret = SecretKey::from_slice(&scalar).unwrap();
    let der = secret.to_pkcs8_der().unwrap();
    let pem = encode_pem(
        PemLabel::PrivateKey,
        der.as_bytes(),
        PemEncodeOptions::default(),
    )
    .unwrap();

    let imported = private_key_from_pkcs8_pem(pem.as_str()).unwrap();
    let imported_via_auto = private_key_from_pem(pem.as_str()).unwrap();
    let (public_from_raw, _) = generate_p256_keypair_from_secret_key(&scalar).unwrap();
    let public_from_imported = compressed_public_key_from_private_key(&imported).unwrap();

    assert_eq!(*imported, scalar);
    assert_eq!(*imported, *imported_via_auto);
    assert_eq!(public_from_imported.as_slice(), public_from_raw.as_slice());
}

#[test]
fn rejects_wrong_pem_labels() {
    assert!(private_key_from_pkcs8_pem(SEC1_PRIVATE_KEY_PEM).is_err());
    assert!(private_key_from_sec1_pem(SPKI_PUBLIC_KEY_PEM).is_err());
    assert!(public_key_from_spki_pem(SEC1_PRIVATE_KEY_PEM).is_err());
}

#[test]
fn direct_der_imports_reject_empty_and_oversized_documents() {
    const MAX_KEY_DER_LEN: usize = 4096;
    let oversized = vec![0u8; MAX_KEY_DER_LEN + 1];

    for der in [&[][..], oversized.as_slice()] {
        assert!(private_key_from_pkcs8_der(der).is_err());
        assert!(private_key_from_sec1_der(der).is_err());
        assert!(public_key_from_spki_der(der).is_err());
    }
}
