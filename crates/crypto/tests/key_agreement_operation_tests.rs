// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "dispatch",
    feature = "x25519",
    feature = "p256",
    feature = "p384",
    feature = "p521"
))]
#![allow(clippy::panic)]

//! Key-agreement operation-owner tests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crypto_core::Algorithm;
use reallyme_crypto::operations::{
    key_agreement::{self, KeyAgreementKeyPair},
    OperationError, PrimitiveErrorReason, ProviderErrorReason,
};
use zeroize::Zeroizing;

const X25519_SECRET_KEY: &str = "E7QOQ0MpyDlZIqZtb7jFDTs1Jj-OXAbKxiSoZSfTswQ";
const X25519_PUBLIC_KEY: &str = "y77BzmdEAIfQO_2FNuo_f6kiz1KavGZXi2Lzv1qyYUE";
const X25519_PEER_PUBLIC_KEY: &str = "RESov4Ctflb8KNvIJtn0T8Sb2UXzuiYmE495HXpVGAs";
const X25519_SHARED_SECRET: &str = "4AxNYqi-7u3A19Csp45MlDlaBjU5qCBM6PwREg6NvBg";
const P256_SECRET_KEY: &str = "IU-LbKKdMxCVR2YScoOv7g0ZQVt8ItQ5UYqwZS-Rw0Q";
const P256_PUBLIC_KEY: &str = "Agf8y0NFCW-WIXJvxOQ3vgz4HEMQgfMo5VSWcjmsVSLu";
const P256_PEER_PUBLIC_KEY: &str = "Ali-yYlmw_dYNuAs1pru8ZlUqrQouhAoBlJ4W_zPnhEh";
const P256_SHARED_SECRET: &str = "iOVlde6amQQJ4-QGzYLITKXVKdLax4Hs46FesLh2_nE";
const P384_SECRET_KEY: &str = "XY9hKpTANncb4lCuR5wD0WJ6tO6IIQk18ETKfRmDtlIP2XArrFgT5nSRIs86vVUI";
const P384_PUBLIC_KEY: &str = "AyQp1rInwuJ6H3lh1jS8OWwLrBsZlrgiW1LT6Ms4zFbG8LkHlEsn0gExi5n81-3ozg";
const P384_PEER_PUBLIC_KEY: &str =
    "Aq2Oc53kYhoPAGTMXlEqgljI-we9Wn16em0ScbohwlRadoiRzdx52eHK-gigZgTsIw";
const P384_SHARED_SECRET: &str = "4rVcfZ5JccXZoOsgX74hgoj468NztGflBonS740PoiX1S14IgBDL0wpLMGYCwa6Y";
const P521_SECRET_KEY: &str =
    "ASt8PZRY4Q9zpsIZTYC17jVqCdxBl_JuGKvFAH0jWYTvEkiwbNcxmgX-YotE0XYguj-ZDlLIFKdtKPNFjAG5bzNa";
const P521_PUBLIC_KEY: &str =
    "AwCxcyb3lSGY_gJm7QMd71MeUizbIwnuNoPyEVxgiO_aK7gq4ixEk1-ayy6cAmaofdNhZlimM7IYk5MqYamILvr0tA";
const P521_PEER_PUBLIC_KEY: &str =
    "AwFw_IQR_xCn8Wa2ADWzgizRk3UFftri0NWWIeBuw8RbBbgCtxVdb-NZ1FB4jPAt-vs6QlFWf2S3u8WOmjTcr3NpxQ";
const P521_SHARED_SECRET: &str =
    "AeDog_SZcOJVTsiR-WUAjPnIjv_Rg3RsyNuKpPF9PqWKvF7uHCtgnwiaiR4HcvgAfXXrMc9fRICmZHe9WYW11oZx";

struct AgreementCase {
    algorithm: Algorithm,
    first_secret_key: Vec<u8>,
    second_secret_key: Vec<u8>,
    shared_secret_len: usize,
}

struct VectorCase {
    algorithm: Algorithm,
    secret_key: &'static str,
    public_key: &'static str,
    peer_public_key: &'static str,
    shared_secret: &'static str,
}

#[test]
fn repository_vectors_match_owner_and_public_facades_without_implicit_kdf() {
    for case in vector_cases() {
        let secret_key = decode_vector(case.secret_key);
        let public_key = decode_vector(case.public_key);
        let peer_public_key = decode_vector(case.peer_public_key);
        let expected_raw_secret = decode_vector(case.shared_secret);

        let key_pair = derive_key_pair_or_panic(case.algorithm, &secret_key);
        let owner_secret =
            derive_shared_secret_or_panic(case.algorithm, &secret_key, &peer_public_key);
        let facade_secret = derive_with_facade(case.algorithm, &secret_key, &peer_public_key);

        assert_eq!(key_pair.public_key, public_key);
        assert_eq!(&*owner_secret, &expected_raw_secret);
        assert_eq!(&*facade_secret, &expected_raw_secret);
    }
}

#[test]
fn key_agreement_owner_round_trips_raw_shared_secret_outputs() {
    for case in agreement_cases() {
        let first = derive_key_pair_or_panic(case.algorithm, &case.first_secret_key);
        let second = derive_key_pair_or_panic(case.algorithm, &case.second_secret_key);

        let first_shared =
            derive_shared_secret_or_panic(case.algorithm, &first.secret_key, &second.public_key);
        let second_shared =
            derive_shared_secret_or_panic(case.algorithm, &second.secret_key, &first.public_key);

        assert_zeroizing_vec(&first_shared);
        assert_zeroizing_vec(&second_shared);
        assert_eq!(first_shared.len(), case.shared_secret_len);
        assert_eq!(second_shared.len(), case.shared_secret_len);
        assert_eq!(&*first_shared, &*second_shared);
    }
}

#[test]
fn key_agreement_owner_generates_zeroizing_secret_keys() {
    for algorithm in [
        Algorithm::X25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
    ] {
        let key_pair = generate_key_pair_or_panic(algorithm);
        assert!(!key_pair.public_key.is_empty());
        assert_zeroizing_vec(&key_pair.secret_key);
    }
}

#[test]
fn key_agreement_owner_rejects_unsupported_algorithm() {
    let error = match key_agreement::generate_key_pair(Algorithm::Ed25519) {
        Ok(_) => panic!("signature algorithm must not be a key-agreement route"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        OperationError::Provider {
            reason: ProviderErrorReason::UnsupportedAlgorithm
        }
    );
}

#[test]
fn key_agreement_owner_rejects_invalid_secret_key_material() {
    for algorithm in [
        Algorithm::X25519,
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::P521,
    ] {
        assert_invalid_key(key_agreement::derive_key_pair(algorithm, &[1, 2]));
        assert_invalid_shared_secret_input(key_agreement::derive_shared_secret(
            algorithm,
            &[1, 2],
            &[3, 4],
        ));
    }
}

#[test]
fn key_agreement_owner_rejects_invalid_public_key_material() {
    for case in vector_cases() {
        assert_invalid_shared_secret_input(key_agreement::derive_shared_secret(
            case.algorithm,
            &decode_vector(case.secret_key),
            &[3, 4],
        ));
    }
}

#[test]
fn x25519_all_zero_peer_output_fails_as_invalid_shared_secret() {
    let secret_key = [9u8; 32];
    let public_key = [0u8; 32];

    let error =
        match key_agreement::derive_shared_secret(Algorithm::X25519, &secret_key, &public_key) {
            Ok(_) => panic!("non-contributory X25519 output must fail closed"),
            Err(error) => error,
        };

    assert_eq!(
        error,
        OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidSharedSecret
        }
    );
}

fn agreement_cases() -> [AgreementCase; 4] {
    [
        AgreementCase {
            algorithm: Algorithm::X25519,
            first_secret_key: vec![9u8; 32],
            second_secret_key: vec![11u8; 32],
            shared_secret_len: 32,
        },
        AgreementCase {
            algorithm: Algorithm::P256,
            first_secret_key: vec![5u8; 32],
            second_secret_key: vec![7u8; 32],
            shared_secret_len: 32,
        },
        AgreementCase {
            algorithm: Algorithm::P384,
            first_secret_key: vec![3u8; 48],
            second_secret_key: vec![5u8; 48],
            shared_secret_len: 48,
        },
        AgreementCase {
            algorithm: Algorithm::P521,
            first_secret_key: p521_secret_key(3),
            second_secret_key: p521_secret_key(5),
            shared_secret_len: 66,
        },
    ]
}

fn vector_cases() -> [VectorCase; 4] {
    [
        VectorCase {
            algorithm: Algorithm::X25519,
            secret_key: X25519_SECRET_KEY,
            public_key: X25519_PUBLIC_KEY,
            peer_public_key: X25519_PEER_PUBLIC_KEY,
            shared_secret: X25519_SHARED_SECRET,
        },
        VectorCase {
            algorithm: Algorithm::P256,
            secret_key: P256_SECRET_KEY,
            public_key: P256_PUBLIC_KEY,
            peer_public_key: P256_PEER_PUBLIC_KEY,
            shared_secret: P256_SHARED_SECRET,
        },
        VectorCase {
            algorithm: Algorithm::P384,
            secret_key: P384_SECRET_KEY,
            public_key: P384_PUBLIC_KEY,
            peer_public_key: P384_PEER_PUBLIC_KEY,
            shared_secret: P384_SHARED_SECRET,
        },
        VectorCase {
            algorithm: Algorithm::P521,
            secret_key: P521_SECRET_KEY,
            public_key: P521_PUBLIC_KEY,
            peer_public_key: P521_PEER_PUBLIC_KEY,
            shared_secret: P521_SHARED_SECRET,
        },
    ]
}

fn p521_secret_key(last_byte: u8) -> Vec<u8> {
    let mut secret_key = vec![0u8; 66];
    secret_key[65] = last_byte;
    secret_key
}

fn assert_zeroizing_vec(_: &Zeroizing<Vec<u8>>) {}

fn assert_invalid_key(result: Result<KeyAgreementKeyPair, OperationError>) {
    assert_eq!(
        result.err(),
        Some(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey
        })
    );
}

fn assert_invalid_shared_secret_input(result: Result<Zeroizing<Vec<u8>>, OperationError>) {
    assert_eq!(
        result.err(),
        Some(OperationError::Primitive {
            reason: PrimitiveErrorReason::InvalidKey
        })
    );
}

fn decode_vector(value: &str) -> Vec<u8> {
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(bytes) => bytes,
        Err(_) => panic!("repository vector must be valid base64url"),
    }
}

fn derive_with_facade(
    algorithm: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Zeroizing<Vec<u8>> {
    let result = match algorithm {
        Algorithm::X25519 => {
            reallyme_crypto::x25519::derive_x25519_shared_secret(secret_key, public_key)
        }
        Algorithm::P256 => reallyme_crypto::p256::derive_p256_shared_secret(secret_key, public_key),
        Algorithm::P384 => reallyme_crypto::p384::derive_p384_shared_secret(secret_key, public_key),
        Algorithm::P521 => reallyme_crypto::p521::derive_p521_shared_secret(secret_key, public_key),
        _ => panic!("vector table contains only key-agreement algorithms"),
    };
    match result {
        Ok(shared_secret) => shared_secret,
        Err(_) => panic!("repository vector must pass through the public facade"),
    }
}

fn generate_key_pair_or_panic(algorithm: Algorithm) -> KeyAgreementKeyPair {
    match key_agreement::generate_key_pair(algorithm) {
        Ok(key_pair) => key_pair,
        Err(_) => panic!("key generation succeeds"),
    }
}

fn derive_key_pair_or_panic(algorithm: Algorithm, secret_key: &[u8]) -> KeyAgreementKeyPair {
    match key_agreement::derive_key_pair(algorithm, secret_key) {
        Ok(key_pair) => key_pair,
        Err(_) => panic!("valid test key"),
    }
}

fn derive_shared_secret_or_panic(
    algorithm: Algorithm,
    secret_key: &[u8],
    public_key: &[u8],
) -> Zeroizing<Vec<u8>> {
    match key_agreement::derive_shared_secret(algorithm, secret_key, public_key) {
        Ok(shared_secret) => shared_secret,
        Err(_) => panic!("valid shared secret"),
    }
}
