// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{RsaSigningKey, MAX_PRIVATE_KEY_DER_BYTES};
use crypto_core::CryptoError;

const KEY: &[u8] = include_bytes!("testdata/rsa2048.pk8");

#[test]
fn rs256_signs_exact_message_and_exports_public_components() -> Result<(), CryptoError> {
    let key = RsaSigningKey::from_pkcs8_der(KEY)?;
    let public = key.public_key()?;
    assert_eq!(public.modulus.len(), 256);
    assert_eq!(public.exponent, [1, 0, 1]);
    let signature = key.sign_rs256(b"RS256 conformance vector")?;
    crate::verify_rsa_pkcs1v15(
        &public.spki_der,
        crate::RsaPublicKeyDerEncoding::Spki,
        crate::RsaHash::Sha256,
        b"RS256 conformance vector",
        &signature,
    )?;
    assert!(crate::verify_rsa_pkcs1v15(
        &public.spki_der,
        crate::RsaPublicKeyDerEncoding::Spki,
        crate::RsaHash::Sha256,
        b"altered",
        &signature
    )
    .is_err());
    // Blinding changes the internal operation, never the wire signature.
    assert_eq!(signature, key.sign_rs256(b"RS256 conformance vector")?);
    Ok(())
}

#[test]
fn import_rejects_weak_truncated_trailing_and_oversized_keys() {
    for invalid in [
        b"".as_slice(),
        &[0x30, 0],
        include_bytes!("testdata/rsa1024.pk8").as_slice(),
        &KEY[..KEY.len() - 1],
    ] {
        assert!(matches!(
            RsaSigningKey::from_pkcs8_der(invalid),
            Err(CryptoError::PRIMITIVE_INVALID_KEY)
        ));
    }
    let mut trailing = KEY.to_vec();
    trailing.push(0);
    assert!(RsaSigningKey::from_pkcs8_der(&trailing).is_err());
    assert!(RsaSigningKey::from_pkcs8_der(&vec![0; MAX_PRIVATE_KEY_DER_BYTES + 1]).is_err());
}

#[derive(Debug, thiserror::Error)]
#[error("test entropy unavailable")]
struct TestEntropyError;

struct FailedEntropy;
impl getrandom::rand_core::TryRng for FailedEntropy {
    type Error = TestEntropyError;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(TestEntropyError)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(TestEntropyError)
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
        Err(TestEntropyError)
    }
}
impl getrandom::rand_core::TryCryptoRng for FailedEntropy {}

#[test]
fn entropy_failure_never_falls_back_to_unblinded_signing() -> Result<(), CryptoError> {
    let key = RsaSigningKey::from_pkcs8_der(KEY)?;
    assert_eq!(
        key.sign_with_rng(b"message", &mut FailedEntropy),
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    );
    Ok(())
}

#[test]
fn corrupted_crt_components_are_not_silently_repaired() {
    let mut damaged = zeroize::Zeroizing::new(KEY.to_vec());
    if let Some(last) = damaged.last_mut() {
        *last ^= 1;
    }
    assert!(matches!(
        RsaSigningKey::from_pkcs8_der(&damaged),
        Err(CryptoError::PRIMITIVE_INVALID_KEY)
    ));
}

#[cfg(feature = "proto")]
#[test]
fn protected_signing_contract_matches_native_owner() -> Result<(), CryptoError> {
    use crypto_proto::generated::proto::reallyme::crypto::v1::{
        CryptoRsaPkcs1v15Sha256SignRequest, CryptoRsaSigningKeyImportRequest,
    };
    let request = CryptoRsaSigningKeyImportRequest {
        secret_key: KEY.to_vec().into(),
    };
    let key = RsaSigningKey::try_from(&request)?;
    let public = key.public_key()?;
    let wire_public = key.public_key_proto()?;
    assert_eq!(
        wire_public.public_key_spki_der.as_ref(),
        public.spki_der.as_slice()
    );
    let request = CryptoRsaPkcs1v15Sha256SignRequest {
        secret_key: KEY.to_vec().into(),
        message: b"message".to_vec().into(),
    };
    let operation = crate::proto_operations::RsaPkcs1v15Sha256SignInputs::try_from(&request)?;
    assert_eq!(
        operation.sign()?.signature.as_ref(),
        key.sign_rs256(b"message")?.as_slice()
    );
    let invalid = CryptoRsaSigningKeyImportRequest {
        secret_key: vec![0].into(),
    };
    assert!(matches!(
        RsaSigningKey::try_from(&invalid),
        Err(CryptoError::PRIMITIVE_INVALID_KEY)
    ));
    Ok(())
}
