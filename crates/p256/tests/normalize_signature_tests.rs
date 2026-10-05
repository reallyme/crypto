// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-S normalization tests for canonical P-256 DER signatures.

use crypto_core::CryptoError;
use crypto_p256::{
    normalize_p256_ecdsa_der_low_s, normalize_p256_ecdsa_jose_signature_low_s,
    p256_ecdsa_jose_signature_to_der,
};
use hex_literal::hex;

#[cfg(feature = "native")]
use crypto_p256::{
    generate_p256_keypair_from_secret_key, p256_ecdsa_der_to_jose_signature, sign_p256_digest_der,
    verify_p256_digest_der,
};
#[cfg(feature = "native")]
use sha2::{Digest, Sha256};

const LOW_S: [u8; 32] = hex!("5c8c885bb6f785dcb92a7c63f248fa34cadb5c6ab952e66b6a8b7f0475fbd08b");
const HIGH_S: [u8; 32] = hex!("a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6");
const R: [u8; 32] = hex!("6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7");

fn raw_signature(s: [u8; 32]) -> [u8; 64] {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&R);
    raw[32..].copy_from_slice(&s);
    raw
}

#[test]
fn normalizes_high_s_and_is_idempotent() -> Result<(), CryptoError> {
    let high_raw = raw_signature(HIGH_S);
    let low_raw = raw_signature(LOW_S);
    let high_der = p256_ecdsa_jose_signature_to_der(&high_raw)?;
    let expected = p256_ecdsa_jose_signature_to_der(&low_raw)?;

    let normalized = normalize_p256_ecdsa_der_low_s(&high_der)?;
    assert_eq!(normalized, expected);
    assert_eq!(normalize_p256_ecdsa_der_low_s(&normalized)?, normalized);
    assert_eq!(
        normalize_p256_ecdsa_jose_signature_low_s(&high_raw)?,
        low_raw
    );
    assert_eq!(
        normalize_p256_ecdsa_jose_signature_low_s(&low_raw)?,
        low_raw
    );
    Ok(())
}

#[test]
fn preserves_low_s_and_half_order_boundary() -> Result<(), CryptoError> {
    let low_der = p256_ecdsa_jose_signature_to_der(&raw_signature(LOW_S))?;
    assert_eq!(normalize_p256_ecdsa_der_low_s(&low_der)?, low_der);

    let half_order = hex!("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
    let boundary_der = p256_ecdsa_jose_signature_to_der(&raw_signature(half_order))?;
    assert_eq!(normalize_p256_ecdsa_der_low_s(&boundary_der)?, boundary_der);
    Ok(())
}

#[test]
fn rejects_malformed_noncanonical_and_out_of_range_inputs() {
    let malformed = hex!("30060201010201");
    let redundant_padding = hex!("300702020001020101");
    let zero_s = hex!("3006020101020100");
    let order_s =
        hex!("3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    for signature in [
        malformed.as_slice(),
        redundant_padding.as_slice(),
        zero_s.as_slice(),
        order_s.as_slice(),
    ] {
        assert!(normalize_p256_ecdsa_der_low_s(signature).is_err());
    }

    let one = {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        scalar
    };
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    assert!(normalize_p256_ecdsa_jose_signature_low_s(&[0u8; 63]).is_err());
    assert!(normalize_p256_ecdsa_jose_signature_low_s(&raw_signature([0u8; 32])).is_err());
    let mut order_signature = [0u8; 64];
    order_signature[..32].copy_from_slice(&one);
    order_signature[32..].copy_from_slice(&order);
    assert!(normalize_p256_ecdsa_jose_signature_low_s(&order_signature).is_err());
}

#[cfg(feature = "native")]
#[test]
fn normalized_twin_preserves_signature_validity() -> Result<(), CryptoError> {
    let secret = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let message = b"reallyme p256 low-s normalization";
    let (public_key, _) = generate_p256_keypair_from_secret_key(&secret)?;
    let digest = Sha256::digest(message);
    let low_der = sign_p256_digest_der(&secret, digest.as_ref())?;
    let mut high_raw = p256_ecdsa_der_to_jose_signature(&low_der)?;
    let low_s = <&[u8; 32]>::try_from(&high_raw[32..]).map_err(|_| {
        crypto_core::CryptoError::Signature {
            backend: crypto_core::SignatureBackend::Native,
            operation: crypto_core::SignatureOperation::Verify,
            kind: crypto_core::SignatureFailureKind::InvalidSignature,
        }
    })?;
    let order = hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let mut high_s = [0u8; 32];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let left = u16::from(order[index]);
        let right = u16::from(low_s[index]) + borrow;
        if left >= right {
            high_s[index] =
                u8::try_from(left - right).map_err(|_| crypto_core::CryptoError::Signature {
                    backend: crypto_core::SignatureBackend::Native,
                    operation: crypto_core::SignatureOperation::Verify,
                    kind: crypto_core::SignatureFailureKind::InvalidSignature,
                })?;
            borrow = 0;
        } else {
            high_s[index] = u8::try_from(256u16 + left - right).map_err(|_| {
                crypto_core::CryptoError::Signature {
                    backend: crypto_core::SignatureBackend::Native,
                    operation: crypto_core::SignatureOperation::Verify,
                    kind: crypto_core::SignatureFailureKind::InvalidSignature,
                }
            })?;
            borrow = 1;
        }
    }
    high_raw[32..].copy_from_slice(&high_s);
    let high_der = p256_ecdsa_jose_signature_to_der(&high_raw)?;

    let normalized = normalize_p256_ecdsa_der_low_s(&high_der)?;

    // The strict digest verifier rejects the high-S representation and accepts
    // its normalized twin. The general message verifier remains interoperable.
    assert!(verify_p256_digest_der(&high_der, &digest, &public_key).is_err());
    verify_p256_digest_der(&normalized, &digest, &public_key)?;
    assert_eq!(normalized, low_der);
    Ok(())
}
