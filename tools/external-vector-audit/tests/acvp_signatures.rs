// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP signature audit adapters.

use crypto_ed25519::verify_ed25519;
use crypto_p256::verify_p256_der_prehash;
use crypto_p384::verify_p384_der_prehash;
use crypto_p521::verify_p521_der_prehash;
use crypto_rsa::{verify_rsa_pkcs1v15, RsaHash, RsaPublicKeyDerEncoding};
use external_vector_audit::refenc;
use external_vector_audit::support::{hex_bytes, load_json, AuditError};
use serde::Deserialize;

// DER/SEC1 byte construction is delegated to the intentionally independent
// `refenc` reference encoder (see its module docs); this adapter only owns the
// fixed coordinate widths it must validate before handing bytes to `refenc`.
const P256_COORDINATE_LEN: usize = 32;
const P384_COORDINATE_LEN: usize = 48;
const P521_COORDINATE_LEN: usize = 66;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaFile {
    test_groups: Vec<EddsaGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaGroup {
    curve: String,
    pre_hash: bool,
    tests: Vec<EddsaCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaCase {
    test_passed: bool,
    message: String,
    q: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaFile {
    test_groups: Vec<EcdsaGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaGroup {
    curve: String,
    hash_alg: String,
    conformance: Option<String>,
    tests: Vec<EcdsaCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaCase {
    test_passed: bool,
    message: String,
    qx: String,
    qy: String,
    r: String,
    s: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaFile {
    test_groups: Vec<RsaGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaGroup {
    sig_type: String,
    hash_alg: String,
    n: String,
    e: String,
    tests: Vec<RsaCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaCase {
    test_passed: bool,
    message: String,
    signature: String,
}

#[test]
fn acvp_eddsa_ed25519_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: EddsaFile = load_json("nist-acvp/signature/eddsa-sigver/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != "ED-25519" || group.pre_hash {
            continue;
        }
        for case in &group.tests {
            let public_key = hex_bytes(&case.q)?;
            let message = hex_bytes(&case.message)?;
            let signature = hex_bytes(&case.signature)?;
            let actual = verify_ed25519(&public_key, &message, &signature);
            assert_signature_result(case.test_passed, actual)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    require_executed(executed)
}

#[test]
fn acvp_ecdsa_p256_sha256_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: EcdsaFile = load_json("nist-acvp/signature/ecdsa-sigver/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != "P-256" || group.hash_alg != "SHA2-256" {
            continue;
        }
        for case in &group.tests {
            let public_key = p256_sec1_public_key(&case.qx, &case.qy)?;
            let signature_der = p256_der_signature(&case.r, &case.s)?;
            let message = hex_bytes(&case.message)?;
            let actual = verify_p256_der_prehash(&signature_der, &message, &public_key);
            assert_signature_result(case.test_passed, actual)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    require_executed(executed)
}

#[test]
fn acvp_ecdsa_p384_sha384_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: EcdsaFile =
        load_json("nist-acvp/signature/ecdsa-sigver-1.0/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != "P-384" || group.hash_alg != "SHA2-384" || group.conformance.is_some() {
            continue;
        }
        for case in &group.tests {
            let public_key = p384_sec1_public_key(&case.qx, &case.qy)?;
            let signature_der = ecdsa_der_signature(&case.r, &case.s)?;
            let message = hex_bytes(&case.message)?;
            let actual = verify_p384_der_prehash(&signature_der, &message, &public_key);
            assert_signature_result(case.test_passed, actual)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    require_executed(executed)
}

#[test]
fn acvp_ecdsa_p521_sha512_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: EcdsaFile =
        load_json("nist-acvp/signature/ecdsa-sigver-1.0/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != "P-521" || group.hash_alg != "SHA2-512" || group.conformance.is_some() {
            continue;
        }
        for case in &group.tests {
            let public_key = p521_sec1_public_key(&case.qx, &case.qy)?;
            let signature_der = ecdsa_der_signature(&case.r, &case.s)?;
            let message = hex_bytes(&case.message)?;
            let actual = verify_p521_der_prehash(&signature_der, &message, &public_key);
            assert_signature_result(case.test_passed, actual)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    require_executed(executed)
}

#[test]
fn acvp_rsa_pkcs1v15_sha256_sigver_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: RsaFile = load_json("nist-acvp/signature/rsa-sigver/internalProjection.json")?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.sig_type != "pkcs1v1.5" || group.hash_alg != "SHA2-256" {
            continue;
        }
        let public_key_der = rsa_pkcs1_public_key_der(&group.n, &group.e)?;
        for case in &group.tests {
            let message = hex_bytes(&case.message)?;
            let signature = hex_bytes(&case.signature)?;
            let actual = verify_rsa_pkcs1v15(
                &public_key_der,
                RsaPublicKeyDerEncoding::Pkcs1,
                RsaHash::Sha256,
                &message,
                &signature,
            );
            assert_signature_result(case.test_passed, actual)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    require_executed(executed)
}

fn p256_sec1_public_key(qx: &str, qy: &str) -> Result<Vec<u8>, AuditError> {
    sec1_public_key::<P256_COORDINATE_LEN>(qx, qy)
}

fn p256_der_signature(r: &str, s: &str) -> Result<Vec<u8>, AuditError> {
    fixed_hex::<P256_COORDINATE_LEN>(r)?;
    fixed_hex::<P256_COORDINATE_LEN>(s)?;
    ecdsa_der_signature(r, s)
}

fn p384_sec1_public_key(qx: &str, qy: &str) -> Result<Vec<u8>, AuditError> {
    sec1_public_key::<P384_COORDINATE_LEN>(qx, qy)
}

fn p521_sec1_public_key(qx: &str, qy: &str) -> Result<Vec<u8>, AuditError> {
    sec1_public_key::<P521_COORDINATE_LEN>(qx, qy)
}

fn sec1_public_key<const N: usize>(qx: &str, qy: &str) -> Result<Vec<u8>, AuditError> {
    let x = fixed_hex::<N>(qx)?;
    let y = fixed_hex::<N>(qy)?;
    refenc::sec1_uncompressed_point(&x, &y)
}

fn ecdsa_der_signature(r: &str, s: &str) -> Result<Vec<u8>, AuditError> {
    refenc::ecdsa_signature_der(&hex_bytes(r)?, &hex_bytes(s)?)
}

fn fixed_hex<const N: usize>(input: &str) -> Result<[u8; N], AuditError> {
    hex_bytes(input)?.try_into().map_err(|_| AuditError::Shape)
}

fn rsa_pkcs1_public_key_der(modulus: &str, exponent: &str) -> Result<Vec<u8>, AuditError> {
    refenc::rsa_pkcs1_public_key_der(&hex_bytes(modulus)?, &hex_bytes(exponent)?)
}

fn assert_signature_result(
    expected_pass: bool,
    actual: Result<(), crypto_core::CryptoError>,
) -> Result<(), AuditError> {
    if expected_pass {
        actual.map_err(|_| AuditError::Mismatch)
    } else if actual.is_err() {
        Ok(())
    } else {
        Err(AuditError::Mismatch)
    }
}

fn require_executed(executed: usize) -> Result<(), AuditError> {
    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}
