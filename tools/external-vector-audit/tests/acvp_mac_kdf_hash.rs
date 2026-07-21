// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP MAC, KDF, and hash audit adapters.

use crypto_core::MacAlgorithm;
use crypto_hmac::{authenticate, HmacKey};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;

const PRACTICAL_SUBSET_PER_FILE: usize = 48;
const BITS_PER_BYTE: u32 = 8;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacFile {
    test_groups: Vec<HmacGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacGroup {
    mac_len: u32,
    tests: Vec<HmacCase>,
}

#[derive(Deserialize)]
struct HmacCase {
    key: String,
    msg: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacSha3File {
    algorithm: String,
    revision: String,
    test_groups: Vec<HmacSha3Group>,
}

#[derive(Deserialize)]
struct HmacSha3Group {
    tests: Vec<HmacSha3Case>,
}

#[derive(Deserialize)]
struct HmacSha3Case {
    key: String,
    msg: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacFile {
    test_groups: Vec<KmacGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacGroup {
    hex_customization: bool,
    xof: bool,
    tests: Vec<KmacCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmacCase {
    key_len: u32,
    msg_len: u32,
    mac_len: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashFile {
    test_groups: Vec<HashGroup>,
}

#[derive(Deserialize)]
struct HashGroup {
    tests: Vec<HashCase>,
}

#[derive(Deserialize)]
struct HashCase {
    msg: Option<String>,
    len: Option<u32>,
    md: Option<String>,
    #[serde(rename = "outLen")]
    out_len: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfFile {
    test_groups: Vec<PbkdfGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbkdfGroup {
    hmac_alg: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ansix963File {
    test_groups: Vec<Ansix963Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ansix963Group {
    hash_alg: String,
    tests: Vec<Ansix963Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ansix963Case {
    shared_info: String,
    key_data: String,
}

#[test]
fn acvp_hmac_sha2_vectors_execute_against_public_api() -> Result<(), AuditError> {
    execute_hmac_file(
        "nist-acvp/mac/hmac-sha2-256/internalProjection.json",
        MacAlgorithm::HmacSha256,
    )?;
    execute_hmac_file(
        "nist-acvp/mac/hmac-sha2-384/internalProjection.json",
        MacAlgorithm::HmacSha384,
    )?;
    execute_hmac_file(
        "nist-acvp/mac/hmac-sha2-512/internalProjection.json",
        MacAlgorithm::HmacSha512,
    )
}

#[test]
fn acvp_hmac_sha3_file_is_vendored_but_not_public_mac_algorithm() -> Result<(), AuditError> {
    let file: HmacSha3File = load_json("nist-acvp/mac/hmac-sha3-256/internalProjection.json")?;
    if file.algorithm != "HMAC-SHA3-256" || file.revision != "2.0" {
        return Err(AuditError::Shape);
    }
    let has_vector_material = file
        .test_groups
        .iter()
        .flat_map(|group| &group.tests)
        .any(HmacSha3Case::has_vector_material);
    let public_mac_algorithms = [
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ];
    let exposes_hmac_sha3 = public_mac_algorithms
        .iter()
        .any(|algorithm| algorithm.as_str().starts_with("HMAC-SHA3"));
    if has_vector_material && !exposes_hmac_sha3 {
        Ok(())
    } else {
        Err(AuditError::NoExecutableVectors)
    }
}

#[test]
fn acvp_kmac256_file_has_no_current_public_boundary_vectors() -> Result<(), AuditError> {
    let file: KmacFile = load_json("nist-acvp/mac/kmac-256/internalProjection.json")?;
    let has_public_boundary_vectors = file.test_groups.iter().any(|group| {
        !group.xof
            && !group.hex_customization
            && group
                .tests
                .iter()
                .any(|case| bit_lengths_are_byte_aligned(case.key_len, case.msg_len, case.mac_len))
    });
    if has_public_boundary_vectors {
        Err(AuditError::Mismatch)
    } else {
        Ok(())
    }
}

#[test]
fn acvp_sha2_vectors_execute_against_public_api() -> Result<(), AuditError> {
    execute_hash_file(
        "nist-acvp/hash/sha2-256/internalProjection.json",
        HashKind::Sha2_256,
    )?;
    execute_hash_file(
        "nist-acvp/hash/sha2-384/internalProjection.json",
        HashKind::Sha2_384,
    )?;
    execute_hash_file(
        "nist-acvp/hash/sha2-512/internalProjection.json",
        HashKind::Sha2_512,
    )
}

#[test]
fn acvp_sha3_vectors_execute_against_public_api() -> Result<(), AuditError> {
    execute_hash_file(
        "nist-acvp/hash/sha3-224/internalProjection.json",
        HashKind::Sha3_224,
    )?;
    execute_hash_file(
        "nist-acvp/hash/sha3-256/internalProjection.json",
        HashKind::Sha3_256,
    )?;
    execute_hash_file(
        "nist-acvp/hash/sha3-384/internalProjection.json",
        HashKind::Sha3_384,
    )?;
    execute_hash_file(
        "nist-acvp/hash/sha3-512/internalProjection.json",
        HashKind::Sha3_512,
    )
}

#[test]
fn acvp_shake256_vectors_execute_against_public_api() -> Result<(), AuditError> {
    execute_hash_file(
        "nist-acvp/hash/shake-256/internalProjection.json",
        HashKind::Shake256,
    )
}

#[test]
fn acvp_pbkdf_file_has_no_current_public_prf_vectors() -> Result<(), AuditError> {
    let file: PbkdfFile = load_json("nist-acvp/kdf/pbkdf/internalProjection.json")?;
    let has_supported_prf = file
        .test_groups
        .iter()
        .any(|group| group.hmac_alg == "SHA2-256" || group.hmac_alg == "SHA2-512");
    if has_supported_prf {
        Err(AuditError::Mismatch)
    } else {
        Ok(())
    }
}

#[test]
fn acvp_ansix963_file_has_no_current_jwa_public_boundary_vectors() -> Result<(), AuditError> {
    let file: Ansix963File = load_json("nist-acvp/kdf/ansix963/internalProjection.json")?;
    let has_relevant_raw_vectors = file.test_groups.iter().any(|group| {
        group.hash_alg == "SHA2-256"
            && group
                .tests
                .iter()
                .any(|case| !case.key_data.is_empty() && case.shared_info.len().is_multiple_of(2))
    });
    if has_relevant_raw_vectors {
        Ok(())
    } else {
        Err(AuditError::NoExecutableVectors)
    }
}

impl HmacSha3Case {
    fn has_vector_material(&self) -> bool {
        !self.key.is_empty() && !self.msg.is_empty() && !self.mac.is_empty()
    }
}

fn execute_hmac_file(relative_path: &str, algorithm: MacAlgorithm) -> Result<(), AuditError> {
    let file: HmacFile = load_json(relative_path)?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if !group.mac_len.is_multiple_of(BITS_PER_BYTE) {
            continue;
        }
        for case in &group.tests {
            let key = HmacKey::from_slice(&hex_bytes(&case.key)?)
                .map_err(|_| AuditError::UnsupportedBoundary)?;
            let message = hex_bytes(&case.msg)?;
            let expected_prefix = hex_bytes(&case.mac)?;
            let prefix_len = bits_to_bytes(group.mac_len)?;
            if expected_prefix.len() != prefix_len {
                return Err(AuditError::Shape);
            }
            let actual =
                authenticate(algorithm, &key, &message).map_err(|_| AuditError::Mismatch)?;
            assert_bytes_eq(&actual.as_bytes()[..prefix_len], &expected_prefix)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
            if executed >= PRACTICAL_SUBSET_PER_FILE {
                return Ok(());
            }
        }
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

fn execute_hash_file(relative_path: &str, kind: HashKind) -> Result<(), AuditError> {
    let file: HashFile = load_json(relative_path)?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        for case in &group.tests {
            let Some(len) = case.len else {
                continue;
            };
            if !len.is_multiple_of(BITS_PER_BYTE) {
                continue;
            }
            if kind == HashKind::Shake256
                && !case
                    .out_len
                    .ok_or(AuditError::Shape)?
                    .is_multiple_of(BITS_PER_BYTE)
            {
                continue;
            }
            let message = hex_bytes(case.msg.as_ref().ok_or(AuditError::Shape)?)?;
            let expected = hex_bytes(case.md.as_ref().ok_or(AuditError::Shape)?)?;
            let actual = match kind {
                HashKind::Sha2_256 => crypto_sha2_256::digest(&message).as_bytes().to_vec(),
                HashKind::Sha2_384 => crypto_sha2::digest_sha2_384(&message).as_bytes().to_vec(),
                HashKind::Sha2_512 => crypto_sha2::digest_sha2_512(&message).as_bytes().to_vec(),
                HashKind::Sha3_224 => crypto_sha3::digest_sha3_224(&message).as_bytes().to_vec(),
                HashKind::Sha3_256 => crypto_sha3_256::digest(&message).as_bytes().to_vec(),
                HashKind::Sha3_384 => crypto_sha3::digest_sha3_384(&message).as_bytes().to_vec(),
                HashKind::Sha3_512 => crypto_sha3::digest_sha3_512(&message).as_bytes().to_vec(),
                HashKind::Shake256 => {
                    let output_len = bits_to_bytes(case.out_len.ok_or(AuditError::Shape)?)?;
                    if expected.len() != output_len {
                        return Err(AuditError::Shape);
                    }
                    let mut output = vec![0u8; output_len];
                    crypto_sha3::shake256_expand(&message, &mut output);
                    output
                }
            };
            assert_bytes_eq(&actual, &expected)?;
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
            if executed >= PRACTICAL_SUBSET_PER_FILE {
                return Ok(());
            }
        }
    }

    if executed == 0 {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(())
    }
}

fn bit_lengths_are_byte_aligned(key_len: u32, msg_len: u32, mac_len: u32) -> bool {
    key_len.is_multiple_of(BITS_PER_BYTE)
        && msg_len.is_multiple_of(BITS_PER_BYTE)
        && mac_len.is_multiple_of(BITS_PER_BYTE)
}

fn bits_to_bytes(bits: u32) -> Result<usize, AuditError> {
    if !bits.is_multiple_of(BITS_PER_BYTE) {
        return Err(AuditError::Shape);
    }
    usize::try_from(bits / BITS_PER_BYTE).map_err(|_| AuditError::Shape)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha2_256,
    Sha2_384,
    Sha2_512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake256,
}
