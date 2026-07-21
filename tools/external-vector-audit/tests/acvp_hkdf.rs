// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ACVP KDA-HKDF audit adapter for the public raw HKDF primitive.

use crypto_hkdf::{derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use serde::Deserialize;
use serde_json::Value;

const HKDF_ACVP_OUTPUT_BYTES: usize = 128;
const HKDF_ACVP_OUTPUT_BITS: u32 = 1024;
const PRACTICAL_SUBSET_PER_SUITE: usize = 16;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfFile {
    test_groups: Vec<HkdfGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfGroup {
    kdf_configuration: Option<HkdfConfiguration>,
    uses_hybrid_shared_secret: Option<bool>,
    multi_expansion: Option<bool>,
    tests: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfConfiguration {
    kdf_type: String,
    l: u32,
    fixed_info_pattern: String,
    fixed_info_encoding: String,
    hmac_alg: HkdfHash,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfCase {
    test_passed: Option<bool>,
    kdf_parameter: HkdfParameter,
    fixed_info_party_u: HkdfPartyInfo,
    fixed_info_party_v: HkdfPartyInfo,
    dkm: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfParameter {
    salt: String,
    z: String,
    t: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfPartyInfo {
    party_id: String,
    ephemeral_data: Option<String>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum HkdfHash {
    #[serde(rename = "SHA2-256")]
    Sha2_256,
    #[serde(rename = "SHA2-384")]
    Sha2_384,
    #[serde(other)]
    Unsupported,
}

#[test]
fn acvp_hkdf_kda_vectors_execute_against_public_raw_hkdf_api() -> Result<(), AuditError> {
    let file: HkdfFile = load_json("nist-acvp/kdf/hkdf-sp800-56cr2/internalProjection.json")?;
    let mut counts = HkdfCounts::default();

    for group in &file.test_groups {
        if !group.matches_public_boundary() {
            continue;
        }
        let configuration = group.kdf_configuration.as_ref().ok_or(AuditError::Shape)?;
        for case in &group.tests {
            let case =
                serde_json::from_value::<HkdfCase>(case.clone()).map_err(|_| AuditError::Json)?;
            if !case.matches_public_boundary() {
                continue;
            }
            execute_hkdf_case(configuration.hmac_alg, &case)?;
            counts.increment(configuration.hmac_alg)?;
            if counts.complete() {
                return Ok(());
            }
        }
    }

    counts.require_all()
}

fn execute_hkdf_case(hash: HkdfHash, case: &HkdfCase) -> Result<(), AuditError> {
    let mut ikm = hex_bytes(&case.kdf_parameter.z)?;
    ikm.extend_from_slice(&hex_bytes(&case.kdf_parameter.t)?);
    let ikm = HkdfInputKeyMaterial::from_slice(&ikm);
    let salt_bytes = hex_bytes(&case.kdf_parameter.salt)?;
    let salt = HkdfSalt::from_slice(&salt_bytes);
    let fixed_info = fixed_info(case)?;
    let info = HkdfInfo::from_slice(&fixed_info);
    let expected = hex_bytes(&case.dkm)?;
    let suite = match hash {
        HkdfHash::Sha2_256 => HkdfSuite::Sha2_256,
        HkdfHash::Sha2_384 => HkdfSuite::Sha2_384,
        HkdfHash::Unsupported => return Err(AuditError::UnsupportedBoundary),
    };
    let actual = derive::<HKDF_ACVP_OUTPUT_BYTES>(&DeriveRequest {
        suite,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .map_err(|_| AuditError::Mismatch)?;
    assert_bytes_eq(actual.as_bytes(), &expected)
}

fn fixed_info(case: &HkdfCase) -> Result<Vec<u8>, AuditError> {
    let party_u_id = hex_bytes(&case.fixed_info_party_u.party_id)?;
    let party_u_ephemeral = optional_hex(case.fixed_info_party_u.ephemeral_data.as_ref())?;
    let party_v_id = hex_bytes(&case.fixed_info_party_v.party_id)?;
    let party_v_ephemeral = optional_hex(case.fixed_info_party_v.ephemeral_data.as_ref())?;
    let capacity = party_u_id
        .len()
        .checked_add(party_u_ephemeral.len())
        .and_then(|value| value.checked_add(party_v_id.len()))
        .and_then(|value| value.checked_add(party_v_ephemeral.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or(AuditError::Shape)?;
    let mut fixed_info = Vec::with_capacity(capacity);
    fixed_info.extend_from_slice(&party_u_id);
    fixed_info.extend_from_slice(&party_u_ephemeral);
    fixed_info.extend_from_slice(&party_v_id);
    fixed_info.extend_from_slice(&party_v_ephemeral);
    fixed_info.extend_from_slice(&HKDF_ACVP_OUTPUT_BITS.to_be_bytes());
    Ok(fixed_info)
}

fn optional_hex(input: Option<&String>) -> Result<Vec<u8>, AuditError> {
    match input {
        Some(value) => hex_bytes(value),
        None => Ok(Vec::new()),
    }
}

impl HkdfGroup {
    fn matches_public_boundary(&self) -> bool {
        self.kdf_configuration
            .as_ref()
            .is_some_and(|configuration| {
                configuration.kdf_type == "hkdf"
                    && configuration.l == HKDF_ACVP_OUTPUT_BITS
                    && configuration.fixed_info_pattern == "uPartyInfo||vPartyInfo||l"
                    && configuration.fixed_info_encoding == "concatenation"
                    && matches!(
                        configuration.hmac_alg,
                        HkdfHash::Sha2_256 | HkdfHash::Sha2_384
                    )
            })
            && self.uses_hybrid_shared_secret == Some(true)
            && self.multi_expansion == Some(false)
    }
}

impl HkdfCase {
    fn matches_public_boundary(&self) -> bool {
        self.test_passed.unwrap_or(true)
    }
}

#[derive(Default)]
struct HkdfCounts {
    sha2_256: usize,
    sha2_384: usize,
}

impl HkdfCounts {
    fn increment(&mut self, hash: HkdfHash) -> Result<(), AuditError> {
        let count = match hash {
            HkdfHash::Sha2_256 => &mut self.sha2_256,
            HkdfHash::Sha2_384 => &mut self.sha2_384,
            HkdfHash::Unsupported => return Err(AuditError::UnsupportedBoundary),
        };
        *count = count
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
        Ok(())
    }

    fn complete(&self) -> bool {
        self.sha2_256 >= PRACTICAL_SUBSET_PER_SUITE && self.sha2_384 >= PRACTICAL_SUBSET_PER_SUITE
    }

    fn require_all(&self) -> Result<(), AuditError> {
        if self.sha2_256 > 0 && self.sha2_384 > 0 {
            Ok(())
        } else {
            Err(AuditError::NoExecutableVectors)
        }
    }
}
