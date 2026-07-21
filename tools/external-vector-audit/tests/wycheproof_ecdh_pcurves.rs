// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof P-256/P-384/P-521 ECDH audit adapters.
//!
//! Uses the Wycheproof `ecpoint` variant, whose `public` field is a raw SEC1
//! point (the form the public `derive_p*_shared_secret` functions accept). A
//! `valid` case must derive the recorded shared secret; an `invalid` case (off
//! -curve point, identity, wrong length) must be rejected; `acceptable` cases
//! are skipped. Vendored via `scripts/vendor_external_vectors.mjs`; ignored by
//! default.
//!
//! Two deliberate representation/policy differences are encoded here so they
//! read as positive checks rather than spurious mismatches:
//!
//! - Wycheproof encodes the private key as a variable-length big-endian integer
//!   (a leading `0x00` when the high bit is set, stripped leading zeros for
//!   small values); the public API takes a fixed-width scalar, so the adapter
//!   normalizes it — the same encoding-adaptation role it plays for DER.
//! - ReallyMe rejects an all-zero (degenerate) shared secret by policy, so a
//!   Wycheproof `valid` case whose shared secret is all-zero is expected to be
//!   rejected here.

use crypto_core::CryptoError;
use crypto_p256::derive_p256_shared_secret;
use crypto_p384::derive_p384_shared_secret;
use crypto_p521::derive_p521_shared_secret;
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use external_vector_audit::wycheproof::{WycheproofFile, WycheproofResult};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhGroup {
    curve: String,
    tests: Vec<EcdhCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhCase {
    public: String,
    private: String,
    shared: String,
    result: WycheproofResult,
}

type DeriveFn = fn(&[u8], &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;

const P256_SCALAR_LEN: usize = 32;
const P384_SCALAR_LEN: usize = 48;
const P521_SCALAR_LEN: usize = 66;

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_ecdh_p256_vectors_execute_against_public_api() -> Result<(), AuditError> {
    run_ecdh(
        "wycheproof/ecdh_secp256r1_ecpoint_test.json",
        "secp256r1",
        P256_SCALAR_LEN,
        derive_p256_shared_secret,
    )
}

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_ecdh_p384_vectors_execute_against_public_api() -> Result<(), AuditError> {
    run_ecdh(
        "wycheproof/ecdh_secp384r1_ecpoint_test.json",
        "secp384r1",
        P384_SCALAR_LEN,
        derive_p384_shared_secret,
    )
}

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_ecdh_p521_vectors_execute_against_public_api() -> Result<(), AuditError> {
    run_ecdh(
        "wycheproof/ecdh_secp521r1_ecpoint_test.json",
        "secp521r1",
        P521_SCALAR_LEN,
        derive_p521_shared_secret,
    )
}

fn run_ecdh(
    path: &str,
    curve: &str,
    scalar_len: usize,
    derive: DeriveFn,
) -> Result<(), AuditError> {
    let file: WycheproofFile<EcdhGroup> = load_json(path)?;
    let mut executed = 0usize;

    for group in &file.test_groups {
        if group.curve != curve {
            continue;
        }
        for case in &group.tests {
            if case.result == WycheproofResult::Acceptable {
                continue;
            }
            let public_key = hex_bytes(&case.public)?;
            // Normalize the variable-width Wycheproof scalar to fixed width, then
            // derive. A scalar that cannot be normalized counts as rejected.
            let derived = normalize_scalar(&hex_bytes(&case.private)?, scalar_len)
                .and_then(|private_key| derive(&private_key, &public_key).ok());
            match case.result {
                WycheproofResult::Valid => {
                    let expected = hex_bytes(&case.shared)?;
                    if expected.iter().all(|byte| *byte == 0) {
                        // All-zero shared secret: ReallyMe rejects by policy.
                        if derived.is_some() {
                            return Err(AuditError::Mismatch);
                        }
                    } else {
                        let shared = derived.ok_or(AuditError::Mismatch)?;
                        assert_bytes_eq(shared.as_slice(), &expected)?;
                    }
                }
                WycheproofResult::Invalid => {
                    if derived.is_some() {
                        return Err(AuditError::Mismatch);
                    }
                }
                WycheproofResult::Acceptable => {}
            }
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

/// Normalizes a big-endian scalar to `len` bytes: left-pads a short value with
/// zeros and strips leading zero bytes from a longer one. Returns `None` if a
/// non-zero byte would have to be dropped (a genuinely out-of-range scalar).
fn normalize_scalar(scalar: &[u8], len: usize) -> Option<Vec<u8>> {
    match scalar.len().cmp(&len) {
        std::cmp::Ordering::Equal => Some(scalar.to_vec()),
        std::cmp::Ordering::Less => {
            let mut padded = vec![0u8; len];
            padded[len - scalar.len()..].copy_from_slice(scalar);
            Some(padded)
        }
        std::cmp::Ordering::Greater => {
            let extra = scalar.len() - len;
            if scalar[..extra].iter().all(|byte| *byte == 0) {
                Some(scalar[extra..].to_vec())
            } else {
                None
            }
        }
    }
}
