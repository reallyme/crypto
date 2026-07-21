// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof X448 shared-secret (XDH) audit adapter.
//!
//! X448 previously had no external vector route in the harness. This executes
//! the Wycheproof `curve448` XDH suite against the public API. Cases flagged
//! `ZeroSharedSecret` must be rejected under ReallyMe's non-contributory-secret
//! policy even when Wycheproof classifies them as `acceptable`. Valid cases
//! must match the recorded secret and invalid cases must be rejected. Other
//! `acceptable` cases have no ReallyMe policy direction and are skipped.
//! Vendored via `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_x448::{derive_x448_shared_secret, X448PrivateKey, X448PublicKey};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_json, AuditError};
use external_vector_audit::wycheproof::{WycheproofFile, WycheproofResult};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XdhGroup {
    curve: String,
    tests: Vec<XdhCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct XdhCase {
    public: String,
    private: String,
    shared: String,
    result: WycheproofResult,
    flags: Vec<XdhFlag>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum XdhFlag {
    EdgeCaseMultiplication,
    EdgeCasePrivateKey,
    EdgeCaseShared,
    Ktv,
    LowOrderPublic,
    NonCanonicalPublic,
    Normal,
    PublicKeyTooLong,
    SmallPublicKey,
    SpecialPublicKey,
    Twist,
    ZeroSharedSecret,
}

impl XdhCase {
    fn must_reject_zero_shared_secret(&self) -> bool {
        self.flags
            .iter()
            .any(|flag| matches!(flag, XdhFlag::ZeroSharedSecret))
    }
}

#[test]
#[ignore = "vendored Wycheproof corpus; run via the external-vectors audit workflow after vendoring"]
fn wycheproof_x448_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: WycheproofFile<XdhGroup> = load_json("wycheproof/x448_test.json")?;
    let mut executed = 0usize;
    let mut policy_rejections = 0usize;

    for group in &file.test_groups {
        if group.curve != "curve448" {
            continue;
        }
        for case in &group.tests {
            let must_reject = case.must_reject_zero_shared_secret();
            if case.result == WycheproofResult::Acceptable && !must_reject {
                continue;
            }
            let private_bytes = hex_bytes(&case.private)?;
            let public_bytes = hex_bytes(&case.public)?;
            let derived = derive_x448(&private_bytes, &public_bytes);
            match (case.result, must_reject) {
                (_, true) => {
                    if derived.is_some() {
                        return Err(AuditError::Mismatch);
                    }
                    policy_rejections = policy_rejections
                        .checked_add(1)
                        .ok_or(AuditError::NoExecutableVectors)?;
                }
                (WycheproofResult::Valid, false) => {
                    let shared = derived.ok_or(AuditError::Mismatch)?;
                    assert_bytes_eq(&shared, &hex_bytes(&case.shared)?)?;
                }
                (WycheproofResult::Invalid, false) => {
                    if derived.is_some() {
                        return Err(AuditError::Mismatch);
                    }
                }
                (WycheproofResult::Acceptable, false) => {}
            }
            executed = executed
                .checked_add(1)
                .ok_or(AuditError::NoExecutableVectors)?;
        }
    }

    if executed == 0 || policy_rejections == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

/// Derives the X448 shared secret, returning `None` on any rejection (bad key
/// length, low-order point, or non-contributory output).
fn derive_x448(private_bytes: &[u8], public_bytes: &[u8]) -> Option<Vec<u8>> {
    let private_key = X448PrivateKey::from_bytes(private_bytes).ok()?;
    let public_key = X448PublicKey::from_bytes(public_bytes).ok()?;
    let shared = derive_x448_shared_secret(&private_key, public_key).ok()?;
    Some(shared.as_bytes().to_vec())
}
