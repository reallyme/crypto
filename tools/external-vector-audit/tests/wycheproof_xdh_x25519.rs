// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wycheproof X25519 shared-secret (XDH) audit adapter.
//!
//! Complements the NIST ACVP X25519 KATs with Wycheproof's adversarial edge
//! cases. The public API rejects non-contributory shared secrets, so cases
//! flagged `ZeroSharedSecret` must be rejected even when Wycheproof classifies
//! them as `acceptable`. Valid cases must match the expected secret. Other
//! `acceptable` cases have no ReallyMe policy direction and are skipped.
//! Vendored via `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_x25519::derive_x25519_shared_secret;
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
fn wycheproof_x25519_vectors_execute_against_public_api() -> Result<(), AuditError> {
    let file: WycheproofFile<XdhGroup> = load_json("wycheproof/x25519_test.json")?;
    let mut executed = 0usize;
    let mut policy_rejections = 0usize;

    for group in &file.test_groups {
        if group.curve != "curve25519" {
            continue;
        }
        for case in &group.tests {
            let must_reject = case.must_reject_zero_shared_secret();
            if case.result == WycheproofResult::Acceptable && !must_reject {
                continue;
            }
            let private_key = hex_bytes(&case.private)?;
            let public_key = hex_bytes(&case.public)?;
            let derived = derive_x25519_shared_secret(&private_key, &public_key);
            match (case.result, must_reject) {
                (_, true) => {
                    if derived.is_ok() {
                        return Err(AuditError::Mismatch);
                    }
                    policy_rejections = policy_rejections
                        .checked_add(1)
                        .ok_or(AuditError::NoExecutableVectors)?;
                }
                (WycheproofResult::Valid, false) => {
                    let shared = derived.map_err(|_| AuditError::Mismatch)?;
                    assert_bytes_eq(shared.as_slice(), &hex_bytes(&case.shared)?)?;
                }
                (WycheproofResult::Invalid, false) => {
                    if derived.is_ok() {
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
