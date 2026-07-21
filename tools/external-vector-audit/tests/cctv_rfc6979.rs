// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! CCTV RFC6979 P-256 rejection-sampling vector.

use crypto_p256::{p256_ecdsa_der_to_jose_signature, sign_p256_der_prehash};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_text, AuditError};

const PRIVATE_KEY_HEX: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const MESSAGE: &[u8] = b"wv[vnX";
const EXPECTED_R_HEX: &str = "EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234";
const EXPECTED_S_HEX: &str = "3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33";

#[test]
fn cctv_rfc6979_p256_rejection_vector_matches_public_signer() -> Result<(), AuditError> {
    let readme = load_text("cctv/rfc6979/README.md")?;
    if !readme.contains("RFC 6979 rejection sampling vector") {
        return Err(AuditError::Shape);
    }

    let private_key = hex_bytes(PRIVATE_KEY_HEX)?;
    let signature_der =
        sign_p256_der_prehash(&private_key, MESSAGE).map_err(|_| AuditError::Mismatch)?;
    let signature =
        p256_ecdsa_der_to_jose_signature(&signature_der).map_err(|_| AuditError::Mismatch)?;
    let mut expected_signature = hex_bytes(EXPECTED_R_HEX)?;
    expected_signature.extend_from_slice(&hex_bytes(EXPECTED_S_HEX)?);

    assert_bytes_eq(&signature, &expected_signature)
}
