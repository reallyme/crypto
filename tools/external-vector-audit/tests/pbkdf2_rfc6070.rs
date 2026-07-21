// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! PBKDF2-HMAC-SHA-256/SHA-512 known-answer test adapter.
//!
//! The vendored NIST ACVP PBKDF sample covers only SHA-224, which the public
//! boundary does not expose. This adapter instead runs the RFC 6070-derived
//! PBKDF2-HMAC-SHA2 vectors from the brycx Test-Vector-Generation corpus against
//! `derive_key`, covering both public PRFs (SHA-256 and SHA-512) across several
//! iteration counts and output lengths. The 16 777 216-iteration case is skipped
//! (it would dominate runtime). Vendored via
//! `scripts/vendor_external_vectors.mjs`; ignored by default.

use crypto_pbkdf2::{
    derive_key, Pbkdf2Iterations, Pbkdf2Password, Pbkdf2Prf, Pbkdf2Request, Pbkdf2Salt,
};
use external_vector_audit::support::{assert_bytes_eq, hex_bytes, load_text, AuditError};

const SKIP_ITERATIONS: u32 = 16_777_216;

#[derive(Default)]
struct Case {
    password: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    iterations: Option<u32>,
    output_len: Option<usize>,
    sha256: Option<Vec<u8>>,
    sha512: Option<Vec<u8>>,
}

#[test]
#[ignore = "vendored PBKDF2 corpus; run via the external-vectors audit workflow after vendoring"]
fn pbkdf2_rfc6070_derived_vectors_match_public_api() -> Result<(), AuditError> {
    let corpus = load_text("pbkdf2/brycx_pbkdf2_hmac_sha2.md")?;
    let mut case = Case::default();
    let mut executed = 0usize;

    for line in corpus.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("P = ") {
            case.password = Some(quoted_bytes(value)?);
        } else if let Some(value) = line.strip_prefix("S = ") {
            case.salt = Some(quoted_bytes(value)?);
        } else if let Some(value) = line.strip_prefix("c = ") {
            case.iterations = Some(value.trim().parse().map_err(|_| AuditError::Shape)?);
        } else if let Some(value) = line.strip_prefix("dkLen = ") {
            case.output_len = Some(value.trim().parse().map_err(|_| AuditError::Shape)?);
        } else if let Some(value) = line.strip_prefix("PBKDF2-HMAC-SHA256 = ") {
            case.sha256 = Some(hex_bytes(hex_value(value))?);
        } else if let Some(value) = line.strip_prefix("PBKDF2-HMAC-SHA512 = ") {
            // SHA-512 is the last output line of a case; run and reset.
            case.sha512 = Some(hex_bytes(hex_value(value))?);
            executed = run_case(&case, executed)?;
            case = Case::default();
        }
    }

    if executed == 0 {
        return Err(AuditError::NoExecutableVectors);
    }
    Ok(())
}

fn run_case(case: &Case, executed: usize) -> Result<usize, AuditError> {
    let (password, salt, iterations, output_len, sha256, sha512) = match (
        &case.password,
        &case.salt,
        case.iterations,
        case.output_len,
        &case.sha256,
        &case.sha512,
    ) {
        (Some(p), Some(s), Some(c), Some(len), Some(a), Some(b)) => (p, s, c, len, a, b),
        _ => return Ok(executed),
    };
    if iterations == SKIP_ITERATIONS {
        return Ok(executed);
    }

    let mut count = executed;
    for (prf, expected) in [
        (Pbkdf2Prf::HmacSha256, sha256),
        (Pbkdf2Prf::HmacSha512, sha512),
    ] {
        let pbkdf2_password =
            Pbkdf2Password::from_slice(password, prf).map_err(|_| AuditError::Shape)?;
        let pbkdf2_salt = Pbkdf2Salt::from_slice(salt, prf).map_err(|_| AuditError::Shape)?;
        let iteration_count =
            Pbkdf2Iterations::from_u32(iterations, prf).map_err(|_| AuditError::Shape)?;
        let output = derive_key(&Pbkdf2Request {
            prf,
            password: &pbkdf2_password,
            salt: &pbkdf2_salt,
            iterations: iteration_count,
            output_len,
        })
        .map_err(|_| AuditError::Mismatch)?;
        assert_bytes_eq(output.as_bytes(), expected)?;
        count = count
            .checked_add(1)
            .ok_or(AuditError::NoExecutableVectors)?;
    }
    Ok(count)
}

/// Extracts the content between the first pair of double quotes, decoding the
/// `\0` escape used for embedded null bytes.
fn quoted_bytes(value: &str) -> Result<Vec<u8>, AuditError> {
    let start = value.find('"').ok_or(AuditError::Shape)?;
    let rest = &value[start.checked_add(1).ok_or(AuditError::Shape)?..];
    let end = rest.find('"').ok_or(AuditError::Shape)?;
    let inner = rest.get(..end).ok_or(AuditError::Shape)?;

    let mut bytes = Vec::new();
    let mut chars = inner.bytes().peekable();
    while let Some(byte) = chars.next() {
        if byte == b'\\' && chars.peek() == Some(&b'0') {
            chars.next();
            bytes.push(0);
        } else {
            bytes.push(byte);
        }
    }
    Ok(bytes)
}

/// Extracts the hex output value, which the corpus writes either as a bare
/// `<hex> (N octets)` token or as a quoted `"<hex>"` string.
fn hex_value(value: &str) -> &str {
    let trimmed = value.trim();
    let unquoted = trimmed.strip_prefix('"').unwrap_or(trimmed);
    let end = unquoted.find(['"', ' ']).unwrap_or(unquoted.len());
    unquoted.get(..end).unwrap_or("")
}
