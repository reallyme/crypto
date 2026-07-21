// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! File loading and byte-decoding helpers for external vector audit adapters.

use flate2::read::GzDecoder;
use serde::de::DeserializeOwned;
use std::io::Read;
use std::path::PathBuf;

/// Fixed, secret-free errors emitted by the audit adapters.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// External vector file could not be read.
    #[error("external vector file could not be read")]
    Io,
    /// External vector JSON could not be decoded into the expected schema.
    #[error("external vector JSON could not be decoded")]
    Json,
    /// External vector hex could not be decoded.
    #[error("external vector hex could not be decoded")]
    Hex,
    /// External vector fields do not match this adapter's expected shape.
    #[error("external vector shape is not supported by this adapter")]
    Shape,
    /// External vector requires an input form outside the public primitive API.
    #[error("external vector uses an unsupported public primitive boundary")]
    UnsupportedBoundary,
    /// No vectors in the file matched this adapter's executable subset.
    #[error("no executable external vectors matched this adapter")]
    NoExecutableVectors,
    /// ReallyMe primitive output did not match the external vector.
    #[error("external vector output mismatch")]
    Mismatch,
}

/// Loads a JSON file from `vectors/external` into a typed adapter schema.
pub fn load_json<T: DeserializeOwned>(relative_path: &str) -> Result<T, AuditError> {
    let bytes = std::fs::read(external_path(relative_path)).map_err(|_| AuditError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| AuditError::Json)
}

/// Loads a UTF-8 text file from `vectors/external`.
pub fn load_text(relative_path: &str) -> Result<String, AuditError> {
    std::fs::read_to_string(external_path(relative_path)).map_err(|_| AuditError::Io)
}

/// Loads a gzip-compressed UTF-8 text file from `vectors/external`.
///
/// Decompression is performed in-process with `flate2` so the audit does not
/// depend on an external `gzip` binary being present on `PATH`; this keeps the
/// result hermetic and reproducible across CI images and platforms.
pub fn load_gzip_text(relative_path: &str) -> Result<String, AuditError> {
    let compressed = std::fs::read(external_path(relative_path)).map_err(|_| AuditError::Io)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut decoded = String::new();
    decoder
        .read_to_string(&mut decoded)
        .map_err(|_| AuditError::Shape)?;
    Ok(decoded)
}

/// Decodes an upstream hex field into bytes.
pub fn hex_bytes(input: &str) -> Result<Vec<u8>, AuditError> {
    hex::decode(input).map_err(|_| AuditError::Hex)
}

/// Decodes an upstream hex field into a fixed-size byte array.
pub fn hex_array<const N: usize>(input: &str) -> Result<[u8; N], AuditError> {
    let bytes = hex_bytes(input)?;
    bytes.try_into().map_err(|_| AuditError::Shape)
}

/// Compares primitive output with an external vector without logging bytes.
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8]) -> Result<(), AuditError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuditError::Mismatch)
    }
}

fn external_path(relative_path: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .join("vectors/external")
        .join(relative_path)
}
