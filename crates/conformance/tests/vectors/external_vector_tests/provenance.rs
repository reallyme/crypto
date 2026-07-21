// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeSet, fs, path::Path};

use serde_json::Value;

use crate::support::{
    external_vectors_dir, field_array, field_string, object_field, read_external_bytes,
    VectorTestError,
};

const PROVENANCE_PATH: &str = "provenance.json";
const EXTERNAL_README_PATH: &str = "README.md";
const NIST_COMMIT: &str = "15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0";
const CCTV_COMMIT: &str = "1e3d2860d46e94e777e1b17c7a6f2436387e3ecc";

pub(crate) fn provenance() -> Result<Value, VectorTestError> {
    crate::support::load_external(PROVENANCE_PATH)
}

pub(crate) fn file_entries(value: &Value) -> Result<&Vec<Value>, VectorTestError> {
    field_array(value, "files")
}

#[test]
fn external_vector_provenance_declares_sources() -> Result<(), VectorTestError> {
    let value = provenance()?;
    assert_eq!(field_string(&value, "retrieved_at")?, "2026-07-19");

    let sources = field_array(&value, "sources")?;
    let nist = source_by_id(sources, "nist-acvp")?;
    let cctv = source_by_id(sources, "cctv")?;

    assert_eq!(field_string(nist, "commit")?, NIST_COMMIT);
    assert_eq!(field_string(cctv, "commit")?, CCTV_COMMIT);
    assert!(field_string(nist, "website_url")?.starts_with("https://pages.nist.gov/ACVP/"));
    assert!(field_string(cctv, "website_url")?.starts_with("https://c2sp.org/CCTV"));

    let nist_license = object_field(nist, "license")?;
    let cctv_license = object_field(cctv, "license")?;
    assert_eq!(
        field_string(nist_license, "declared")?,
        "not declared in upstream repository metadata"
    );
    assert_eq!(
        field_string(cctv_license, "declared")?,
        "mixed per vendored CCTV directory"
    );

    Ok(())
}

#[test]
fn external_vector_coverage_tracks_supported_families() -> Result<(), VectorTestError> {
    let value = provenance()?;
    let coverage = field_array(&value, "coverage")?;

    for algorithm in [
        "AES-GCM",
        "AES-GCM-SIV",
        "AES-KW",
        "HMAC-SHA2",
        "KMAC-256",
        "PBKDF2",
        "HKDF",
        "Concat KDF",
        "SHA-2",
        "SHA-3",
        "ECDSA P-256/P-384/P-521",
        "Ed25519",
        "RSA signatures",
        "X25519",
        "ML-KEM",
        "ML-KEM adversarial internals",
        "ML-DSA",
        "SLH-DSA",
    ] {
        let entry = coverage_by_algorithm(coverage, algorithm)?;
        assert_ne!(field_string(entry, "status")?, "no_upstream_source_found");
    }

    // Argon2id has no vendored upstream suite for its public boundary.
    //
    // ChaCha20-Poly1305 and secp256k1/BIP-340 are intentionally NOT asserted
    // here: they migrate from `no_upstream_source_found` to a vendored source
    // when `scripts/vendor_external_vectors.mjs` imports their Wycheproof /
    // BIP-340 corpora, so this test stays agnostic to their current status.
    let argon2id = coverage_by_algorithm(coverage, "Argon2id")?;
    assert_eq!(
        field_string(argon2id, "status")?,
        "no_upstream_source_found"
    );

    Ok(())
}

#[test]
fn external_vector_urls_are_pinned_to_commits() -> Result<(), VectorTestError> {
    let value = provenance()?;
    let sources = field_array(&value, "sources")?;

    // Source-driven: every vendored file's upstream URL must embed the pinned
    // commit declared by its own source entry. This holds for the original
    // nist-acvp / cctv sources and for any source added by the vendoring script
    // (Wycheproof, BIP-340, RFC 8032, ...) without hard-coding source ids here.
    for entry in file_entries(&value)? {
        let source_id = field_string(entry, "source_id")?;
        let upstream_url = field_string(entry, "upstream_url")?;
        let source = source_by_id(sources, source_id)?;
        let commit = field_string(source, "commit")?;
        assert!(
            upstream_url.contains(commit),
            "{source_id} upstream url is not pinned to its source commit"
        );
    }

    Ok(())
}

#[test]
fn every_external_corpus_file_has_provenance() -> Result<(), VectorTestError> {
    let value = provenance()?;
    let mut declared_paths = BTreeSet::new();
    for entry in file_entries(&value)? {
        let local_path = field_string(entry, "local_path")?;
        assert!(
            declared_paths.insert(local_path.to_owned()),
            "duplicate provenance entry: {local_path}"
        );
    }

    let root = external_vectors_dir()?;
    let mut corpus_paths = BTreeSet::new();
    collect_corpus_paths(&root, &root, &mut corpus_paths)?;
    corpus_paths.remove(PROVENANCE_PATH);
    corpus_paths.remove(EXTERNAL_README_PATH);

    assert_eq!(
        corpus_paths, declared_paths,
        "every external corpus file must have exactly one provenance entry"
    );
    Ok(())
}

#[test]
#[ignore = "full external-corpus integrity sweep; run deliberately when auditing vendored vectors"]
fn external_vector_files_match_pinned_sha256() -> Result<(), VectorTestError> {
    let value = provenance()?;

    for entry in file_entries(&value)? {
        let local_path = field_string(entry, "local_path")?;
        let expected_sha256 = field_string(entry, "sha256")?;
        let bytes = read_external_bytes(local_path)?;
        let actual_sha256 = sha256_hex(&bytes);
        assert_eq!(actual_sha256, expected_sha256, "{local_path}");
    }

    Ok(())
}

fn source_by_id<'a>(sources: &'a [Value], source_id: &str) -> Result<&'a Value, VectorTestError> {
    sources
        .iter()
        .find(|source| {
            source
                .get("source_id")
                .and_then(Value::as_str)
                .is_some_and(|candidate| candidate == source_id)
        })
        .ok_or(VectorTestError::InvalidField)
}

fn coverage_by_algorithm<'a>(
    coverage: &'a [Value],
    algorithm: &str,
) -> Result<&'a Value, VectorTestError> {
    coverage
        .iter()
        .find(|entry| {
            entry
                .get("reallyme_algorithm")
                .and_then(Value::as_str)
                .is_some_and(|candidate| candidate == algorithm)
        })
        .ok_or(VectorTestError::InvalidField)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = crypto_sha2_256::digest(bytes).into_bytes();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn collect_corpus_paths(
    root: &Path,
    directory: &Path,
    paths: &mut BTreeSet<String>,
) -> Result<(), VectorTestError> {
    for entry in fs::read_dir(directory).map_err(|_| VectorTestError::ReadVector)? {
        let entry = entry.map_err(|_| VectorTestError::ReadVector)?;
        let path = entry.path();
        if path.is_dir() {
            collect_corpus_paths(root, &path, paths)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| VectorTestError::InvalidField)?;
            let relative = relative
                .to_str()
                .ok_or(VectorTestError::InvalidField)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            paths.insert(relative);
        }
    }
    Ok(())
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'a' + (nibble - 10)),
    }
}
