// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::support::{read_external_bytes, VectorTestError};

#[test]
fn representative_cctv_vectors_are_present() -> Result<(), VectorTestError> {
    assert_text_contains(
        "cctv/ml-kem/README.md",
        &[b"ML-KEM test vectors", b"CC0 1.0", b"Unlucky"],
    )?;
    assert_text_contains(
        "cctv/ml-kem/intermediate/ML-KEM-512.txt",
        &[b"d = ", b"KBar = "],
    )?;
    assert_text_contains(
        "cctv/ml-kem/strcmp/ML-KEM-512.txt",
        &[b"dk = ", b"c = ", b"K = "],
    )?;
    assert_text_contains(
        "cctv/ml-kem/unluckysample/ML-KEM-512.txt",
        &[b"d = ", b"z = ", b"ek = ", b"dk = "],
    )?;
    assert_text_contains(
        "cctv/ed25519/ed25519vectors.json",
        &[b"low_order_A", b"non_canonical_R"],
    )?;
    assert_text_contains(
        "cctv/ml-dsa/accumulated/README.md",
        &[b"Accumulated ML-DSA tests", b"100 iterations"],
    )?;
    assert_text_contains(
        "cctv/rfc6979/README.md",
        &[b"RFC 6979 rejection sampling vector", b"NIST P-256"],
    )?;
    assert_text_contains(
        "cctv/keygen/README.md",
        &[b"RSA key generation benchmark", b"prime candidates"],
    )?;

    Ok(())
}

#[test]
#[ignore = "full CCTV corpus shape sweep; run deliberately when auditing vendored vectors"]
fn all_vendored_cctv_files_have_expected_markers() -> Result<(), VectorTestError> {
    for parameter_set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        assert_text_contains(
            &format!("cctv/ml-kem/intermediate/{parameter_set}.txt"),
            &[b"d = ", b"KBar = "],
        )?;
        assert_text_contains(
            &format!("cctv/ml-kem/strcmp/{parameter_set}.txt"),
            &[b"dk = ", b"c = ", b"K = "],
        )?;
        assert_text_contains(
            &format!("cctv/ml-kem/unluckysample/{parameter_set}.txt"),
            &[b"d = ", b"z = ", b"ek = ", b"dk = "],
        )?;
    }

    assert_text_contains(
        "cctv/ed25519/README.md",
        &[b"ed25519vectors.json", b"Ecosystem behaviors"],
    )?;
    assert_text_contains(
        "cctv/ed25519/ed25519vectors.json",
        &[b"low_order_A", b"reencoded_k"],
    )?;
    for parameter_set in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        assert_text_contains(
            &format!("cctv/ml-dsa/benchmark/{parameter_set}.json"),
            &[b"["],
        )?;
        assert_text_contains(
            &format!("cctv/ml-dsa/benchmark/{parameter_set}.alt.json"),
            &[b"["],
        )?;
    }
    assert_text_contains(
        "cctv/ml-dsa/benchmark/README.md",
        &[b"ML-DSA signing benchmark targets"],
    )?;
    assert_text_contains(
        "cctv/ml-dsa/accumulated/README.md",
        &[b"60 000 000 iterations"],
    )?;
    assert_text_contains("cctv/rfc6979/README.md", &[b"message = \"wv[vnX\""])?;
    assert_text_contains("cctv/keygen/README.md", &[b"rsa.bench.NNNN.txt"])?;

    Ok(())
}

fn assert_text_contains(path: &str, needles: &[&[u8]]) -> Result<(), VectorTestError> {
    let bytes = read_external_bytes(path)?;
    for needle in needles {
        assert!(
            bytes
                .windows(needle.len())
                .any(|candidate| candidate == *needle),
            "{path}"
        );
    }
    Ok(())
}
