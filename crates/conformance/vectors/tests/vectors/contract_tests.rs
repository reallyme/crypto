// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::support::{field_array, field_string, load, VectorTestError};

const PROTO_ENUM_VALUES: &[(&str, i32)] = &[
    ("CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED", 0),
    ("CRYPTO_ALGORITHM_FAMILY_SIGNATURE", 1),
    ("CRYPTO_ALGORITHM_FAMILY_KEY_AGREEMENT", 2),
    ("CRYPTO_ALGORITHM_FAMILY_KEM", 3),
    ("CRYPTO_ALGORITHM_FAMILY_AEAD", 4),
    ("CRYPTO_ALGORITHM_FAMILY_HASH", 5),
    ("CRYPTO_ALGORITHM_FAMILY_MAC", 6),
    ("CRYPTO_ALGORITHM_FAMILY_KDF", 7),
    ("CRYPTO_ALGORITHM_FAMILY_KEY_WRAP", 8),
    ("CRYPTO_ALGORITHM_FAMILY_HPKE", 9),
    ("SIGNATURE_ALGORITHM_UNSPECIFIED", 0),
    ("SIGNATURE_ALGORITHM_ED25519", 1),
    ("SIGNATURE_ALGORITHM_ECDSA_P256_SHA256", 2),
    ("SIGNATURE_ALGORITHM_ECDSA_P384_SHA384", 3),
    ("SIGNATURE_ALGORITHM_ECDSA_P521_SHA512", 4),
    ("SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256", 5),
    ("SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256", 6),
    ("SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1", 7),
    ("SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256", 8),
    ("SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384", 9),
    ("SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512", 10),
    ("SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1", 11),
    ("SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256", 12),
    ("SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384", 13),
    ("SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512", 14),
    ("SIGNATURE_ALGORITHM_ML_DSA_44", 15),
    ("SIGNATURE_ALGORITHM_ML_DSA_65", 16),
    ("SIGNATURE_ALGORITHM_ML_DSA_87", 17),
    ("SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S", 18),
    ("KEY_AGREEMENT_ALGORITHM_UNSPECIFIED", 0),
    ("KEY_AGREEMENT_ALGORITHM_X25519", 1),
    ("KEY_AGREEMENT_ALGORITHM_P256_ECDH", 2),
    ("KEY_AGREEMENT_ALGORITHM_P384_ECDH", 3),
    ("KEY_AGREEMENT_ALGORITHM_P521_ECDH", 4),
    ("KEM_ALGORITHM_UNSPECIFIED", 0),
    ("KEM_ALGORITHM_ML_KEM_512", 1),
    ("KEM_ALGORITHM_ML_KEM_768", 2),
    ("KEM_ALGORITHM_ML_KEM_1024", 3),
    ("KEM_ALGORITHM_X_WING_768", 4),
    ("KEM_ALGORITHM_X_WING_1024", 5),
    ("HPKE_SUITE_UNSPECIFIED", 0),
    (
        "HPKE_SUITE_DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
        1,
    ),
    (
        "HPKE_SUITE_DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305",
        2,
    ),
    ("AEAD_ALGORITHM_UNSPECIFIED", 0),
    ("AEAD_ALGORITHM_AES_256_GCM", 1),
    ("AEAD_ALGORITHM_AES_256_GCM_SIV", 2),
    ("AEAD_ALGORITHM_CHACHA20_POLY1305", 3),
    ("AEAD_ALGORITHM_XCHACHA20_POLY1305", 4),
    ("AEAD_ALGORITHM_AES_128_GCM", 5),
    ("AEAD_ALGORITHM_AES_192_GCM", 6),
    ("HASH_ALGORITHM_UNSPECIFIED", 0),
    ("HASH_ALGORITHM_SHA2_256", 1),
    ("HASH_ALGORITHM_SHA2_384", 2),
    ("HASH_ALGORITHM_SHA2_512", 3),
    ("HASH_ALGORITHM_SHA3_224", 4),
    ("HASH_ALGORITHM_SHA3_256", 5),
    ("HASH_ALGORITHM_SHA3_384", 6),
    ("HASH_ALGORITHM_SHA3_512", 7),
    ("MAC_ALGORITHM_UNSPECIFIED", 0),
    ("MAC_ALGORITHM_HMAC_SHA256", 1),
    ("MAC_ALGORITHM_HMAC_SHA512", 2),
    ("KDF_ALGORITHM_UNSPECIFIED", 0),
    ("KDF_ALGORITHM_HKDF_SHA256", 1),
    ("KDF_ALGORITHM_ARGON2ID", 2),
    ("KDF_ALGORITHM_PBKDF2_HMAC_SHA256", 3),
    ("KDF_ALGORITHM_PBKDF2_HMAC_SHA512", 4),
    ("KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256", 5),
    ("KEY_WRAP_ALGORITHM_UNSPECIFIED", 0),
    ("KEY_WRAP_ALGORITHM_AES_256_KW", 1),
    ("MULTICODEC_KEY_ALGORITHM_UNSPECIFIED", 0),
    ("MULTICODEC_KEY_ALGORITHM_ED25519_PUB", 1),
    ("MULTICODEC_KEY_ALGORITHM_X25519_PUB", 2),
    ("MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB", 3),
    ("MULTICODEC_KEY_ALGORITHM_P256_PUB", 4),
    ("MULTICODEC_KEY_ALGORITHM_P384_PUB", 5),
    ("MULTICODEC_KEY_ALGORITHM_P521_PUB", 6),
    ("MULTICODEC_KEY_ALGORITHM_ED448_PUB", 7),
    ("MULTICODEC_KEY_ALGORITHM_RSA_PUB", 8),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB", 9),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB", 10),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB", 11),
    ("MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB", 12),
    ("MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB", 13),
    ("MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB", 14),
    ("MULTICODEC_KEY_ALGORITHM_ED25519_PRIV", 15),
    ("MULTICODEC_KEY_ALGORITHM_X25519_PRIV", 16),
    ("MULTICODEC_KEY_ALGORITHM_SECP256K1_PRIV", 17),
    ("MULTICODEC_KEY_ALGORITHM_P256_PRIV", 18),
    ("MULTICODEC_KEY_ALGORITHM_P384_PRIV", 19),
    ("MULTICODEC_KEY_ALGORITHM_P521_PRIV", 20),
    ("MULTICODEC_KEY_ALGORITHM_ED448_PRIV", 21),
    ("MULTICODEC_KEY_ALGORITHM_RSA_PRIV", 22),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PRIV", 23),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PRIV", 24),
    ("MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PRIV", 25),
];

const PROTO_ALGORITHM_ENUMS: &[&str] = &[
    "CryptoAlgorithmFamily",
    "SignatureAlgorithm",
    "KeyAgreementAlgorithm",
    "KemAlgorithm",
    "HpkeSuite",
    "AeadAlgorithm",
    "HashAlgorithm",
    "MacAlgorithm",
    "KdfAlgorithm",
    "KeyWrapAlgorithm",
    "MulticodecKeyAlgorithm",
];

const VECTOR_ALG_STRINGS: &[&str] = &[
    "AES-128",
    "AES-128-GCM",
    "AES-192",
    "AES-192-GCM",
    "AES-256",
    "AES-256-GCM",
    "AES-256-GCM-SIV",
    "AES-256-KW",
    "Argon2id",
    "BIP-340",
    "ChaCha-128",
    "ChaCha-256",
    "ChaCha20-Poly1305",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "Ed25519",
    "Ed448",
    "EdDSA",
    "HKDF-SHA256",
    "HMAC-SHA-256",
    "HMAC-SHA-512",
    "HPKE-P256-SHA256-AES256GCM",
    "HPKE-X25519-SHA256-CHACHA20POLY1305",
    "JWA-CONCAT-KDF-SHA256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "ML-KEM-1024",
    "ML-KEM-512",
    "ML-KEM-768",
    "P-256",
    "P-384",
    "P-521",
    "PBKDF2-HMAC-SHA-256",
    "PBKDF2-HMAC-SHA-512",
    "RSA",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SLH-DSA-SHA2-128s",
    "X-Wing-1024",
    "X-Wing-768",
    "X25519",
    "XChaCha20-Poly1305",
    "secp256k1",
];

const MULTICODEC_PREFIXES: &[(&str, &str, &str)] = &[
    ("sha2-256", "SHA2-256", "Eg"),
    ("sha2-512", "SHA2-512", "Ew"),
    ("sha3-512", "SHA3-512", "FA"),
    ("sha3-384", "SHA3-384", "FQ"),
    ("sha3-256", "SHA3-256", "Fg"),
    ("sha3-224", "SHA3-224", "Fw"),
    ("sha2-384", "SHA2-384", "IA"),
    ("aes-128", "AES-128", "oAE"),
    ("aes-192", "AES-192", "oQE"),
    ("aes-256", "AES-256", "ogE"),
    ("chacha-128", "ChaCha-128", "owE"),
    ("chacha-256", "ChaCha-256", "pAE"),
    ("ed25519-pub", "Ed25519", "7QE"),
    ("x25519-pub", "X25519", "7AE"),
    ("p256-pub", "P-256", "gCQ"),
    ("p384-pub", "P-384", "gSQ"),
    ("p521-pub", "P-521", "giQ"),
    ("ed448-pub", "Ed448", "gyQ"),
    ("rsa-pub", "RSA", "hSQ"),
    ("secp256k1-pub", "secp256k1", "5wE"),
    ("mldsa-44-pub", "ML-DSA-44", "kCQ"),
    ("mldsa-65-pub", "ML-DSA-65", "kSQ"),
    ("mldsa-87-pub", "ML-DSA-87", "kiQ"),
    ("mlkem-512-pub", "ML-KEM-512", "iyQ"),
    ("mlkem-768-pub", "ML-KEM-768", "jCQ"),
    ("mlkem-1024-pub", "ML-KEM-1024", "jSQ"),
    ("ed25519-priv", "Ed25519", "gCY"),
    ("secp256k1-priv", "secp256k1", "gSY"),
    ("x25519-priv", "X25519", "giY"),
    ("rsa-priv", "RSA", "hSY"),
    ("p256-priv", "P-256", "hiY"),
    ("p384-priv", "P-384", "hyY"),
    ("p521-priv", "P-521", "iCY"),
    ("ed448-priv", "Ed448", "kSY"),
    ("mlkem-512-priv", "ML-KEM-512", "kyY"),
    ("mlkem-768-priv", "ML-KEM-768", "lCY"),
    ("mlkem-1024-priv", "ML-KEM-1024", "lSY"),
    ("aes-gcm-256", "AES-256-GCM", "gEA"),
    ("chacha20-poly1305", "ChaCha20-Poly1305", "gMAC"),
];

fn repo_root() -> Result<PathBuf, VectorTestError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(VectorTestError::VectorsDirectory)
}

fn read_repo_file(path: &str) -> Result<String, VectorTestError> {
    fs::read_to_string(repo_root()?.join(path)).map_err(|_| VectorTestError::ReadVector)
}

fn assert_repo_dir(path: &str) -> Result<(), VectorTestError> {
    assert!(
        repo_root()?.join(path).is_dir(),
        "required repository directory is missing: {path}"
    );
    Ok(())
}

fn assert_repo_file(path: &str) -> Result<(), VectorTestError> {
    assert!(
        repo_root()?.join(path).is_file(),
        "required repository file is missing: {path}"
    );
    Ok(())
}

fn assert_repo_path_absent(path: &str) -> Result<(), VectorTestError> {
    assert!(
        !repo_root()?.join(path).exists(),
        "obsolete repository path should not exist: {path}"
    );
    Ok(())
}

fn collect_source_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), VectorTestError> {
    for entry in fs::read_dir(root).map_err(|_| VectorTestError::ReadVector)? {
        let entry = entry.map_err(|_| VectorTestError::ReadVector)?;
        let path = entry.path();
        if path.is_dir() {
            let directory_name = path.file_name().and_then(|value| value.to_str());
            if matches!(
                directory_name,
                Some(".build" | ".gradle" | "build" | "dist" | "node_modules" | "target")
            ) {
                continue;
            }
            collect_source_files(&path, out)?;
            continue;
        }

        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if matches!(extension, "rs" | "swift" | "kt" | "ts") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_files_named(
    root: &Path,
    file_name: &str,
    out: &mut Vec<PathBuf>,
) -> Result<(), VectorTestError> {
    for entry in fs::read_dir(root).map_err(|_| VectorTestError::ReadVector)? {
        let entry = entry.map_err(|_| VectorTestError::ReadVector)?;
        let path = entry.path();
        if path.is_dir() {
            let directory_name = path.file_name().and_then(|value| value.to_str());
            if matches!(
                directory_name,
                Some(".build" | ".gradle" | "build" | "dist" | "node_modules" | "target")
            ) {
                continue;
            }
            collect_files_named(&path, file_name, out)?;
            continue;
        }

        if path.file_name().and_then(|value| value.to_str()) == Some(file_name) {
            out.push(path);
        }
    }
    Ok(())
}

fn line_has_wildcard_export_or_import(line: &str) -> bool {
    let trimmed = line.trim();
    (trimmed.starts_with("pub use ") && trimmed.contains("::*"))
        || trimmed.starts_with("export *")
        || trimmed.starts_with("@_exported import ")
        || (trimmed.starts_with("import ") && trimmed.ends_with(".*"))
        || (trimmed.starts_with("import ") && trimmed.ends_with(".*;"))
}

fn collect_alg_strings(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(alg)) = fields.get("alg") {
                out.insert(alg.to_owned());
            }
            for child in fields.values() {
                collect_alg_strings(child, out);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_alg_strings(child, out);
            }
        }
        _ => {}
    }
}

fn parse_proto_enum_values(proto: &str, enum_names: &[&str]) -> BTreeMap<String, i32> {
    let mut values = BTreeMap::new();
    let allowed_enums = enum_names.iter().copied().collect::<BTreeSet<_>>();
    let mut include_current_enum = false;

    for line in proto.lines() {
        let trimmed = line.trim();
        if let Some(enum_name) = trimmed
            .strip_prefix("enum ")
            .and_then(|rest| rest.strip_suffix(" {"))
        {
            include_current_enum = allowed_enums.contains(enum_name);
            continue;
        }
        if trimmed == "}" {
            include_current_enum = false;
            continue;
        }
        if !include_current_enum {
            continue;
        }
        let Some((name, rest)) = trimmed.split_once(" = ") else {
            continue;
        };
        if !name.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        }) {
            continue;
        }
        let Some(value) = rest.strip_suffix(';') else {
            continue;
        };
        let Ok(parsed) = value.parse::<i32>() else {
            continue;
        };
        values.insert(name.to_owned(), parsed);
    }

    values
}

#[test]
fn protobuf_algorithm_enum_numbers_are_stable() -> Result<(), VectorTestError> {
    let proto = read_repo_file("proto/reallyme/crypto/v1/crypto.proto")?;
    let actual = parse_proto_enum_values(&proto, PROTO_ALGORITHM_ENUMS);
    let expected = PROTO_ENUM_VALUES
        .iter()
        .map(|(name, value)| ((*name).to_owned(), *value))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn repository_package_shape_is_stable() -> Result<(), VectorTestError> {
    for path in [
        "crates/crypto/primitives",
        "crates/crypto/dispatch",
        "crates/crypto/ffi",
        "crates/crypto/protocols",
        "packages/swift/Sources/ReallyMeCrypto",
        "packages/swift/Tests",
        "packages/kotlin/src/main/kotlin/me/really/crypto",
        "packages/kotlin/src/test",
        "packages/ts/src",
        "packages/ts/test",
        "vectors",
    ] {
        assert_repo_dir(path)?;
    }

    for path in [
        "Package.swift",
        "packages/swift/Sources/ReallyMeCrypto/Algorithms.swift",
        "packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift",
        "packages/swift/Sources/ReallyMeCrypto/Hkdf.swift",
        "packages/swift/Sources/ReallyMeCrypto/Hmac.swift",
        "packages/swift/Sources/ReallyMeCrypto/P256Ecdh.swift",
        "packages/swift/Sources/ReallyMeCrypto/Pbkdf2.swift",
        "packages/swift/Sources/ReallyMeCrypto/X25519.swift",
        "packages/kotlin/build.gradle.kts",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Algorithms.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Ed25519.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Hkdf.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Hmac.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/P256Ecdh.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt",
        "packages/kotlin/src/main/kotlin/me/really/crypto/X25519.kt",
        "packages/ts/package.json",
        "packages/ts/src/algorithms.ts",
        "packages/ts/src/cryptoFacade.ts",
        "packages/ts/src/ed25519.ts",
        "packages/ts/src/hkdf.ts",
        "packages/ts/src/hmac.ts",
        "packages/ts/src/p256Ecdh.ts",
        "packages/ts/src/pbkdf2.ts",
        "packages/ts/src/x25519.ts",
        "proto/reallyme/crypto/v1/crypto.proto",
    ] {
        assert_repo_file(path)?;
    }

    // SwiftPM package-by-URL consumers read the root manifest. Keeping a second
    // manifest under packages/swift would split the SDK contract again.
    assert_repo_path_absent("packages/swift/Package.swift")?;

    Ok(())
}

#[test]
fn source_exports_and_imports_are_named_not_wildcarded() -> Result<(), VectorTestError> {
    let root = repo_root()?;
    let mut source_files = Vec::new();
    for path in ["crates", "packages"] {
        collect_source_files(&root.join(path), &mut source_files)?;
    }

    for source_file in source_files {
        let source = fs::read_to_string(&source_file).map_err(|_| VectorTestError::ReadVector)?;
        for (index, line) in source.lines().enumerate() {
            assert!(
                !line_has_wildcard_export_or_import(line),
                "wildcard export/import at {}:{}; package and crate surfaces must use named exports",
                source_file.display(),
                index + 1
            );
        }
    }

    Ok(())
}

#[test]
fn vector_algorithm_strings_are_stable() -> Result<(), VectorTestError> {
    let manifest = load("manifest.json")?;
    let vectors = field_array(&manifest, "vectors")?;
    let mut actual = BTreeSet::new();

    for vector in vectors {
        let vector_name = vector.as_str().ok_or(VectorTestError::InvalidField)?;
        collect_alg_strings(&load(vector_name)?, &mut actual);
    }

    let expected = VECTOR_ALG_STRINGS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn multicodec_prefix_contract_is_stable() -> Result<(), VectorTestError> {
    let codecs = load("codecs.json")?;
    let prefixes = field_array(&codecs, "multicodec_prefixes")?;
    let mut actual = BTreeMap::new();

    for prefix in prefixes {
        actual.insert(
            field_string(prefix, "name")?,
            (
                field_string(prefix, "alg")?,
                field_string(prefix, "prefix")?,
            ),
        );
    }

    assert_eq!(actual.len(), MULTICODEC_PREFIXES.len());
    for &(name, alg, prefix) in MULTICODEC_PREFIXES {
        assert_eq!(actual.get(name), Some(&(alg, prefix)));
    }

    Ok(())
}

#[test]
fn matrix_records_kotlin_jvm_and_android_separately() -> Result<(), VectorTestError> {
    // The backend matrix is generated into PROVIDER_POLICY.md by
    // scripts/generate_provider_matrix.mjs from provider_manifest.json.
    let matrix = read_repo_file("PROVIDER_POLICY.md")?;

    assert!(
        matrix.contains(
            "| Algorithm | Family | Swift | Kotlin/JVM | Kotlin/Android | TypeScript/WASM |"
        ),
        "Kotlin provider matrix must split JVM and Android policy"
    );
    assert!(
        matrix.contains("Generated from `provider_manifest.json`"),
        "Kotlin lane split must be generated from the provider manifest"
    );

    Ok(())
}

#[test]
fn typescript_contract_is_sync_and_webcrypto_free() -> Result<(), VectorTestError> {
    let contract = read_repo_file("CONTRACT.md")?;
    let package = read_repo_file("packages/ts/package.json")?;
    let policy = read_repo_file("PROVIDER_POLICY.md")?;

    assert!(contract.contains("The TypeScript facade is synchronous for the 0.1 line."));
    assert!(contract.contains("WebCrypto is not part of the 0.1 facade"));
    assert!(policy.contains("WebCrypto is not part of the 0.1 line"));
    assert!(!package.contains("\"zod\""));
    assert!(!package.contains("\"io-ts\""));

    Ok(())
}

/// Canonical package algorithm identifier strings. These are the exact
/// strings the Swift raw values, Kotlin `algorithmName` values, and
/// TypeScript union members must all carry; a rename in one lane without the
/// others is contract drift that per-lane builds cannot catch.
const PACKAGE_ALGORITHM_IDENTIFIERS: &[&str] = &[
    // Signature
    "Ed25519",
    "ECDSA-P256-SHA256",
    "ECDSA-P384-SHA384",
    "ECDSA-P521-SHA512",
    "ECDSA-secp256k1-SHA256",
    "BIP340-Schnorr-secp256k1-SHA256",
    "RSA-PKCS1v15-SHA1",
    "RSA-PKCS1v15-SHA256",
    "RSA-PKCS1v15-SHA384",
    "RSA-PKCS1v15-SHA512",
    "RSA-PSS-SHA1-MGF1-SHA1",
    "RSA-PSS-SHA256-MGF1-SHA256",
    "RSA-PSS-SHA384-MGF1-SHA384",
    "RSA-PSS-SHA512-MGF1-SHA512",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    // Key agreement
    "X25519",
    "P-256-ECDH",
    "P-384-ECDH",
    "P-521-ECDH",
    // KEM
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "X-Wing-768",
    "X-Wing-1024",
    // AEAD
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "AES-256-GCM-SIV",
    "ChaCha20-Poly1305",
    "XChaCha20-Poly1305",
    // Hash
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    // MAC
    "HMAC-SHA-256",
    "HMAC-SHA-512",
    // KDF
    "HKDF-SHA256",
    "Argon2id",
    "PBKDF2-HMAC-SHA-256",
    "PBKDF2-HMAC-SHA-512",
    // Key wrap
    "AES-256-KW",
    // HPKE
    "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
    "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
];

#[test]
fn package_algorithm_identifiers_are_stable_across_lanes() -> Result<(), VectorTestError> {
    for lane in [
        "packages/swift/Sources/ReallyMeCrypto/Algorithms.swift",
        "packages/kotlin/src/main/kotlin/me/really/crypto/Algorithms.kt",
        "packages/ts/src/algorithms.ts",
    ] {
        let source = read_repo_file(lane)?;
        for identifier in PACKAGE_ALGORITHM_IDENTIFIERS {
            assert!(
                source.contains(&format!("\"{identifier}\"")),
                "canonical algorithm identifier {identifier} is missing from {lane}; \
                 package identifier strings must stay byte-identical across lanes"
            );
        }
    }

    Ok(())
}

/// Discovers primitive crates that accidentally grow a platform-provider
/// backend. Primitive crates are publishable Rust engines: Swift/Kotlin
/// provider policy belongs in package facades, where a missing provider can
/// return a typed unsupported error instead of changing a primitive crate's
/// compile-time surface.
fn primitive_crates_with_platform_lane() -> Result<Vec<String>, VectorTestError> {
    let primitives = repo_root()?.join("crates/crypto/primitives");
    let mut out = Vec::new();
    for entry in fs::read_dir(&primitives).map_err(|_| VectorTestError::ReadVector)? {
        let entry = entry.map_err(|_| VectorTestError::ReadVector)?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        if dir.join("src/swift").is_dir() || dir.join("src/kotlin").is_dir() {
            out.push(format!(
                "crates/crypto/primitives/{}/src/lib.rs",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    Ok(out)
}

#[test]
fn primitive_crates_do_not_own_platform_provider_lanes() -> Result<(), VectorTestError> {
    let platform_lanes = primitive_crates_with_platform_lane()?;
    assert!(
        platform_lanes.is_empty(),
        "primitive crates must not own Swift/Kotlin provider lanes: {platform_lanes:?}"
    );

    for entry in fs::read_dir(repo_root()?.join("crates/crypto/primitives"))
        .map_err(|_| VectorTestError::ReadVector)?
    {
        let entry = entry.map_err(|_| VectorTestError::ReadVector)?;
        let lib = entry.path().join("src/lib.rs");
        if !lib.is_file() {
            continue;
        }
        let source = fs::read_to_string(&lib).map_err(|_| VectorTestError::ReadVector)?;
        for required in [
            "reallyme_link_swift_crypto",
            "reallyme_link_kotlin_crypto",
            "reallyme_test_native_backend",
            concat!("REALLYME_TEST_", "NATIVE_BACKEND=1"),
        ] {
            assert!(
                !source.contains(required),
                "{} still contains primitive-level platform backend token {required}",
                lib.display()
            );
        }
    }

    Ok(())
}

#[test]
fn rust_crates_do_not_publish_swift_or_kotlin_feature_lanes() -> Result<(), VectorTestError> {
    let root = repo_root()?;
    let mut cargo_manifests = vec![root.join("Cargo.toml")];
    collect_files_named(&root.join("crates"), "Cargo.toml", &mut cargo_manifests)?;
    let swift_feature_cfg = concat!("feature = ", "\"", "swift", "\"");
    let kotlin_feature_cfg = concat!("feature = ", "\"", "kotlin", "\"");

    for manifest in cargo_manifests {
        let source = fs::read_to_string(&manifest).map_err(|_| VectorTestError::ReadVector)?;
        for forbidden in [
            "\nswift =",
            "\nkotlin =",
            "/swift",
            "/kotlin",
            swift_feature_cfg,
            kotlin_feature_cfg,
        ] {
            assert!(
                !source.contains(forbidden),
                "{} contains vestigial Rust platform feature token {forbidden:?}; \
                 platform provider selection belongs in SDK packages",
                manifest.display()
            );
        }
    }

    let mut rust_sources = Vec::new();
    collect_source_files(&root.join("crates"), &mut rust_sources)?;
    for source_path in rust_sources {
        if source_path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&source_path).map_err(|_| VectorTestError::ReadVector)?;
        for forbidden in [swift_feature_cfg, kotlin_feature_cfg] {
            assert!(
                !source.contains(forbidden),
                "{} contains vestigial Rust platform cfg token {forbidden:?}; \
                 Rust crates expose native/wasm features only",
                source_path.display()
            );
        }
    }

    Ok(())
}

#[test]
fn provider_policy_records_every_package_algorithm_identifier() -> Result<(), VectorTestError> {
    let policy = read_repo_file("PROVIDER_POLICY.md")?;

    for identifier in PACKAGE_ALGORITHM_IDENTIFIERS {
        assert!(
            policy.contains(&format!("| `{identifier}` |")),
            "provider policy is missing canonical algorithm identifier {identifier}; \
             provider order must be explicit for every package algorithm"
        );
    }

    Ok(())
}

#[test]
fn provider_policy_records_lane_hierarchies() -> Result<(), VectorTestError> {
    let policy = read_repo_file("PROVIDER_POLICY.md")?;

    for required in [
        "Swift provider order:",
        "CryptoKit or Security.framework",
        "`CSecp256k1`, only for secp256k1 operations",
        "ReallyMe Rust C ABI",
        "Kotlin/JVM provider order:",
        "JCA/JCE, only when provider behavior is byte-stable",
        "BouncyCastle",
        "Kotlin/Android provider order:",
        "The Android platform provider or Conscrypt",
        "Android Keystore key residency is not part of this policy",
        "TypeScript provider order:",
        "Audited synchronous JavaScript providers",
        "Node `crypto`, only if a future synchronous wrapper is byte-stable",
        "ReallyMe WASM/Rust",
        "Typed `unsupportedAlgorithm`",
        "silently fall back",
    ] {
        assert!(
            policy.contains(required),
            "provider policy is missing required provider rule: {required}"
        );
    }

    Ok(())
}

#[test]
fn provider_catalogs_name_explicit_provider_sets() -> Result<(), VectorTestError> {
    let swift = read_repo_file("packages/swift/Sources/ReallyMeCrypto/ProviderCatalog.swift")?;
    let kotlin =
        read_repo_file("packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt")?;
    let ts = read_repo_file("packages/ts/src/providerCatalog.ts")?;

    // Post-quantum on Swift routes through the ReallyMe Rust C ABI per
    // PROVIDER_POLICY.md, so no Swift-native PQ package (SwiftKyber/
    // SwiftDilithium) is linked or named in the catalog.
    for required in ["CryptoKit", "CSecp256k1", "Digest", "ReallyMe Rust C ABI"] {
        assert!(
            swift.contains(required),
            "Swift provider catalog is missing explicit provider {required}"
        );
    }

    for required in ["JCA/JCE", "BouncyCastle", "ReallyMe Rust C ABI"] {
        assert!(
            kotlin.contains(required),
            "Kotlin provider catalog is missing explicit provider {required}"
        );
    }

    for required in ["@noble/curves", "@noble/hashes", "ReallyMe Rust WASM"] {
        assert!(
            ts.contains(required),
            "TypeScript provider catalog is missing explicit provider {required}"
        );
    }

    Ok(())
}
