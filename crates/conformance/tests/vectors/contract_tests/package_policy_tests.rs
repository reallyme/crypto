// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
    "HMAC-SHA-384",
    "HMAC-SHA-512",
    // KDF
    "HKDF-SHA256",
    "HKDF-SHA384",
    "Argon2id",
    "PBKDF2-HMAC-SHA-256",
    "PBKDF2-HMAC-SHA-512",
    "JWA-CONCAT-KDF-SHA256",
    "KMAC256",
    // Key wrap
    "AES-128-KW",
    "AES-192-KW",
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

const PRIMITIVE_CRATES: &[&str] = &[
    "aes-kw",
    "aes256-gcm",
    "aes256-gcm-siv",
    "argon2id",
    "chacha20-poly1305",
    "concat-kdf",
    "constant-time",
    "csprng",
    "ed25519",
    "hkdf",
    "hmac",
    "kmac",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "ml-kem-1024",
    "ml-kem-512",
    "ml-kem-768",
    "p256",
    "p384",
    "p521",
    "pbkdf2",
    "rsa",
    "secp256k1",
    "sha2",
    "sha2-256",
    "sha3",
    "sha3-256",
    "slh-dsa",
    "x-wing",
    "x25519",
];

/// Discovers primitive crates that accidentally grow a platform-provider
/// backend. Primitive crates are publishable Rust engines: Swift/Kotlin
/// provider policy belongs in package facades, where a missing provider can
/// return a typed unsupported error instead of changing a primitive crate's
/// compile-time surface.
fn primitive_crates_with_platform_lane() -> Result<Vec<String>, VectorTestError> {
    let root = repo_root()?;
    let mut out = Vec::new();
    for crate_name in PRIMITIVE_CRATES {
        let dir = root.join("crates").join(crate_name);
        if !dir.is_dir() {
            continue;
        }
        if dir.join("src/swift").is_dir() || dir.join("src/kotlin").is_dir() {
            out.push(format!("crates/{crate_name}/src/lib.rs"));
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

    let root = repo_root()?;
    for crate_name in PRIMITIVE_CRATES {
        let lib = root.join("crates").join(crate_name).join("src/lib.rs");
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
    let algorithm_policy = policy
        .split_once("## Algorithm Policy")
        .and_then(|(_, remainder)| remainder.split_once("## Policy Tests"))
        .map(|(section, _)| section)
        .ok_or(VectorTestError::InvalidField)?;

    for identifier in PACKAGE_ALGORITHM_IDENTIFIERS {
        assert!(
            algorithm_policy.contains(&format!("| `{identifier}` |")),
            "hand-written algorithm policy is missing canonical identifier {identifier}; \
             generated matrix text must not mask policy-table drift"
        );
    }

    Ok(())
}

#[test]
fn readme_records_messaging_bundle_and_x448_scope() -> Result<(), VectorTestError> {
    let readme = read_repo_file("README.md")?;
    let root_cargo = read_repo_file("crates/crypto/Cargo.toml")?;
    let manifest = read_repo_file("provider_manifest.json")?;

    assert!(!root_cargo.contains("messaging-dispatch"));
    assert!(root_cargo
        .contains("x25519 = [\"dep:crypto-x25519\", \"dispatch\", \"crypto-dispatch?/x25519\"]"));
    assert!(readme.contains("this bundle also enables `dispatch`"));
    assert!(readme.contains("does not enable `signer`"));
    assert!(!readme.contains("It does not enable `dispatch`"));

    assert!(readme.contains("standalone `reallyme-crypto-x448` Rust crate"));
    assert!(readme.contains("intentionally absent from the package provider"));
    assert!(!manifest.contains("\"id\": \"X448\""));

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
        "ReallyMeAndroidPlatformKeys",
        "A requested StrongBox residency never",
        "downgrades to TEE.",
        "TypeScript provider order:",
        "Audited synchronous JavaScript providers",
        "ReallyMe WASM/Rust",
        "Typed `unsupportedAlgorithm`",
        "No silent fallback",
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
