// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn repository_package_shape_is_stable() -> Result<(), VectorTestError> {
    for path in [
        "crates/aes-kw",
        "crates/ml-kem-768",
        "crates/p256",
        "crates/crypto/dispatch",
        "crates/ffi",
        "crates/hpke",
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
        "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
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
        if path_is_generated(&source_file) {
            continue;
        }
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

    assert!(contract.contains("The TypeScript facade is synchronous."));
    assert!(contract.contains("WebCrypto is not part of the facade"));
    assert!(policy.contains("WebCrypto is not a provider for the synchronous TypeScript facade"));
    assert!(!package.contains("\"zod\""));
    assert!(!package.contains("\"io-ts\""));

    Ok(())
}

#[test]
fn canonical_contract_is_documented_and_not_rust_api_only() -> Result<(), VectorTestError> {
    let contract = read_repo_file("CONTRACT.md")?;
    let readme = read_repo_file("README.md")?;
    let policy = read_repo_file("PROVIDER_POLICY.md")?;
    let protobuf = read_repo_file("docs/protobuf.md")?;
    let conformance = read_repo_file("docs/conformance.md")?;
    let root_rustdoc = read_repo_file("crates/crypto/src/lib.rs")?;

    for required in [
        "## Canonical Contract",
        "protobuf enums and boundary messages",
        "package algorithm identifiers",
        "typed Rust error taxonomy",
        "provider_manifest.json",
        "shared positive and negative conformance vectors",
        "Rust remains the reference implementation",
        "platform facade is a first-class SDK surface",
        "Every provider route must implement identical input validation",
        "differential tests",
    ] {
        assert!(
            contract.contains(required),
            "CONTRACT.md is missing canonical-contract rule: {required}"
        );
    }

    for (path, source, required) in [
        (
            "README.md",
            readme.as_str(),
            "The canonical contract is not mechanically generated from one language API.",
        ),
        (
            "PROVIDER_POLICY.md",
            policy.as_str(),
            "Provider policy is one part of the canonical Crypto contract",
        ),
        (
            "PROVIDER_POLICY.md",
            policy.as_str(),
            "A native provider is interchangeable only when shared vectors",
        ),
        (
            "docs/protobuf.md",
            protobuf.as_str(),
            "not a generated mirror of the Rust package API",
        ),
        (
            "docs/conformance.md",
            conformance.as_str(),
            "Every provider route must prove the same contract",
        ),
        (
            "crates/crypto/src/lib.rs",
            root_rustdoc.as_str(),
            "The canonical contract is not the Rust API by itself.",
        ),
    ] {
        assert!(
            source.contains(required),
            "{path} is missing canonical-contract language: {required}"
        );
    }

    Ok(())
}
