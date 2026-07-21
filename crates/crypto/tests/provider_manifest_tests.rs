// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SWIFT_LANE: &str = "swift";
const KOTLIN_JVM_LANE: &str = "kotlin_jvm";
const KOTLIN_ANDROID_LANE: &str = "kotlin_android";
const TYPESCRIPT_WASM_LANE: &str = "typescript_wasm";

const SUPPORTED: &str = "supported";
const PROVIDER_AWARE: &str = "provider_aware";
const PARTIAL: &str = "partial";
const UNSUPPORTED: &str = "unsupported";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderManifest {
    schema_version: u16,
    generated_document: String,
    required_lanes: Vec<String>,
    fallback_behaviors: Vec<String>,
    algorithms: Vec<ManifestAlgorithm>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestAlgorithm {
    id: String,
    family: String,
    package_api: bool,
    lanes: Option<ManifestLanes>,
    same_as: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ManifestLanes {
    swift: ManifestLane,
    kotlin_jvm: ManifestLane,
    kotlin_android: ManifestLane,
    typescript_wasm: ManifestLane,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManifestLane {
    status: String,
    providers: Vec<String>,
    uses_rust: bool,
    api: String,
    fallback: String,
}

#[test]
fn provider_manifest_covers_every_package_algorithm_identifier() {
    let root = workspace_root();
    let manifest = load_manifest(&root);
    let manifest_algorithm_ids = package_algorithm_ids(&manifest);

    assert_eq!(
        manifest_algorithm_ids,
        quoted_strings(&root.join("packages/swift/Sources/ReallyMeCrypto/Algorithms.swift")),
        "Swift package algorithm identifiers must match provider_manifest.json"
    );
    assert_eq!(
        manifest_algorithm_ids,
        quoted_strings(
            &root.join("packages/kotlin/src/main/kotlin/me/really/crypto/Algorithms.kt")
        ),
        "Kotlin package algorithm identifiers must match provider_manifest.json"
    );
    assert_eq!(
        manifest_algorithm_ids,
        quoted_strings(&root.join("packages/ts/src/algorithms.ts")),
        "TypeScript package algorithm identifiers must match provider_manifest.json"
    );
}

#[test]
fn every_manifest_algorithm_has_required_lanes_and_explicit_fallback() {
    let root = workspace_root();
    let manifest = load_manifest(&root);
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.generated_document, "PROVIDER_POLICY.md");
    assert_eq!(
        manifest.required_lanes,
        [
            SWIFT_LANE.to_owned(),
            KOTLIN_JVM_LANE.to_owned(),
            KOTLIN_ANDROID_LANE.to_owned(),
            TYPESCRIPT_WASM_LANE.to_owned(),
        ]
    );

    let fallback_behaviors: BTreeSet<&str> = manifest
        .fallback_behaviors
        .iter()
        .map(String::as_str)
        .collect();

    for algorithm in resolved_algorithms(&manifest) {
        assert!(
            !algorithm.id.is_empty(),
            "manifest algorithm id must not be empty"
        );
        assert!(
            !algorithm.family.is_empty(),
            "manifest family for {} must not be empty",
            algorithm.id
        );
        assert!(
            algorithm.same_as.is_none(),
            "resolved algorithm {} unexpectedly retained sameAs",
            algorithm.id
        );

        for (lane_name, lane) in lane_entries(&algorithm) {
            assert!(
                fallback_behaviors.contains(lane.fallback.as_str()),
                "{} has unknown fallback {} for {}",
                algorithm.id,
                lane.fallback,
                lane_name
            );
            assert_ne!(
                lane.fallback, "silent",
                "{} must not silently fall back for {}",
                algorithm.id, lane_name
            );
            assert!(
                !lane.api.is_empty(),
                "{} must name an API or typed unsupported behavior for {}",
                algorithm.id,
                lane_name
            );
            assert_eq!(
                lane.uses_rust,
                lane.providers
                    .iter()
                    .any(|provider| provider.contains("Rust")),
                "{} Rust-provider declaration must match providers for {}",
                algorithm.id,
                lane_name
            );

            match lane.status.as_str() {
                SUPPORTED | PROVIDER_AWARE | PARTIAL => assert!(
                    !lane.providers.is_empty(),
                    "{} must name at least one provider for {}",
                    algorithm.id,
                    lane_name
                ),
                UNSUPPORTED => assert!(
                    lane.providers.is_empty(),
                    "{} must not name providers for unsupported {} lane",
                    algorithm.id,
                    lane_name
                ),
                _ => panic!(
                    "{} has unknown status {} for {}",
                    algorithm.id, lane.status, lane_name
                ),
            }
        }
    }
}

#[test]
fn manifest_providers_are_present_in_package_catalogs() {
    let root = workspace_root();
    let manifest = load_manifest(&root);
    let swift_catalog =
        quoted_strings(&root.join("packages/swift/Sources/ReallyMeCrypto/ProviderCatalog.swift"));
    let kotlin_catalog = quoted_strings(
        &root.join("packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt"),
    );
    let mut kotlin_android_catalog = kotlin_catalog.clone();
    kotlin_android_catalog.extend(quoted_strings(&root.join(
        "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidProviderCatalog.kt",
    )));
    let typescript_catalog = quoted_strings(&root.join("packages/ts/src/providerCatalog.ts"));

    for algorithm in resolved_algorithms(&manifest) {
        let lanes = algorithm
            .lanes
            .as_ref()
            .expect("resolved algorithms have lanes");
        assert_catalog_covers(&algorithm.id, SWIFT_LANE, &swift_catalog, &lanes.swift);
        assert_catalog_covers(
            &algorithm.id,
            KOTLIN_JVM_LANE,
            &kotlin_catalog,
            &lanes.kotlin_jvm,
        );
        assert_catalog_covers(
            &algorithm.id,
            KOTLIN_ANDROID_LANE,
            &kotlin_android_catalog,
            &lanes.kotlin_android,
        );
        assert_catalog_covers(
            &algorithm.id,
            TYPESCRIPT_WASM_LANE,
            &typescript_catalog,
            &lanes.typescript_wasm,
        );
    }
}

#[test]
fn hardware_backed_providers_are_explicit_handle_backed_routes_only() {
    let root = workspace_root();
    let manifest = load_manifest(&root);
    let algorithms = resolved_algorithms(&manifest);

    let p256_signature = find_algorithm(&algorithms, "ECDSA-P256-SHA256");
    let p256_signature_lanes = p256_signature
        .lanes
        .as_ref()
        .expect("resolved algorithms have lanes");
    assert!(
        p256_signature_lanes
            .swift
            .providers
            .contains(&"Secure Enclave/Keychain".to_owned()),
        "Swift P-256 signing must keep its explicit Secure Enclave handle route"
    );
    assert!(
        p256_signature_lanes
            .swift
            .api
            .contains("ReallyMeP256SecureEnclaveEcdsa"),
        "Swift P-256 signing manifest must name the handle-backed API"
    );

    let p256_ecdh = find_algorithm(&algorithms, "P-256-ECDH");
    let p256_ecdh_lanes = p256_ecdh
        .lanes
        .as_ref()
        .expect("resolved algorithms have lanes");
    assert!(
        p256_ecdh_lanes
            .swift
            .providers
            .contains(&"Secure Enclave/Keychain".to_owned()),
        "Swift P-256 ECDH must keep its explicit Secure Enclave handle route"
    );
    assert!(
        p256_ecdh_lanes
            .swift
            .api
            .contains("ReallyMeP256SecureEnclaveEcdh"),
        "Swift P-256 ECDH manifest must name the handle-backed API"
    );

    for algorithm in algorithms {
        for (lane_name, lane) in lane_entries(&algorithm) {
            if lane_name == KOTLIN_ANDROID_LANE || lane_name == KOTLIN_JVM_LANE {
                let is_android_platform_key_algorithm = lane_name == KOTLIN_ANDROID_LANE
                    && matches!(algorithm.id.as_str(), "ECDSA-P256-SHA256" | "P-256-ECDH");
                let names_android_hardware = lane
                    .providers
                    .iter()
                    .any(|provider| provider == "Android Keystore" || provider == "StrongBox");
                if is_android_platform_key_algorithm {
                    assert!(
                        names_android_hardware && lane.api.contains("ReallyMeAndroidPlatformKeys"),
                        "{} must name the Android handle-backed hardware provider API",
                        algorithm.id
                    );
                } else {
                    assert!(
                        !names_android_hardware
                            && !lane.api.contains("StrongBox")
                            && !lane.api.contains("Android Keystore"),
                        "{} must not silently select Android hardware providers for {}",
                        algorithm.id,
                        lane_name
                    );
                }
            }

            if lane_name != SWIFT_LANE {
                assert!(
                    !lane
                        .providers
                        .contains(&"Secure Enclave/Keychain".to_owned()),
                    "{} must not list Apple Secure Enclave outside Swift",
                    algorithm.id
                );
            }
        }
    }
}

#[test]
fn platform_backend_matrix_is_generated_from_manifest() {
    let root = workspace_root();
    let status = Command::new("node")
        .arg("scripts/generate_provider_matrix.mjs")
        .arg("--check")
        .current_dir(root)
        .status()
        .expect("node can run provider matrix generator");

    assert!(
        status.success(),
        "PROVIDER_POLICY.md backend matrix is stale"
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_manifest(root: &Path) -> ProviderManifest {
    let bytes =
        fs::read(root.join("provider_manifest.json")).expect("provider_manifest.json is readable");
    serde_json::from_slice(&bytes).expect("provider_manifest.json matches the manifest schema")
}

fn package_algorithm_ids(manifest: &ProviderManifest) -> BTreeSet<String> {
    manifest
        .algorithms
        .iter()
        .filter(|algorithm| algorithm.package_api)
        .map(|algorithm| algorithm.id.clone())
        .collect()
}

fn resolved_algorithms(manifest: &ProviderManifest) -> Vec<ManifestAlgorithm> {
    let by_id: BTreeMap<&str, &ManifestAlgorithm> = manifest
        .algorithms
        .iter()
        .map(|algorithm| (algorithm.id.as_str(), algorithm))
        .collect();

    manifest
        .algorithms
        .iter()
        .map(|algorithm| resolve_algorithm(algorithm, &by_id, BTreeSet::new()))
        .collect()
}

fn resolve_algorithm(
    algorithm: &ManifestAlgorithm,
    by_id: &BTreeMap<&str, &ManifestAlgorithm>,
    mut seen: BTreeSet<String>,
) -> ManifestAlgorithm {
    if algorithm.lanes.is_some() {
        return algorithm.clone();
    }

    let source_id = algorithm
        .same_as
        .as_ref()
        .expect("manifest sameAs rows name their source algorithm");
    assert!(
        seen.insert(algorithm.id.clone()),
        "manifest sameAs cycle includes {}",
        algorithm.id
    );
    let source = by_id
        .get(source_id.as_str())
        .expect("manifest sameAs source exists");
    let resolved_source = resolve_algorithm(source, by_id, seen);
    ManifestAlgorithm {
        id: algorithm.id.clone(),
        family: algorithm.family.clone(),
        package_api: algorithm.package_api,
        lanes: resolved_source.lanes,
        same_as: None,
    }
}

fn lane_entries(algorithm: &ManifestAlgorithm) -> [(&'static str, &ManifestLane); 4] {
    let lanes = algorithm
        .lanes
        .as_ref()
        .expect("resolved algorithms have lanes");
    [
        (SWIFT_LANE, &lanes.swift),
        (KOTLIN_JVM_LANE, &lanes.kotlin_jvm),
        (KOTLIN_ANDROID_LANE, &lanes.kotlin_android),
        (TYPESCRIPT_WASM_LANE, &lanes.typescript_wasm),
    ]
}

fn find_algorithm<'a>(
    algorithms: &'a [ManifestAlgorithm],
    algorithm_id: &str,
) -> &'a ManifestAlgorithm {
    algorithms
        .iter()
        .find(|algorithm| algorithm.id == algorithm_id)
        .expect("manifest algorithm exists")
}

fn assert_catalog_covers(
    algorithm_id: &str,
    lane_name: &str,
    catalog: &BTreeSet<String>,
    lane: &ManifestLane,
) {
    for provider in &lane.providers {
        assert!(
            catalog.contains(provider),
            "{algorithm_id} names provider {provider} for {lane_name}, but the package catalog does not compile it"
        );
    }
}

fn quoted_strings(path: &Path) -> BTreeSet<String> {
    let source = fs::read_to_string(path).expect("source file is readable");
    let mut strings = BTreeSet::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for character in source.chars() {
        if in_string {
            if escaped {
                current.push(character);
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == '"' {
                strings.insert(current.clone());
                current.clear();
                in_string = false;
                continue;
            }
            current.push(character);
        } else if character == '"' {
            in_string = true;
        }
    }

    strings
}
