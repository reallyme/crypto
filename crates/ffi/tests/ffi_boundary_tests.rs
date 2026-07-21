// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn ffi_manifest_uses_the_facade_instead_of_primitive_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let forbidden_dependencies = [
        "crypto-argon2id =",
        "crypto-csprng =",
        "crypto-ed25519 =",
        "crypto-hkdf =",
        "crypto-hpke =",
        "crypto-kmac =",
        "crypto-ml-dsa-",
        "crypto-ml-kem-",
        "crypto-p256 =",
        "crypto-p384 =",
        "crypto-p521 =",
        "crypto-pbkdf2 =",
        "crypto-rsa =",
        "crypto-secp256k1 =",
        "crypto-slh-dsa =",
        "crypto-x25519 =",
        "crypto-x-wing =",
    ];

    assert!(manifest.contains("reallyme-crypto ="));
    for dependency in forbidden_dependencies {
        assert!(
            !manifest.contains(dependency),
            "FFI must reach primitive implementations through reallyme-crypto, not {dependency}"
        );
    }
}

#[test]
fn primary_kotlin_operation_bridge_calls_the_rust_operation_boundary_once() {
    let source = include_str!("../src/kotlin_proto.rs");
    let primary_start = source
        .find("fn process_operation_response<'local>")
        .expect("primary Kotlin operation bridge should exist");
    let primary_bridge = &source[primary_start..];

    assert!(source.contains("reallyme_crypto::operation_contract"));
    assert!(!source.contains("process_proto_envelope"));
    assert!(primary_bridge.contains("let output = process(request.as_slice())"));
    assert!(!primary_bridge.contains("process_output("));
    assert!(!primary_bridge.contains("rm_crypto_process_"));
}

#[test]
fn variable_length_csprng_commits_output_only_after_successful_fill() {
    let source = include_str!("../src/csprng.rs");
    let start = source
        .find("pub unsafe extern \"C\" fn rm_crypto_csprng_generate_bytes")
        .expect("variable-length CSPRNG export should exist");
    let body = exported_function_body(source, start)
        .expect("variable-length CSPRNG export should have balanced braces");
    let fill = body
        .find("operations::random::fill_bytes")
        .expect("CSPRNG export should fill through the operation layer");
    let commit = body
        .rfind("write_fixed(output_out")
        .expect("CSPRNG export should commit through the pointer helper");

    assert!(body.contains("Zeroizing::new(Vec::new())"));
    assert!(body.contains("try_reserve_exact(output_out_len)"));
    assert!(
        fill < commit,
        "caller output must be committed only after RNG success"
    );
    assert!(!body.contains("fill_bytes(output"));
}

#[test]
fn kotlin_byte_arrays_are_bounded_before_native_copy() {
    let aead = include_str!("../src/kotlin_aead.rs");
    let argon2id = include_str!("../src/kotlin_argon2id.rs");

    assert!(aead.contains("MAX_JNI_BYTE_INPUT_LENGTH"));
    assert!(aead.contains("let key_len = match key.len(env)"));
    assert!(aead.contains("let plaintext_len = match plaintext.len(env)"));
    assert!(aead.contains("let ciphertext_len = match ciphertext.len(env)"));
    assert!(
        aead.find("plaintext.len(env)")
            .expect("plaintext length preflight should exist")
            < aead
                .find("convert_byte_array(&plaintext)")
                .expect("plaintext copy should exist")
    );
    assert!(
        aead.find("ciphertext.len(env)")
            .expect("ciphertext length preflight should exist")
            < aead
                .find("convert_byte_array(&ciphertext)")
                .expect("ciphertext copy should exist")
    );

    assert!(argon2id.contains("ARGON2ID_SECRET_MAX_LENGTH"));
    assert!(
        argon2id
            .find("secret.len(env)")
            .expect("secret length preflight should exist")
            < argon2id
                .find("convert_byte_array(&secret)")
                .expect("secret copy should exist")
    );
    assert!(
        argon2id
            .find("salt.len(env)")
            .expect("salt length preflight should exist")
            < argon2id
                .find("convert_byte_array(&salt)")
                .expect("salt copy should exist")
    );
}

#[test]
fn raw_slice_construction_stays_in_pointer_module() {
    for source_path in ffi_source_files() {
        if source_path.file_name().and_then(|name| name.to_str()) == Some("pointer.rs") {
            continue;
        }

        let source = fs::read_to_string(&source_path).expect("source file should be readable");
        assert!(
            !source.contains("from_raw_parts"),
            "{} must use pointer.rs for raw pointer/length validation",
            source_path.display()
        );
        assert!(
            !source.contains("from_raw_parts_mut"),
            "{} must use pointer.rs for raw pointer/length validation",
            source_path.display()
        );
    }
}

#[test]
fn raw_null_pointer_checks_stay_in_pointer_module() {
    for source_path in ffi_source_files() {
        if source_path.file_name().and_then(|name| name.to_str()) == Some("pointer.rs") {
            continue;
        }

        let source = fs::read_to_string(&source_path).expect("source file should be readable");
        assert!(
            !source.contains(".is_null()"),
            "{} must use pointer.rs for raw pointer validation",
            source_path.display()
        );
    }
}

#[test]
fn exported_ffi_symbols_route_through_panic_guard() {
    for source_path in ffi_source_files() {
        let source = fs::read_to_string(&source_path).expect("source file should be readable");
        let mut search_from = 0_usize;

        while let Some(relative_start) = source[search_from..].find(EXTERN_EXPORT_PREFIX) {
            let start = search_from
                .checked_add(relative_start)
                .expect("search offset should not overflow");
            let body = exported_function_body(&source, start)
                .expect("exported function body should have balanced braces");
            assert!(
                body.contains("ffi_guard(||"),
                "{} export at byte {} must route through ffi_guard",
                source_path.display(),
                start
            );
            search_from = start
                .checked_add(body.len())
                .expect("search offset should not overflow");
        }
    }
}

#[test]
fn release_packaging_requires_the_unwind_capable_profile() {
    let workspace_manifest = include_str!("../../../Cargo.toml");
    let ffi_manifest = include_str!("../Cargo.toml");
    let ffi_root = include_str!("../src/lib.rs");
    let kotlin_script = include_str!("../../../scripts/build_kotlin_native_resource.sh");
    let android_script = include_str!("../../../scripts/build_android_native_resources.sh");
    let swift_script = include_str!("../../../scripts/build_swift_xcframework.sh");

    assert!(workspace_manifest.contains("[profile.release-ffi]"));
    assert!(workspace_manifest.contains("panic = \"unwind\""));
    assert!(!ffi_manifest.contains("require-unwind"));
    assert!(ffi_root.contains("#[cfg(not(panic = \"unwind\"))]"));

    for script in [kotlin_script, android_script, swift_script] {
        assert!(script.contains("--profile release-ffi"));
        assert!(!script.contains("-C panic=unwind"));
        assert!(script.contains("unset CARGO_ENCODED_RUSTFLAGS"));
    }
}

#[test]
fn exported_c_abi_functions_do_not_call_other_c_abi_exports() {
    for source_path in ffi_source_files() {
        let source = fs::read_to_string(&source_path).expect("source file should be readable");
        let mut search_from = 0_usize;

        while let Some(relative_start) = source[search_from..].find(EXTERN_EXPORT_PREFIX) {
            let start = search_from
                .checked_add(relative_start)
                .expect("search offset should not overflow");
            let body = exported_function_body(&source, start)
                .expect("exported function body should have balanced braces");
            assert!(
                !body.contains("rm_crypto_"),
                "{} export at byte {} must call the operation layer, not another C ABI export",
                source_path.display(),
                start
            );
            search_from = start
                .checked_add(body.len())
                .expect("search offset should not overflow");
        }
    }
}

#[test]
fn header_declares_every_exported_ffi_symbol() {
    let header = include_str!("../abi/reallyme_crypto_ffi.h");
    let conformance_only_symbols = [
        "rm_crypto_ml_kem_512_encapsulate_derand",
        "rm_crypto_ml_kem_768_encapsulate_derand",
        "rm_crypto_ml_kem_1024_encapsulate_derand",
        "rm_crypto_x_wing_768_encapsulate_derand",
    ];

    for source_path in ffi_source_files() {
        let source = fs::read_to_string(&source_path).expect("source file should be readable");
        for symbol in exported_ffi_symbol_names(&source) {
            if conformance_only_symbols.contains(&symbol) {
                assert!(
                    source.contains(&format!(
                        "#[cfg(feature = \"test-vectors\")]\npub unsafe extern \"C\" fn {symbol}"
                    )),
                    "conformance-only symbol {symbol} must remain feature-gated"
                );
                assert!(
                    !header.contains(symbol),
                    "release header must not declare conformance-only symbol {symbol}"
                );
                continue;
            }
            assert!(
                header.contains(symbol),
                "header is missing exported FFI symbol {symbol} from {}",
                source_path.display()
            );
        }
    }
}

const EXTERN_EXPORT_PREFIX: &str = "pub unsafe extern \"C\" fn";

fn ffi_source_files() -> Vec<PathBuf> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_source_files(&src_dir, &mut files);
    files.sort();
    files
}

fn collect_rust_source_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).expect("ffi source directory should be readable");
    for entry in entries {
        let path = entry.expect("directory entry should be readable").path();
        if path.is_dir() {
            collect_rust_source_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn exported_function_body(source: &str, function_start: usize) -> Option<&str> {
    let body_start_relative = source[function_start..]
        .find('{')
        .expect("exported function should have a body");
    let body_start = function_start
        .checked_add(body_start_relative)
        .expect("body start should not overflow");
    let mut depth = 0_usize;

    for (relative_index, character) in source[body_start..].char_indices() {
        match character {
            '{' => {
                depth = depth
                    .checked_add(1)
                    .expect("brace depth should not overflow");
            }
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("brace depth should not underflow");
                if depth == 0 {
                    let body_end = body_start
                        .checked_add(relative_index)
                        .and_then(|value| value.checked_add(character.len_utf8()))
                        .expect("body end should not overflow");
                    return Some(&source[body_start..body_end]);
                }
            }
            _ => {}
        }
    }

    None
}

fn exported_ffi_symbol_names(source: &str) -> Vec<&str> {
    let mut symbols = Vec::new();
    let mut search_from = 0_usize;

    while let Some(relative_start) = source[search_from..].find("rm_crypto_") {
        let start = search_from
            .checked_add(relative_start)
            .expect("search offset should not overflow");
        let name_end_relative = source[start..]
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(source.len() - start);
        let name_end = start
            .checked_add(name_end_relative)
            .expect("name end should not overflow");
        let symbol = &source[start..name_end];
        if !symbols.contains(&symbol) {
            symbols.push(symbol);
        }
        search_from = name_end;
    }

    symbols
}
