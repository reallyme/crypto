// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

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

const EXTERN_EXPORT_PREFIX: &str = "pub unsafe extern \"C\" fn rm_crypto_";

fn ffi_source_files() -> Vec<PathBuf> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let entries = fs::read_dir(src_dir).expect("ffi src directory should be readable");
    let mut files = Vec::new();

    for entry in entries {
        let path = entry.expect("directory entry should be readable").path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }

    files
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
