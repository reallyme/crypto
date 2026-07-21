// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

fn repo_root() -> Result<PathBuf, VectorTestError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
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
        if matches!(extension, "rs" | "swift" | "kt" | "ts" | "js" | "mjs") {
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
    ((trimmed.starts_with("use ") || trimmed.starts_with("pub use "))
        && trimmed.contains("::*"))
        || trimmed.starts_with("export *")
        || trimmed.starts_with("import * as ")
        || trimmed.starts_with("@_exported import ")
        || (trimmed.starts_with("import ") && trimmed.ends_with(".*"))
        || (trimmed.starts_with("import ") && trimmed.ends_with(".*;"))
}

fn path_is_generated(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "generated")
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
        let parsed = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse::<i32>(), |hex| i32::from_str_radix(hex, 16));
        let Ok(parsed) = parsed else {
            continue;
        };
        values.insert(name.to_owned(), parsed);
    }

    values
}

fn parse_proto_messages(proto: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut messages: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current_message: Option<String> = None;
    let mut depth = 0usize;

    for line in proto.lines() {
        let trimmed = line.trim();
        if current_message.is_none() {
            if let Some(message_name) = trimmed
                .strip_prefix("message ")
                .and_then(|rest| rest.strip_suffix(" {"))
            {
                current_message = Some(message_name.to_owned());
                depth = 1;
                messages.entry(message_name.to_owned()).or_default();
            }
            continue;
        }

        if let Some((field, _tag)) = trimmed.split_once(" = ") {
            if let Some(message_name) = current_message.as_ref() {
                let tokens = field.split_whitespace().collect::<Vec<_>>();
                if tokens.len() >= 2 {
                    let field_name = tokens[tokens.len() - 1].to_owned();
                    let field_type = tokens[..tokens.len() - 1].join(" ");
                    messages
                        .entry(message_name.to_owned())
                        .or_default()
                        .insert(field_name, field_type);
                }
            }
        }

        depth = depth.saturating_add(trimmed.matches('{').count());
        depth = depth.saturating_sub(trimmed.matches('}').count());
        if depth == 0 {
            current_message = None;
        }
    }

    messages
}

fn collect_ts_crypto_facade_methods(source: &str) -> BTreeSet<String> {
    let mut methods = BTreeSet::new();
    let mut in_facade = false;

    for line in source.lines() {
        if line.trim() == ") => ({" {
            in_facade = true;
            continue;
        }
        if !in_facade {
            continue;
        }
        if line.trim() == "} as const);" {
            break;
        }
        if line.starts_with("  ") && !line.starts_with("    ") {
            let trimmed = line.trim_start();
            if let Some((name, _rest)) = trimmed.split_once('(') {
                if name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    methods.insert(name.to_owned());
                }
            }
        }
    }

    methods
}

fn assert_message_fields(
    messages: &BTreeMap<String, BTreeMap<String, String>>,
    message_name: &str,
    expected_fields: &[(&str, &str)],
) -> Result<(), VectorTestError> {
    let actual_fields = messages
        .get(message_name)
        .ok_or(VectorTestError::InvalidField)?;
    let expected = expected_fields
        .iter()
        .map(|(field_name, field_type)| ((*field_name).to_owned(), (*field_type).to_owned()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        actual_fields, &expected,
        "{message_name} must capture exactly the protocol fields expected by the public facade"
    );
    Ok(())
}

fn is_plain_proto_byte_api_name(name: &str) -> bool {
    name.ends_with("Proto") && !name.ends_with("ToProto") && !name.ends_with("FromProto")
}

fn plain_proto_byte_apis(
    source: &str,
    declaration_prefix: &str,
    name_separator: char,
    signature_end: &str,
    byte_return_token: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut lines = source.lines().enumerate().peekable();

    while let Some((line_index, line)) = lines.next() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(declaration_prefix) else {
            continue;
        };
        let Some((name, _after_name)) = rest.split_once(name_separator) else {
            continue;
        };
        if !is_plain_proto_byte_api_name(name) {
            continue;
        }

        let mut signature = trimmed.to_owned();
        while !signature.contains(signature_end) {
            let Some((_next_index, next_line)) = lines.peek() else {
                break;
            };
            signature.push(' ');
            signature.push_str(next_line.trim());
            lines.next();
        }

        if signature.contains(byte_return_token) {
            violations.push(format!("line {}: {name}", line_index + 1));
        }
    }

    violations
}
