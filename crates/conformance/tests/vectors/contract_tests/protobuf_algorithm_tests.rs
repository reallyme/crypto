// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn protobuf_algorithm_enum_numbers_are_stable() -> Result<(), VectorTestError> {
    let proto = read_repo_file("crates/proto/proto/reallyme/crypto/v1/crypto.proto")?;
    let actual = parse_proto_enum_values(&proto, PROTO_ALGORITHM_ENUMS);
    let expected = PROTO_ENUM_VALUES
        .iter()
        .map(|(name, value)| ((*name).to_owned(), *value))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn every_public_algorithm_has_exactly_one_proto_selector() -> Result<(), VectorTestError> {
    let proto = read_repo_file("crates/proto/proto/reallyme/crypto/v1/crypto.proto")?;
    let proto_selectors = parse_proto_enum_values(&proto, PUBLIC_ALGORITHM_PROTO_ENUMS)
        .into_keys()
        .filter(|name| !name.ends_with("_UNSPECIFIED"))
        .collect::<BTreeSet<_>>();

    let mapped_proto_selectors = PUBLIC_ALGORITHM_PROTO_MAPPING
        .iter()
        .map(|(proto_name, _algorithm_id)| (*proto_name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        mapped_proto_selectors.len(),
        PUBLIC_ALGORITHM_PROTO_MAPPING.len(),
        "a protobuf selector is mapped more than once"
    );
    assert_eq!(proto_selectors, mapped_proto_selectors);
    assert!(
        proto.contains("message HpkeSuiteIdentifier"),
        "public HPKE profiles require the typed component identifier message"
    );

    let manifest_source = read_repo_file("provider_manifest.json")?;
    let manifest: Value =
        serde_json::from_str(&manifest_source).map_err(|_| VectorTestError::ParseVector)?;
    let manifest_algorithms = field_array(&manifest, "algorithms")?;
    let public_algorithm_ids = manifest_algorithms
        .iter()
        .filter(|algorithm| {
            algorithm
                .get("packageApi")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|algorithm| field_string(algorithm, "id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mapped_algorithm_ids = PUBLIC_ALGORITHM_PROTO_MAPPING
        .iter()
        .map(|(_proto_name, algorithm_id)| (*algorithm_id).to_owned())
        .chain(
            PUBLIC_HPKE_PROTO_PROFILE_MAPPING
                .iter()
                .map(|algorithm_id| (*algorithm_id).to_owned()),
        )
        .collect::<BTreeSet<_>>();
    let expected_mapping_count = PUBLIC_ALGORITHM_PROTO_MAPPING
        .len()
        .checked_add(PUBLIC_HPKE_PROTO_PROFILE_MAPPING.len())
        .ok_or(VectorTestError::InvalidField)?;
    assert_eq!(
        mapped_algorithm_ids.len(),
        expected_mapping_count,
        "a public algorithm is mapped more than once"
    );
    assert_eq!(public_algorithm_ids, mapped_algorithm_ids);

    Ok(())
}

#[test]
fn protobuf_byte_helpers_do_not_use_plain_proto_names() -> Result<(), VectorTestError> {
    let ts = read_repo_file("packages/ts/src/proto.ts")?;
    let kotlin =
        read_repo_file("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt")?;
    let swift =
        read_repo_file("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift")?;

    let mut violations = Vec::new();
    violations.extend(
        plain_proto_byte_apis(&ts, "export const ", ' ', "=>", "Uint8Array")
            .into_iter()
            .map(|name| format!("TypeScript {name}")),
    );
    violations.extend(
        plain_proto_byte_apis(&kotlin, "public fun ", '(', "=", "ByteArray")
            .into_iter()
            .map(|name| format!("Kotlin {name}")),
    );
    violations.extend(
        plain_proto_byte_apis(&swift, "public static func ", '(', "{", "[UInt8]")
            .into_iter()
            .map(|name| format!("Swift {name}")),
    );

    assert!(
        violations.is_empty(),
        "protobuf byte-returning APIs must use explicit ToProtoBytes/FromProtoBytes names, \
         not plain *Proto names that can be confused with success-or-error envelopes: {violations:?}"
    );

    Ok(())
}
