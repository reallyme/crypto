// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
use codec_cbor::{decode_dag_cbor, encode_dag_cbor, CborValue};

#[test]
fn null_roundtrip() {
    let v = CborValue::Null;
    assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
}

#[test]
fn boolean_roundtrip() {
    assert_eq!(
        decode_dag_cbor(&encode_dag_cbor(&CborValue::Bool(true))).unwrap(),
        CborValue::Bool(true)
    );
    assert_eq!(
        decode_dag_cbor(&encode_dag_cbor(&CborValue::Bool(false))).unwrap(),
        CborValue::Bool(false)
    );
}

#[test]
fn integer_roundtrip() {
    let cases = [0, 42, -1, -1000];
    for n in cases {
        let v = CborValue::Int(n);
        assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
    }
}

#[test]
fn string_roundtrip() {
    let v = CborValue::String("hello".into());
    assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
}

#[test]
fn byte_string_roundtrip() {
    let v = CborValue::Bytes(vec![1, 2, 3]);
    assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
}

#[test]
fn array_roundtrip() {
    let v = CborValue::Array(vec![
        CborValue::Int(1),
        CborValue::Bool(true),
        CborValue::String("x".into()),
        CborValue::Null,
    ]);
    assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
}

#[test]
fn map_keys_sorted_utf8() {
    let v = CborValue::Map(vec![
        ("b".into(), CborValue::Int(2)),
        ("a".into(), CborValue::Int(1)),
    ]);

    let encoded = encode_dag_cbor(&v);
    let decoded = decode_dag_cbor(&encoded).unwrap();

    assert_eq!(
        decoded,
        CborValue::Map(vec![
            ("a".into(), CborValue::Int(1)),
            ("b".into(), CborValue::Int(2)),
        ])
    );
}

#[test]
fn rejects_trailing_bytes() {
    let mut bytes = encode_dag_cbor(&CborValue::Int(42));
    bytes.push(0x00);
    assert!(decode_dag_cbor(&bytes).is_err());
}

#[test]
fn rejects_out_of_order_map() {
    // map(2) { "b":1, "a":2 }
    let bad = vec![0xA2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02];

    assert!(decode_dag_cbor(&bad).is_err());
}

#[test]
fn deep_nested_roundtrip() {
    let v = CborValue::Map(vec![(
        "a".into(),
        CborValue::Map(vec![(
            "b".into(),
            CborValue::Map(vec![(
                "c".into(),
                CborValue::Map(vec![(
                    "d".into(),
                    CborValue::Array(vec![
                        CborValue::Int(1),
                        CborValue::Int(2),
                        CborValue::Int(3),
                        CborValue::Map(vec![("x".into(), CborValue::Bool(true))]),
                    ]),
                )]),
            )]),
        )]),
    )]);

    assert_eq!(decode_dag_cbor(&encode_dag_cbor(&v)).unwrap(), v);
}

#[test]
fn rejects_duplicate_map_keys() {
    // map(2) { "a":1, "a":2 }
    let bad = vec![0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];

    assert!(decode_dag_cbor(&bad).is_err());
}

#[test]
fn rejects_cbor_tags() {
    // tag(1) followed by integer 42
    let bad = vec![
        0xC1, // major type 6 (tag), value 1
        0x18, 0x2A, // uint(42)
    ];

    assert!(decode_dag_cbor(&bad).is_err());
}

#[test]
fn rejects_indefinite_length_array() {
    // array(*) [ 1, 2 ]
    let bad = vec![
        0x9F, // array, indefinite length
        0x01, 0x02, 0xFF, // break
    ];

    assert!(decode_dag_cbor(&bad).is_err());
}

#[test]
fn rejects_indefinite_length_map() {
    // map(*) { "a": 1 }
    let bad = vec![
        0xBF, // map, indefinite length
        0x61, 0x61, 0x01, 0xFF,
    ];

    assert!(decode_dag_cbor(&bad).is_err());
}
