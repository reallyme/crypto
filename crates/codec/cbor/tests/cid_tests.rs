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
use codec_cbor::CborValue;
use codec_cbor::{
    compute_cid_dag_cbor, dag_cbor_multihash, encode_dag_cbor, is_valid_cid_string,
    sha2_256_content_hash, verify_dag_cbor_cid,
};

#[test]
fn deterministic_cid_for_same_input() {
    let v = CborValue::Map(vec![
        ("a".into(), CborValue::Int(1)),
        ("b".into(), CborValue::Bool(true)),
    ]);

    let b1 = encode_dag_cbor(&v);
    let b2 = encode_dag_cbor(&v);

    let cid1 = compute_cid_dag_cbor(&b1);
    let cid2 = compute_cid_dag_cbor(&b2);

    assert_eq!(cid1, cid2);
}

#[test]
fn different_inputs_produce_different_cids() {
    let cid1 = compute_cid_dag_cbor(&encode_dag_cbor(&CborValue::Int(1)));
    let cid2 = compute_cid_dag_cbor(&encode_dag_cbor(&CborValue::Int(2)));
    assert_ne!(cid1, cid2);
}

#[test]
fn verify_matching_cid() {
    let v = CborValue::Map(vec![("hello".into(), CborValue::String("world".into()))]);
    let bytes = encode_dag_cbor(&v);
    let cid = compute_cid_dag_cbor(&bytes);

    let (ok, _, _) = verify_dag_cbor_cid(&cid, &bytes);
    assert!(ok);
}

#[test]
fn detect_cid_mismatch() {
    let b1 = encode_dag_cbor(&CborValue::Int(1));
    let b2 = encode_dag_cbor(&CborValue::Int(2));

    let cid_wrong = compute_cid_dag_cbor(&b2);
    let (ok, _, _) = verify_dag_cbor_cid(&cid_wrong, &b1);

    assert!(!ok);
}

#[test]
fn cid_syntax_validation() {
    let v = encode_dag_cbor(&CborValue::Int(123));
    let cid = compute_cid_dag_cbor(&v);

    assert!(is_valid_cid_string(&cid));
    assert!(!is_valid_cid_string("not-a-cid"));
}

#[test]
fn content_hash_matches_dag_cbor_multihash_digest() {
    let bytes = encode_dag_cbor(&CborValue::String("dag-cbor hash".into()));
    let hash = sha2_256_content_hash(&bytes);
    let multihash = dag_cbor_multihash(&bytes);

    assert_eq!(multihash.code(), 0x12);
    assert_eq!(multihash.size(), 32);
    assert_eq!(multihash.digest(), hash);
}

#[test]
fn random_payloads_produce_valid_cids() {
    for i in 0..50 {
        let v = CborValue::Map(vec![("data".into(), CborValue::Bytes(vec![i; 32]))]);
        let cid = compute_cid_dag_cbor(&encode_dag_cbor(&v));
        assert!(is_valid_cid_string(&cid));
    }
}
