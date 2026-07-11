// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::CborValue;

const MT_UINT: u8 = 0;
const MT_NEGINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_STRING: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;

/// Encode a value using canonical DAG-CBOR.
///
/// This encoding:
/// - uses definite-length, shortest-form (canonical) integer headers only
/// - orders map keys by RFC 8949 core deterministic rules: shorter encoded
///   key first, then bytewise lexical order among equal lengths
/// - contains no floats, tags, or indefinite-length items
/// - is deterministic and cryptographically stable, so equal values always
///   encode to identical bytes (a prerequisite for stable content IDs)
pub fn encode_dag_cbor(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out);
    out
}

fn encode_value(v: &CborValue, out: &mut Vec<u8>) {
    match v {
        CborValue::Null => out.push(0xf6),
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Bool(true) => out.push(0xf5),

        CborValue::Int(n) => {
            if *n >= 0 {
                write_header(MT_UINT, n.unsigned_abs(), out);
            } else {
                write_header(MT_NEGINT, n.unsigned_abs() - 1, out);
            }
        }

        CborValue::Bytes(b) => {
            write_header(MT_BYTES, len_as_u64(b.len()), out);
            out.extend_from_slice(b);
        }

        CborValue::String(s) => {
            let bytes = s.as_bytes();
            write_header(MT_STRING, len_as_u64(bytes.len()), out);
            out.extend_from_slice(bytes);
        }

        CborValue::Array(arr) => {
            write_header(MT_ARRAY, len_as_u64(arr.len()), out);
            for v in arr {
                encode_value(v, out);
            }
        }

        CborValue::Map(entries) => {
            // RFC 8949 core deterministic ordering sorts text keys by the
            // length of their encoded bytes first, then by bytewise lexical
            // order. did:me vectors rely on this exact order for stable CIDs.
            let mut sorted = entries.clone();
            sorted.sort_by(|(ka, _), (kb, _)| {
                ka.len()
                    .cmp(&kb.len())
                    .then_with(|| ka.as_bytes().cmp(kb.as_bytes()))
            });

            write_header(MT_MAP, len_as_u64(sorted.len()), out);

            for (k, v) in sorted {
                let kb = k.as_bytes();
                write_header(MT_STRING, len_as_u64(kb.len()), out);
                out.extend_from_slice(kb);
                encode_value(&v, out);
            }
        }
    }
}

/// Widens a container length to the `u64` argument width CBOR headers use.
///
/// This is a widening conversion — `usize` is at most 64 bits on every
/// supported target — so it never loses information; the saturating
/// fallback is unreachable and exists only to keep the conversion
/// total without an `as` cast or a panic.
fn len_as_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Writes a CBOR head byte plus the minimal big-endian argument encoding
/// for `value`, following canonical (shortest-form) integer rules.
///
/// Each branch slices the exact low-order bytes of `value.to_be_bytes()`
/// that its range guarantees are significant, so no narrowing cast or
/// truncation is involved.
fn write_header(mt: u8, value: u64, out: &mut Vec<u8>) {
    let be = value.to_be_bytes();
    let head = mt << 5;
    if value < 24 {
        // The whole argument fits in the low 5 bits of the head byte.
        out.push(head | be[7]);
    } else if value < 0x100 {
        out.push(head | 24);
        out.extend_from_slice(&be[7..8]);
    } else if value < 0x1_0000 {
        out.push(head | 25);
        out.extend_from_slice(&be[6..8]);
    } else if value < 0x1_0000_0000 {
        out.push(head | 26);
        out.extend_from_slice(&be[4..8]);
    } else {
        out.push(head | 27);
        out.extend_from_slice(&be);
    }
}
