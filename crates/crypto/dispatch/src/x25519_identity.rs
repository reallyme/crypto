// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical X25519 encodings for identity-bearing envelopes.

const PUBLIC_KEY_LENGTH: usize = 32;
const FIELD_PRIME_LOW_BYTE: u8 = 0xed;
const FIELD_PRIME_HIGH_BYTE: u8 = 0x7f;

pub(crate) fn is_canonical(public_key: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LENGTH || public_key[31] > FIELD_PRIME_HIGH_BYTE {
        return false;
    }
    // RFC 7748 agreement accepts non-canonical field elements, but JWK and
    // multikey are identifiers. The 19 encodings from p through 2^255-1 must
    // not give the same key a second identity.
    public_key[31] != FIELD_PRIME_HIGH_BYTE
        || public_key[1..31].iter().any(|&byte| byte != 0xff)
        || public_key[0] < FIELD_PRIME_LOW_BYTE
}
