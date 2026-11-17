// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// X448 private scalar length from RFC 7748.
pub const X448_PRIVATE_KEY_LEN: usize = crypto_core::contract_constants::x448::X448_PRIVATE_KEY_LEN;
/// X448 public u-coordinate length from RFC 7748.
pub const X448_PUBLIC_KEY_LEN: usize = crypto_core::contract_constants::x448::X448_PUBLIC_KEY_LEN;
/// X448 raw shared-secret length from RFC 7748.
pub const X448_SHARED_SECRET_LEN: usize =
    crypto_core::contract_constants::x448::X448_SHARED_SECRET_LEN;

// RFC 7748 permits reduction of noncanonical coordinates modulo
// p = 2^448 - 2^224 - 1. These encodings reduce to the low-order points 0 and 1.
#[cfg(feature = "native")]
pub(crate) const FIELD_PRIME_LE: [u8; X448_PUBLIC_KEY_LEN] = {
    let mut bytes = [0xff; X448_PUBLIC_KEY_LEN];
    bytes[28] = 0xfe;
    bytes
};

#[cfg(feature = "native")]
pub(crate) const FIELD_PRIME_PLUS_ONE_LE: [u8; X448_PUBLIC_KEY_LEN] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
