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
