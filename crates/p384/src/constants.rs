// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Length in bytes of a raw P-384 scalar.
pub const P384_SECRET_KEY_LEN: usize = crypto_core::contract_constants::p384::P384_SECRET_KEY_LEN;
/// Length in bytes of a compressed SEC1 P-384 public key.
pub const P384_PUBLIC_KEY_COMPRESSED_LEN: usize =
    crypto_core::contract_constants::p384::P384_PUBLIC_KEY_COMPRESSED_LEN;
/// Length in bytes of an uncompressed SEC1 P-384 public key.
pub const P384_PUBLIC_KEY_UNCOMPRESSED_LEN: usize =
    crypto_core::contract_constants::p384::P384_PUBLIC_KEY_UNCOMPRESSED_LEN;
/// Length in bytes of a raw `X || Y` P-384 public key.
pub const P384_PUBLIC_KEY_RAW_LEN: usize =
    crypto_core::contract_constants::p384::P384_PUBLIC_KEY_RAW_LEN;
/// Length in bytes of the SEC 1 ECDH x-coordinate for P-384.
pub const P384_SHARED_SECRET_LEN: usize =
    crypto_core::contract_constants::p384::P384_SHARED_SECRET_LEN;
/// Conservative maximum length for a DER-encoded P-384 ECDSA signature.
pub const P384_SIGNATURE_DER_MAX_LEN: usize =
    crypto_core::contract_constants::p384::P384_SIGNATURE_DER_MAX_LEN;
