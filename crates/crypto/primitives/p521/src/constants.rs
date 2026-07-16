// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of a raw P-521 scalar.
pub const P521_SECRET_KEY_LEN: usize = 66;
/// Length in bytes of a compressed SEC1 P-521 public key.
pub const P521_PUBLIC_KEY_COMPRESSED_LEN: usize = 67;
/// Length in bytes of an uncompressed SEC1 P-521 public key.
pub const P521_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 133;
/// Length in bytes of a raw `X || Y` P-521 public key.
pub const P521_PUBLIC_KEY_RAW_LEN: usize = 132;
/// Length in bytes of the SEC 1 ECDH x-coordinate for P-521.
pub const P521_SHARED_SECRET_LEN: usize = 66;
/// Conservative maximum length for a DER-encoded P-521 ECDSA signature.
pub const P521_SIGNATURE_DER_MAX_LEN: usize = 144;
