// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of a raw P-384 scalar.
pub const P384_SECRET_KEY_LEN: usize = 48;
/// Length in bytes of a compressed SEC1 P-384 public key.
pub const P384_PUBLIC_KEY_COMPRESSED_LEN: usize = 49;
/// Length in bytes of an uncompressed SEC1 P-384 public key.
pub const P384_PUBLIC_KEY_UNCOMPRESSED_LEN: usize = 97;
/// Length in bytes of a raw `X || Y` P-384 public key.
pub const P384_PUBLIC_KEY_RAW_LEN: usize = 96;
/// Conservative maximum length for a DER-encoded P-384 ECDSA signature.
pub const P384_SIGNATURE_DER_MAX_LEN: usize = 104;
