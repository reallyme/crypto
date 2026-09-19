// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Exact maximum length for a DER-encoded P-256 ECDSA signature.
///
/// Each scalar can require a 33-byte positive ASN.1 INTEGER, including its
/// leading sign-protection byte. Two INTEGER tag/length/value encodings plus
/// the enclosing SEQUENCE tag and length require at most 72 bytes.
pub const P256_SIGNATURE_DER_MAX_LEN: usize = 72;

/// Exact length of a P-256 secret scalar in bytes.
pub const P256_SECRET_KEY_LEN: usize = 32;

/// Exact length of the SHA-256 digest signed by ES256.
pub const P256_SHA256_DIGEST_LEN: usize = 32;
