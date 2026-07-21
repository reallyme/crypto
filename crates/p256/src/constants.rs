// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Exact maximum length for a DER-encoded P-256 ECDSA signature.
///
/// Each scalar can require a 33-byte positive ASN.1 INTEGER, including its
/// leading sign-protection byte. Two INTEGER tag/length/value encodings plus
/// the enclosing SEQUENCE tag and length require at most 72 bytes.
pub const P256_SIGNATURE_DER_MAX_LEN: usize = 72;
