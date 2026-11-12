// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generic EC signing in older provider releases has a nonce timing leak
// (CVE-2026-54872). Restrict the optional provider to maintained release
// families containing that fix. Existing portable backends do not use it.
const RELEASE_FAMILY_MASK: i64 = 0xfff0_0000;
const OPENSSL_35: i64 = 0x3050_0000;
const OPENSSL_40: i64 = 0x4000_0000;
const OPENSSL_41: i64 = 0x4010_0000;
const MIN_OPENSSL_35: i64 = 0x3050_0090;
const MIN_OPENSSL_40: i64 = 0x4000_0030;
const MIN_OPENSSL_41: i64 = 0x4010_0000;

pub(crate) fn is_available() -> bool {
    is_reviewed_release(openssl::version::number())
}

fn is_reviewed_release(version: i64) -> bool {
    match version & RELEASE_FAMILY_MASK {
        OPENSSL_35 => version >= MIN_OPENSSL_35,
        OPENSSL_40 => version >= MIN_OPENSSL_40,
        OPENSSL_41 => version >= MIN_OPENSSL_41,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
