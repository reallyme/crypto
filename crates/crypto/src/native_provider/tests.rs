// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::is_reviewed_release;

#[test]
fn affected_and_unreviewed_provider_versions_fail_closed() {
    for version in [
        0,
        0x1010_11ff,
        0x3000_0170,
        0x3040_0080,
        0x3050_0080,
        0x3060_0030,
        0x3060_0050,
        0x4000_0020,
        0x4020_0000,
    ] {
        assert!(!is_reviewed_release(version));
    }
    for version in [
        0x3050_0090,
        0x3050_00a0,
        0x4000_0030,
        0x4000_0040,
        0x4010_0000,
        0x4010_0010,
    ] {
        assert!(is_reviewed_release(version));
    }
}
