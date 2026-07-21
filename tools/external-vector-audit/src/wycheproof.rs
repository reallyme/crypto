// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared schema helpers for Google/C2SP Wycheproof test vectors.
//!
//! Wycheproof files share a common envelope (`algorithm`, `testGroups`, and
//! per-test `result`) while the group and test shapes vary per primitive. This
//! module holds the shared pieces; each adapter defines the concrete group and
//! case structs it needs.

use serde::Deserialize;

/// The expected outcome Wycheproof records for a single test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum WycheproofResult {
    /// The operation must succeed and match the expected output.
    #[serde(rename = "valid")]
    Valid,
    /// The operation must be rejected.
    #[serde(rename = "invalid")]
    Invalid,
    /// Legal but discouraged (e.g. non-canonical or malleable). Each adapter
    /// applies the documented ReallyMe policy for the relevant flag; cases
    /// without a policy direction may be skipped.
    #[serde(rename = "acceptable")]
    Acceptable,
}

/// Top-level Wycheproof file, generic over the concrete test-group shape.
#[derive(Debug, Deserialize)]
pub struct WycheproofFile<G> {
    /// Upstream algorithm identifier (e.g. `CHACHA20-POLY1305`).
    pub algorithm: String,
    /// Test groups; the concrete `G` depends on the primitive.
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<G>,
}
