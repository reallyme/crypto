// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Produces the unique canonical byte string for a JSON value so that a
//! signature computed over the output verifies across independent
//! implementations. Correctness of two subtle areas — object member
//! ordering by UTF-16 code unit and ECMAScript-conformant number
//! serialization — is what makes that cross-stack guarantee hold; both are
//! implemented to the RFC and covered by conformance tests.

mod canonicalize;
mod error;

pub use canonicalize::canonicalize_json;
pub use error::JcsError;

/// Maximum array/object nesting depth accepted by [`canonicalize_json`].
///
/// Defense in depth: `serde_json`'s parser already caps nesting, but a
/// caller may hand in a `Value` built by other means, so canonicalization
/// enforces its own bound rather than trusting the input's provenance.
pub const MAX_NESTING_DEPTH: usize = 128;
