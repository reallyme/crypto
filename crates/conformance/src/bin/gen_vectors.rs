// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic cross-lane conformance vector generator.

#[path = "gen_vectors/mod.rs"]
mod generator;

fn main() -> Result<(), generator::VectorGenError> {
    generator::run()
}
