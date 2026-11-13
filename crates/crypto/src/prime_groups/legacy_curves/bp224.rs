// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// RFC 5639 section 3.3.
// Standard cofactor-one parameters; deployment policy belongs to the caller.

define_legacy_curve! {
    curve: BrainpoolP224r1, uint: U256, bytes: U28,
    padding: "00000000",
    field: ("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 3),
    scalar: ("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 3),
    a: "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
    b: "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
    generator: ("0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d", "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd")
}
