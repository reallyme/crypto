// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Standards for Efficient Cryptography 2 (SEC 2), version 2.0, section 2.2.2.
// Standard cofactor-one parameters; deployment policy belongs to the caller.

define_legacy_curve! {
    curve: NistP192, uint: U192, bytes: U24,
    padding: "",
    field: ("fffffffffffffffffffffffffffffffeffffffffffffffff", 11),
    scalar: ("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 3),
    a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
    b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    generator: ("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", "07192b95ffc8da78631011ed6b24cdd573f977a11e794811")
}
