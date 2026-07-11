// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
pub struct Sha3_256Vector {
    pub message: &'static [u8],
    pub digest_hex: &'static str,
}

pub fn all_vectors() -> Vec<Sha3_256Vector> {
    vec![
        empty_message_vector(),
        abc_vector(),
        quick_brown_fox_vector(),
        quick_brown_fox_with_period_vector(),
    ]
}

pub fn empty_message_vector() -> Sha3_256Vector {
    Sha3_256Vector {
        message: b"",
        digest_hex: "a7ffc6f8bf1ed76651c14756a061d662\
                     f580ff4de43b49fa82d80a4b80f8434a",
    }
}

pub fn abc_vector() -> Sha3_256Vector {
    Sha3_256Vector {
        message: b"abc",
        digest_hex: "3a985da74fe225b2045c172d6bd390bd\
                     855f086e3e9d525b46bfe24511431532",
    }
}

pub fn quick_brown_fox_vector() -> Sha3_256Vector {
    Sha3_256Vector {
        message: b"The quick brown fox jumps over the lazy dog",
        digest_hex: "69070dda01975c8c120c3aada1b28239\
                     4e7f032fa9cf32f4cb2259a0897dfc04",
    }
}

pub fn quick_brown_fox_with_period_vector() -> Sha3_256Vector {
    Sha3_256Vector {
        message: b"The quick brown fox jumps over the lazy dog.",
        digest_hex: "a80f839cd4f83f6c3dafc87feae47004\
                     5e4eb0d366397d5c6ce34ba1739f734d",
    }
}
