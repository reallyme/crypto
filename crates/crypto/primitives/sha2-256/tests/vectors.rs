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
pub struct Sha2_256Vector {
    pub message: &'static [u8],
    pub digest_hex: &'static str,
}

pub fn all_vectors() -> Vec<Sha2_256Vector> {
    vec![
        empty_message_vector(),
        abc_vector(),
        quick_brown_fox_vector(),
        quick_brown_fox_with_period_vector(),
    ]
}

pub fn empty_message_vector() -> Sha2_256Vector {
    Sha2_256Vector {
        message: b"",
        digest_hex: "e3b0c44298fc1c149afbf4c8996fb924\
                     27ae41e4649b934ca495991b7852b855",
    }
}

pub fn abc_vector() -> Sha2_256Vector {
    Sha2_256Vector {
        message: b"abc",
        digest_hex: "ba7816bf8f01cfea414140de5dae2223\
                     b00361a396177a9cb410ff61f20015ad",
    }
}

pub fn quick_brown_fox_vector() -> Sha2_256Vector {
    Sha2_256Vector {
        message: b"The quick brown fox jumps over the lazy dog",
        digest_hex: "d7a8fbb307d7809469ca9abcb0082e4f\
                     8d5651e46d3cdb762d02d0bf37c9e592",
    }
}

pub fn quick_brown_fox_with_period_vector() -> Sha2_256Vector {
    Sha2_256Vector {
        message: b"The quick brown fox jumps over the lazy dog.",
        digest_hex: "ef537f25c895bfa782526529a9b63d97\
                     aa631564d5d789c2b765448c8635fb6c",
    }
}
