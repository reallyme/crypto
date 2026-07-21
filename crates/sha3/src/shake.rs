// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use shake::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Expand `input` with SHAKE256 into the caller-provided output buffer.
///
/// SHAKE256 is used by composite primitives such as X-Wing for deterministic
/// key expansion. The caller owns the output buffer so secret material can stay
/// inside that caller's zeroization model.
pub fn shake256_expand(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize_xof().read(output);
}
