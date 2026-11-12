// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

use super::SIGNATURE_LEN;

/// RFC 8032 dom4 with F=0 and an empty context. Ed448ph and contextual Ed448
/// deliberately have no entry point in this ordinary-signature contract.
pub(super) const DOMAIN: &[u8; 10] = b"SigEd448\0\0";
const MOST_SIGNIFICANT_SCALAR_OCTET: usize = 55;
const FINAL_SEED_OCTET: usize = 56;
const PRUNED_LOW_BITS_MASK: u8 = 0xfc;
const PRUNED_HIGH_BIT: u8 = 0x80;

pub(super) fn hash(parts: &[&[u8]]) -> Zeroizing<[u8; SIGNATURE_LEN]> {
    // SHAKE's zeroize feature clears both the absorbing state and reader.
    let mut state = Shake256::default();
    for part in parts {
        state.update(part);
    }
    let mut output = Zeroizing::new([0; SIGNATURE_LEN]);
    state.finalize_xof().read(output.as_mut());
    output
}

pub(super) fn expand(seed: &[u8]) -> Zeroizing<[u8; SIGNATURE_LEN]> {
    let mut expanded = hash(&[seed]);
    expanded[0] &= PRUNED_LOW_BITS_MASK;
    expanded[MOST_SIGNIFICANT_SCALAR_OCTET] |= PRUNED_HIGH_BIT;
    expanded[FINAL_SEED_OCTET] = 0;
    expanded
}
