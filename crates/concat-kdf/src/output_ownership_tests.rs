// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{FinalizedSha256Output, JwaConcatKdfOutput};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[test]
fn finalized_digest_and_final_output_have_live_clearing_owners() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<FinalizedSha256Output>();
    require_cleanup::<JwaConcatKdfOutput<17>>();
    let mut digest = FinalizedSha256Output {
        bytes: Sha256::digest(b"abc"),
    };
    assert_eq!(
        digest.bytes.as_slice(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
    let mut output = JwaConcatKdfOutput { bytes: [0u8; 17] };
    output.bytes.copy_from_slice(&digest.bytes[..17]);
    assert_eq!(output.as_bytes(), &digest.bytes[..17]);
    digest.zeroize();
    assert!(digest.bytes.iter().all(|byte| *byte == 0));
    // The independently owned final bytes survive clearing the staging owner.
    assert!(output.as_bytes().iter().any(|byte| *byte != 0));
    output.zeroize();
    assert!(output.as_bytes().iter().all(|byte| *byte == 0));
}
