// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{allocate_secret_buffer, append_piece, DhKemBufferError};

#[test]
fn authenticated_mode_secret_buffer_never_reallocates_between_dh_outputs(
) -> Result<(), DhKemBufferError> {
    let mut output = allocate_secret_buffer(32, true)?;
    append_piece(&mut output, &[0x11; 32])?;
    let allocation = output.as_ptr();
    append_piece(&mut output, &[0x22; 32])?;

    assert_eq!(output.len(), 64);
    assert_eq!(output.as_ptr(), allocation);
    Ok(())
}
