// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Owned protobuf representations; native key owners retain their secrecy APIs.

mod bytes;
mod json;
mod text;

pub use bytes::{PrivateBytes, SecretBytes};
pub use text::SecretString;

use buffa::{bytes::Buf, DecodeError, FieldPayload};
use zeroize::Zeroizing;

fn read_payload(payload: &mut FieldPayload<impl Buf>) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
    let mut output = Zeroizing::new(Vec::new());
    // Reserve the validated field length before writing any sensitive bytes.
    // Fragmented input therefore never enters the runtime's ordinary scratch.
    output
        .try_reserve_exact(payload.remaining())
        .map_err(|_| DecodeError::MessageTooLarge)?;
    while payload.has_remaining() {
        let chunk = payload.chunk();
        output.extend_from_slice(chunk);
        let length = chunk.len();
        payload.advance(length);
    }
    Ok(output)
}
