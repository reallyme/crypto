// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Secure Enclave handle format:
/// b"SE:" + UTF-8 tag bytes
pub const SE_HANDLE_PREFIX: &[u8] = b"SE:";

/// If `secret` is a Secure Enclave handle, return the tag bytes (UTF-8).
pub fn decode_se_handle(secret: &[u8]) -> Option<&[u8]> {
    secret.strip_prefix(SE_HANDLE_PREFIX)
}

/// Encode a tag into a Secure Enclave handle.
pub fn encode_se_handle(tag: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SE_HANDLE_PREFIX.len() + tag.len());
    out.extend_from_slice(SE_HANDLE_PREFIX);
    out.extend_from_slice(tag);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let tag = b"me.really.did.p256";
        let h = encode_se_handle(tag);

        assert_eq!(decode_se_handle(&h), Some(tag.as_slice()));
        assert_eq!(decode_se_handle(tag), None);
    }
}
