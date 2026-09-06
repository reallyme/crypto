// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret-aware replacement of generated protobuf scalar fields.

use buffa::{bytes::Buf, DecodeError};
use zeroize::Zeroize;

pub(crate) fn merge_bytes(value: &mut Vec<u8>, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Protobuf permits repeated singular fields (last value wins). Buffa clears
    // the old length without wiping the storage, leaving truncated secret bytes
    // in spare capacity or freeing them during growth. Wipe before either can
    // happen. Wipe only the live value: wiping retained capacity on every
    // duplicate makes a large field followed by many empty fields quadratic.
    value.as_mut_slice().zeroize();
    value.clear();
    let result = buffa::types::merge_bytes(value, buf);
    if result.is_err() {
        value.zeroize();
    }
    result
}

pub(crate) fn merge_string(value: &mut String, buf: &mut impl Buf) -> Result<(), DecodeError> {
    // Authentication prompts are privacy-bearing even though they are strings.
    value.as_mut_str().zeroize();
    value.clear();
    let result = buffa::types::merge_string(value, buf);
    if result.is_err() {
        // A fragmented input may have been copied before UTF-8 validation
        // clears its length. Wipe spare capacity on this terminal error path.
        value.zeroize();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{merge_bytes, merge_string};

    #[test]
    #[allow(unsafe_code)]
    fn shrinking_a_byte_field_wipes_the_previous_initialized_tail() -> Result<(), buffa::DecodeError>
    {
        let mut value = vec![0xa5; 64];
        let allocation = value.as_ptr();
        merge_bytes(&mut value, &mut &[1, 7][..])?;
        assert_eq!(value, [7]);
        assert_eq!(value.as_ptr(), allocation);
        // SAFETY: The same allocation is retained, and all 64 bytes were
        // initialized before the merge. There is no mutation while borrowed;
        // this test observes only the live allocation, never freed memory.
        let initialized_storage = unsafe { core::slice::from_raw_parts(value.as_ptr(), 64) };
        assert!(initialized_storage[1..].iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn replacement_and_empty_values_preserve_last_value_wins() -> Result<(), buffa::DecodeError> {
        let mut bytes = vec![1];
        merge_bytes(&mut bytes, &mut &[3, 2, 3, 4][..])?;
        assert_eq!(bytes, [2, 3, 4]);
        merge_bytes(&mut bytes, &mut &[0][..])?;
        assert!(bytes.is_empty());
        let mut text = String::from("private prompt");
        merge_string(&mut text, &mut &[2, b'o', b'k'][..])?;
        assert_eq!(text, "ok");
        merge_string(&mut text, &mut &[0][..])?;
        assert!(text.is_empty());
        Ok(())
    }

    #[test]
    fn malformed_replacements_do_not_retain_old_secrets() {
        let mut bytes = vec![0xa5; 32];
        assert!(merge_bytes(&mut bytes, &mut &[2, 1][..]).is_err());
        assert!(bytes.is_empty());
        let mut text = String::from("private prompt");
        assert!(merge_string(&mut text, &mut &[1, 0xff][..]).is_err());
        assert!(text.is_empty());
    }

    #[test]
    #[allow(unsafe_code)]
    fn successful_replacements_do_not_repeatedly_wipe_spare_capacity(
    ) -> Result<(), buffa::DecodeError> {
        let mut bytes = Vec::with_capacity(64);
        bytes.push(7);
        // A sentinel in initialized spare storage makes this an operation-count
        // regression check without a flaky wall-clock performance assertion.
        bytes.spare_capacity_mut()[0].write(0xa5);
        for _ in 0..128 {
            merge_bytes(&mut bytes, &mut &[1, 9][..])?;
        }
        // SAFETY: Index 1 was initialized above, is in the retained allocation,
        // and is observed only after all mutations have finished.
        assert_eq!(unsafe { *bytes.as_ptr().add(1) }, 0xa5);
        assert_eq!(bytes, [9]);
        Ok(())
    }

    #[test]
    #[allow(unsafe_code)]
    fn fragmented_invalid_utf8_wipes_copied_bytes() {
        use buffa::bytes::Buf;

        let mut text = String::with_capacity(64);
        text.push_str("old secret");
        let mut input = (&[3, b'a'][..]).chain(&[b'b', 0xff][..]);
        assert!(merge_string(&mut text, &mut input).is_err());
        assert!(text.is_empty());
        // SAFETY: The first three bytes were initialized by the fragmented
        // merge; the allocation is still live and is not mutated while read.
        let copied = unsafe { core::slice::from_raw_parts(text.as_ptr(), 3) };
        assert_eq!(copied, [0, 0, 0]);
    }
}
