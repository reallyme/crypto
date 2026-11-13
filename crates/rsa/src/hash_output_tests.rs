// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{digest_message, digest_parts, FinalizedDigestBytes};
use crate::RsaHash;
use crypto_core::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn finalized_hash_storage_has_actual_cleanup_for_every_rsa_hash_width() {
    fn check<const N: usize>() {
        fn require_clearing<T: ZeroizeOnDrop>() {
            assert!(core::mem::needs_drop::<T>());
        }
        require_clearing::<FinalizedDigestBytes<[u8; N]>>();
        let mut digest = FinalizedDigestBytes([0xa5; N]);
        digest.zeroize();
        assert_eq!(digest.0, [0; N]);
    }
    check::<20>();
    check::<32>();
    check::<48>();
    check::<64>();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_rsa_hash_returns_clearing_owned_storage() -> Result<(), CryptoError> {
    fn require_clearing<T: ZeroizeOnDrop>(_: &T) {
        assert!(core::mem::needs_drop::<T>());
    }
    for (hash, length) in [
        (RsaHash::Sha1, 20),
        (RsaHash::Sha256, 32),
        (RsaHash::Sha384, 48),
        (RsaHash::Sha512, 64),
    ] {
        let output = digest_message(hash, b"abc")?;
        require_clearing(&output);
        assert_eq!(output.len(), length);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn borrowed_parts_retain_the_sha256_abc_known_answer() -> Result<(), CryptoError> {
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let output = digest_parts(RsaHash::Sha256, &[b"a", b"", b"bc"])?;
    assert_eq!(output.as_slice(), expected);
    Ok(())
}
