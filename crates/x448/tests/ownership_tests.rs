// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]
#![cfg(feature = "native")]

use crypto_core::CryptoError;
use crypto_x448::{
    derive_x448_shared_secret, X448PrivateKey, X448PublicKey, X448SharedSecret,
    X448_PRIVATE_KEY_LEN,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn private_and_shared_owners_keep_drop_cleanup() {
    fn require_cleanup<T: ZeroizeOnDrop>() {}
    require_cleanup::<X448PrivateKey>();
    require_cleanup::<X448SharedSecret>();
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn slice_import_keeps_caller_storage_and_matches_array_import() -> Result<(), CryptoError> {
    let seed = Zeroizing::new([7_u8; X448_PRIVATE_KEY_LEN]);
    let imported = X448PrivateKey::from_bytes(seed.as_ref())?;
    let array = X448PrivateKey::from_array(*seed);
    assert_eq!(X448PublicKey::from(&imported), X448PublicKey::from(&array));
    assert_eq!(*seed, [7; X448_PRIVATE_KEY_LEN]);
    for length in [0, 1, 55, 57] {
        let source = Zeroizing::new(vec![7; length]);
        assert!(
            matches!(X448PrivateKey::from_bytes(&source),Err(error) if error==CryptoError::PRIMITIVE_INVALID_KEY)
        );
        assert!(source.iter().all(|value| *value == 7));
    }
    Ok(())
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn explicit_zeroization_observes_live_owners_only() -> Result<(), CryptoError> {
    let mut private = X448PrivateKey::from_array([9; X448_PRIVATE_KEY_LEN]);
    let peer = X448PrivateKey::from_array([11; X448_PRIVATE_KEY_LEN]);
    let mut shared = derive_x448_shared_secret(&private, X448PublicKey::from(&peer))?;
    shared.zeroize();
    assert!(shared.as_bytes().iter().all(|byte| *byte == 0));
    private.zeroize();
    assert!(private.as_bytes().iter().all(|byte| *byte == 0));
    Ok(())
}
