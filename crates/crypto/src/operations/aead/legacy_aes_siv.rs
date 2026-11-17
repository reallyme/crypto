// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only compatibility for records encrypted before the AEAD migration.

use crypto_core::CryptoError;
use zeroize::Zeroizing;

/// Authenticates and opens an AES-256-SIV record with an exact 64-byte key and
/// 16-byte nonce. No legacy encryption operation is exposed.
pub fn open_legacy_aes256_siv(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let _policy = crate::secret_material::bind_operation_policy(
        crate::secret_material::SecretMaterialOperation::AeadOpen,
    );
    #[cfg(all(feature = "legacy-aes-siv", any(feature = "native", feature = "wasm")))]
    {
        use aes_siv_backend::aead::KeyInit;
        const LEGACY_KEY_BYTES: usize = 64;
        const LEGACY_NONCE_BYTES: usize = 16;
        const LEGACY_TAG_BYTES: usize = 16;
        if key.len() != LEGACY_KEY_BYTES
            || nonce.len() != LEGACY_NONCE_BYTES
            || ciphertext.len() < LEGACY_TAG_BYTES
        {
            return Err(CryptoError::PRIMITIVE_INVALID_LENGTH);
        }
        let mut cipher = aes_siv_backend::siv::Aes256Siv::new_from_slice(key)
            .map_err(|_| CryptoError::PRIMITIVE_INVALID_KEY)?;
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        // The AEAD wrapper retains a raw key without drop cleanup. The lower
        // SIV owner clears its encryption key and the explicitly enabled CMAC
        // and AES providers clear their states. Preserve AEAD header ordering.
        cipher
            .decrypt_in_place([aad, nonce], &mut *plaintext)
            .map_err(|_| CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)?;
        Ok(plaintext)
    }
    #[cfg(not(all(feature = "legacy-aes-siv", any(feature = "native", feature = "wasm"))))]
    {
        let _ = (key, nonce, aad, ciphertext);
        Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

#[cfg(test)]
#[cfg(all(feature = "legacy-aes-siv", any(feature = "native", feature = "wasm")))]
#[path = "legacy_aes_siv_tests.rs"]
mod tests;

#[cfg(feature = "legacy-aes-siv")]
const _: fn() = || {
    fn requires_drop_cleanup<T: zeroize::ZeroizeOnDrop>() {}
    requires_drop_cleanup::<legacy_siv_aes::Aes256>();
    requires_drop_cleanup::<legacy_siv_cmac::block_api::CmacCore<legacy_siv_aes::Aes256>>();
    requires_drop_cleanup::<
        legacy_siv_cmac::digest::block_api::Buffer<
            legacy_siv_cmac::block_api::CmacCore<legacy_siv_aes::Aes256>,
        >,
    >();
    requires_drop_cleanup::<aes_siv_backend::siv::Aes256Siv>();
};
