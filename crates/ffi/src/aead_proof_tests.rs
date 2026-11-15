// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crypto_core::{AeadAlgorithm, CryptoError};
use reallyme_crypto::hpke::{HpkeOpenOutput, HpkeOpenRequest};
use zeroize::Zeroizing;

use crate::aes256_gcm;
use crate::aes256_gcm_siv;
use crate::chacha20_poly1305;
use crate::hpke;
use crate::status::{CryptoStatus, CRYPTO_AUTHENTICATION_FAILED};

// Kani resolves stubs by name after normal Rust use checking.
#[allow(unused_imports)]
use {
    super::{
        register_input_range, register_output_range, validate_disjoint_ranges,
        validate_registered_inputs_against_output, OutputRangeKind,
    },
    crate::guard::ffi_guard,
};

const TAG_LEN: usize = aes256_gcm::AES128_GCM_TAG_LEN;
const CIPHERTEXT_LEN: usize = 4;
const RECORD_LEN: usize = CIPHERTEXT_LEN + TAG_LEN;
const OUTPUT_CAPACITY: usize = CIPHERTEXT_LEN + 2;

const _: () = {
    assert!(TAG_LEN == aes256_gcm::AES192_GCM_TAG_LEN);
    assert!(TAG_LEN == aes256_gcm::AES256_GCM_TAG_LEN);
    assert!(TAG_LEN == aes256_gcm_siv::AES256_GCM_SIV_TAG_LEN);
    assert!(TAG_LEN == chacha20_poly1305::CHACHA20_POLY1305_TAG_LEN);
    assert!(TAG_LEN == hpke::HPKE_FFI_AEAD_TAG_LEN);
};

type Decrypt = unsafe extern "C" fn(
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> CryptoStatus;

// The harness owns live, disjoint allocations for the duration of the call.
// Exercise the operation body with the guard's normal return semantics.
#[allow(dead_code)]
fn model_ffi_guard<F: FnOnce() -> CryptoStatus>(operation: F) -> CryptoStatus {
    operation()
}

// The harness establishes non-overlap by constructing separate allocations.
// Model successful overlap checks so the verifier can focus on output writes.
#[allow(dead_code)]
fn model_register_input_range(_ptr: *const u8, _len: usize) -> Result<(), CryptoStatus> {
    Ok(())
}

#[allow(dead_code)]
fn model_register_output_range<T>(
    _ptr: *mut T,
    _len: usize,
    _kind: OutputRangeKind,
) -> Result<(), CryptoStatus> {
    Ok(())
}

#[allow(dead_code)]
fn model_validate_registered_inputs<T>(_ptr: *mut T, _len: usize) -> Result<(), CryptoStatus> {
    Ok(())
}

#[allow(dead_code)]
fn model_disjoint_ranges(
    _read_ptr: *const u8,
    _read_len: usize,
    _write_ptr: *mut u8,
    _write_len: usize,
) -> Result<(), CryptoStatus> {
    Ok(())
}

// Model the separately verified staging helper's failure handoff. A backend
// may replace any subset of the ciphertext bytes before reporting failure.
#[allow(dead_code)]
fn model_open(
    _algorithm: AeadAlgorithm,
    _key: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    reject_after_backend_write(record)
}

#[allow(dead_code)]
fn model_hpke_open(request: &HpkeOpenRequest<'_>) -> Result<HpkeOpenOutput, CryptoError> {
    reject_after_backend_write(request.ciphertext)
}

fn reject_after_backend_write<T>(record: &[u8]) -> Result<T, CryptoError> {
    let Some((ciphertext, _)) = record.split_last_chunk::<TAG_LEN>() else {
        return Err(CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT);
    };
    let Ok(ciphertext) = <[u8; CIPHERTEXT_LEN]>::try_from(ciphertext) else {
        return Err(CryptoError::PRIMITIVE_MALFORMED_CIPHERTEXT);
    };
    let mut staging = Zeroizing::new(ciphertext);
    let candidate: [u8; CIPHERTEXT_LEN] = kani::any();
    let written: [bool; CIPHERTEXT_LEN] = kani::any();
    for (index, write) in written.into_iter().enumerate() {
        if write {
            staging[index] = candidate[index];
        }
    }
    kani::cover!(
        *staging != ciphertext
            && written != [false; CIPHERTEXT_LEN]
            && written != [true; CIPHERTEXT_LEN],
        "authentication failure after a partial write"
    );
    kani::cover!(
        *staging != ciphertext && written == [true; CIPHERTEXT_LEN],
        "authentication failure after a complete write"
    );
    Err(CryptoError::PRIMITIVE_AUTHENTICATION_FAILED)
}

struct PlaintextOutput {
    bytes: [u8; OUTPUT_CAPACITY],
    len: usize,
}

impl PlaintextOutput {
    fn check_failure(call: impl FnOnce(&mut Self) -> CryptoStatus) {
        let original_bytes: [u8; OUTPUT_CAPACITY] = kani::any();
        let original_len = kani::any();
        let mut output = Self {
            bytes: original_bytes,
            len: original_len,
        };

        assert_eq!(call(&mut output), CRYPTO_AUTHENTICATION_FAILED);
        assert_eq!(output.len, original_len);
        assert_eq!(output.bytes, original_bytes);
    }
}

fn check_authentication_failure<const KEY_LEN: usize, const NONCE_LEN: usize>(decrypt: Decrypt) {
    let key = [0; KEY_LEN];
    let nonce = [0; NONCE_LEN];
    let record: [u8; RECORD_LEN] = kani::any();
    let aad: [u8; 1] = kani::any();

    // SAFETY: The inputs are initialized and live throughout the call.
    // The byte array and length slot are disjoint and exclusively borrowed.
    PlaintextOutput::check_failure(|output| unsafe {
        decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            record.as_ptr(),
            record.len(),
            output.bytes.as_mut_ptr(),
            output.bytes.len(),
            &mut output.len,
        )
    });
}

fn check_hpke_authentication_failure<const ENCAPSULATED_LEN: usize, const KEY_LEN: usize>(
    suite: u32,
) {
    let encapsulated_key = [0; ENCAPSULATED_LEN];
    let private_key = [0; KEY_LEN];
    let record: [u8; RECORD_LEN] = kani::any();
    let info: [u8; 1] = kani::any();
    let aad: [u8; 1] = kani::any();

    // SAFETY: The inputs are initialized and live throughout the call.
    // The byte array and length slot are disjoint and exclusively borrowed.
    PlaintextOutput::check_failure(|output| unsafe {
        hpke::rm_crypto_hpke_open_base(
            suite,
            encapsulated_key.as_ptr(),
            encapsulated_key.len(),
            private_key.as_ptr(),
            private_key.len(),
            info.as_ptr(),
            info.len(),
            aad.as_ptr(),
            aad.len(),
            record.as_ptr(),
            record.len(),
            output.bytes.as_mut_ptr(),
            output.bytes.len(),
            &mut output.len,
        )
    });
}

kani::stub_set!(
    valid_disjoint_call,
    stub(ffi_guard, model_ffi_guard),
    stub(register_input_range, model_register_input_range),
    stub(register_output_range, model_register_output_range),
    stub(validate_disjoint_ranges, model_disjoint_ranges),
    stub(
        validate_registered_inputs_against_output,
        model_validate_registered_inputs
    ),
);

macro_rules! prove_authentication_failure {
    ($harness:ident, $decrypt:path, $key_len:path, $nonce_len:path) => {
        #[kani::proof]
        // The typed key is cleared on return, including its 32-byte variants.
        #[kani::unwind(33)]
        #[kani::use_stub_set(valid_disjoint_call)]
        #[kani::stub(reallyme_crypto::operations::aead::open, model_open)]
        fn $harness() {
            check_authentication_failure::<{ $key_len }, { $nonce_len }>($decrypt);
        }
    };
}

prove_authentication_failure!(
    aes128_gcm_preserves_outputs_on_failure,
    aes256_gcm::rm_crypto_aes128_gcm_decrypt,
    aes256_gcm::AES128_GCM_KEY_LEN,
    aes256_gcm::AES128_GCM_NONCE_LEN
);
prove_authentication_failure!(
    aes192_gcm_preserves_outputs_on_failure,
    aes256_gcm::rm_crypto_aes192_gcm_decrypt,
    aes256_gcm::AES192_GCM_KEY_LEN,
    aes256_gcm::AES192_GCM_NONCE_LEN
);
prove_authentication_failure!(
    aes256_gcm_preserves_outputs_on_failure,
    aes256_gcm::rm_crypto_aes256_gcm_decrypt,
    aes256_gcm::AES256_GCM_KEY_LEN,
    aes256_gcm::AES256_GCM_NONCE_LEN
);
prove_authentication_failure!(
    aes256_gcm_siv_preserves_outputs_on_failure,
    aes256_gcm_siv::rm_crypto_aes256_gcm_siv_decrypt,
    aes256_gcm_siv::AES256_GCM_SIV_KEY_LEN,
    aes256_gcm_siv::AES256_GCM_SIV_NONCE_LEN
);
prove_authentication_failure!(
    chacha20_poly1305_preserves_outputs_on_failure,
    chacha20_poly1305::rm_crypto_chacha20_poly1305_decrypt,
    chacha20_poly1305::CHACHA20_POLY1305_KEY_LEN,
    chacha20_poly1305::CHACHA20_POLY1305_NONCE_LEN
);
prove_authentication_failure!(
    xchacha20_poly1305_preserves_outputs_on_failure,
    chacha20_poly1305::rm_crypto_xchacha20_poly1305_decrypt,
    chacha20_poly1305::CHACHA20_POLY1305_KEY_LEN,
    chacha20_poly1305::XCHACHA20_POLY1305_NONCE_LEN
);

#[kani::proof]
#[kani::unwind(24)]
#[kani::use_stub_set(valid_disjoint_call)]
#[kani::stub(reallyme_crypto::operations::hpke::open_base, model_hpke_open)]
fn hpke_p256_aes256_gcm_preserves_outputs_on_failure() {
    check_hpke_authentication_failure::<
        { hpke::HPKE_FFI_P256_PUBLIC_KEY_LEN },
        { hpke::HPKE_FFI_P256_PRIVATE_KEY_LEN },
    >(hpke::HPKE_SUITE_P256_SHA256_AES256GCM);
}

#[kani::proof]
#[kani::unwind(24)]
#[kani::use_stub_set(valid_disjoint_call)]
#[kani::stub(reallyme_crypto::operations::hpke::open_base, model_hpke_open)]
fn hpke_x25519_chacha20_poly1305_preserves_outputs_on_failure() {
    check_hpke_authentication_failure::<
        { hpke::HPKE_FFI_X25519_PUBLIC_KEY_LEN },
        { hpke::HPKE_FFI_X25519_PRIVATE_KEY_LEN },
    >(hpke::HPKE_SUITE_X25519_SHA256_CHACHA20_POLY1305);
}
