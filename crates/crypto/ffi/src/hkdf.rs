// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use crate::guard::ffi_guard;
use crate::pointer::{read_slice, write_fixed};
use crate::status::{CryptoStatus, CRYPTO_INVALID_ARGUMENT};
use crypto_hkdf::{derive, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt, HkdfSuite};
use zeroize::Zeroize;

/// Suite selector value requesting HKDF with HMAC-SHA-256 (`1`).
pub const HKDF_SUITE_SHA2_256: u32 = 1;
/// Suite selector value requesting HKDF with HMAC-SHA3-256 (`2`).
pub const HKDF_SUITE_SHA3_256: u32 = 2;

fn suite_from_u32(value: u32) -> Result<HkdfSuite, CryptoStatus> {
    match value {
        HKDF_SUITE_SHA2_256 => Ok(HkdfSuite::Sha2_256),
        HKDF_SUITE_SHA3_256 => Ok(HkdfSuite::Sha3_256),
        _ => Err(CRYPTO_INVALID_ARGUMENT),
    }
}

fn derive_to_output<const N: usize>(
    request: &DeriveRequest<'_>,
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    let mut output = match derive::<N>(request) {
        Ok(value) => value,
        Err(_) => return CRYPTO_INVALID_ARGUMENT,
    };
    let status = unsafe { write_fixed(output_out, output_out_len, output.as_bytes()) };
    // `HkdfOutput` zeroizes on drop, but wipe the derived key material
    // explicitly here so its lifetime ends at the copy-out, matching the
    // AEAD path and keeping the secret's residency window minimal.
    output.zeroize();
    status
}

/// Derives output key material from `ikm`, `salt`, and `info` using HKDF with
/// the hash suite selected by `suite`, writing `output_out_len` bytes to
/// `output_out`. The requested length must be one of 16, 24, 32, 48, or 64.
///
/// # Safety
///
/// `ikm`, `salt`, and `info` must each be valid for their respective lengths
/// (any may be null only when its length is `0`; an empty salt is treated as no
/// salt). `output_out` must be non-null and point to at least `output_out_len`
/// writable bytes. Returns [`CryptoStatus`] via the return value:
/// [`CRYPTO_OK`](crate::status::CRYPTO_OK) on success, or
/// [`CRYPTO_INVALID_ARGUMENT`] for an unknown suite or unsupported output length.
#[no_mangle]
pub unsafe extern "C" fn rm_crypto_hkdf_derive(
    suite: u32,
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    output_out: *mut u8,
    output_out_len: usize,
) -> CryptoStatus {
    ffi_guard(|| {
        let suite = match suite_from_u32(suite) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let ikm = match unsafe { read_slice(ikm, ikm_len) } {
            Ok(value) => HkdfInputKeyMaterial::from_slice(value),
            Err(status) => return status,
        };
        let salt_value = match unsafe { read_slice(salt, salt_len) } {
            Ok([]) => None,
            Ok(value) => Some(HkdfSalt::from_slice(value)),
            Err(status) => return status,
        };
        let info = match unsafe { read_slice(info, info_len) } {
            Ok(value) => HkdfInfo::from_slice(value),
            Err(status) => return status,
        };
        let request = DeriveRequest {
            suite,
            ikm: &ikm,
            salt: salt_value.as_ref(),
            info: &info,
        };

        match output_out_len {
            16 => derive_to_output::<16>(&request, output_out, output_out_len),
            24 => derive_to_output::<24>(&request, output_out, output_out_len),
            32 => derive_to_output::<32>(&request, output_out, output_out_len),
            48 => derive_to_output::<48>(&request, output_out, output_out_len),
            64 => derive_to_output::<64>(&request, output_out, output_out_len),
            _ => CRYPTO_INVALID_ARGUMENT,
        }
    })
}
