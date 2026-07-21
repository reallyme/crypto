// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Panic firewall for the C ABI surface.
//!
//! Every `extern "C"` export routes its body through [`ffi_guard`]. Unwinding
//! across an `extern "C"` boundary is undefined behavior, so unwind-capable FFI
//! builds convert any panic escaping a RustCrypto primitive (or any other
//! unexpected unwind) into a deterministic [`CRYPTO_INTERNAL_ERROR`] status
//! code. The Swift, Android, and JVM release packaging scripts select the
//! workspace's `release-ffi` profile. The crate refuses to compile unless the
//! panic strategy is unwind-capable, so this firewall cannot silently degrade
//! into process aborts in downstream builds.

use crate::pointer::begin_input_range_call;
use crate::status::{CryptoStatus, CRYPTO_INTERNAL_ERROR};

/// Run an FFI operation body behind a panic firewall.
///
/// On the normal path the operation's own [`CryptoStatus`] is returned
/// unchanged, so status codes, output-buffer semantics, and the ABI are
/// untouched. If the operation panics, the unwind is caught at this boundary
/// and reported as [`CRYPTO_INTERNAL_ERROR`]; the panic payload is dropped and
/// never re-raised or exposed to the caller.
///
/// # Unwind safety
///
/// The closure is wrapped in [`AssertUnwindSafe`] because the FFI bodies borrow
/// caller-owned raw pointers, which are not `UnwindSafe`. This is sound for this
/// crate:
///
/// - The operations act on caller-owned raw buffers and short-lived local
///   state; there is no shared `&mut`/interior-mutable state that could be
///   observed in a torn, half-updated form after a caught panic.
/// - Each individual output write is prevalidated and performed by one
///   `copy_from_slice`. Multi-output operations can complete an earlier write
///   before a later unexpected panic, so callers must discard every output
///   whenever the returned status is not success; no unwinding state is reused
///   by a later call.
/// - Secret-bearing temporaries are held in `Zeroizing`/`ZeroizeOnDrop`
///   wrappers whose destructors run during the unwind, before this function
///   converts the panic into a status, so no secret material is leaked or left
///   un-wiped by the firewall.
///
/// [`AssertUnwindSafe`]: std::panic::AssertUnwindSafe
#[inline]
pub fn ffi_guard<F>(operation: F) -> CryptoStatus
where
    F: FnOnce() -> CryptoStatus,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Establishing the per-call alias-tracking scope is part of the FFI
        // boundary itself. Keep it inside the firewall so the guarantee covers
        // all boundary setup, even if that currently panic-free helper changes.
        let _pointer_range_guard = match begin_input_range_call() {
            Ok(guard) => guard,
            Err(_) => return CRYPTO_INTERNAL_ERROR,
        };
        operation()
    })) {
        Ok(status) => status,
        Err(_payload) => CRYPTO_INTERNAL_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::ffi_guard;
    use crate::status::CRYPTO_INTERNAL_ERROR;

    #[test]
    #[allow(clippy::panic)]
    fn panic_is_mapped_to_internal_error_in_unwind_capable_builds() {
        let status = ffi_guard(|| panic!("test-only panic firewall probe"));

        assert_eq!(status, CRYPTO_INTERNAL_ERROR);
    }
}
