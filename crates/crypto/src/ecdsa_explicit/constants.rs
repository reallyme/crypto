// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub(super) const P256_SCALAR_LEN: usize = 32;
pub(super) const P384_SCALAR_LEN: usize = 48;
pub(super) const P521_SCALAR_LEN: usize = 66;

#[cfg(any(
    feature = "brainpool",
    all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
))]
pub(super) const BRAINPOOL_P256_SCALAR_LEN: usize = size_of::<bp256::FieldBytes>();
#[cfg(any(
    feature = "brainpool",
    all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
))]
pub(super) const BRAINPOOL_P320_SCALAR_LEN: usize = 40;
#[cfg(any(
    feature = "brainpool",
    all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
))]
pub(super) const BRAINPOOL_P384_SCALAR_LEN: usize = size_of::<bp384::FieldBytes>();
#[cfg(any(
    feature = "brainpool",
    all(feature = "brainpool-openssl", not(target_arch = "wasm32"))
))]
pub(super) const BRAINPOOL_P512_SCALAR_LEN: usize = 64;
