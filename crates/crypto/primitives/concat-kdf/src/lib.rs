// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JWA ECDH-ES Concat KDF over SHA-256.

mod types;
pub use types::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfOutput, JwaConcatKdfRequest,
    JwaPartyInfo, JwaSharedSecret, JWA_CONCAT_KDF_MAX_INFO_LENGTH,
    JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH, JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH,
};
