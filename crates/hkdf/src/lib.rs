// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! HKDF (RFC 5869) extract-and-expand key derivation over SHA-2, with optional SHA-3 support.

#![forbid(unsafe_code)]

mod derive;
mod material;
mod policy;
mod sha384;

pub use derive::{derive, derive_domain_key_32, DeriveRequest};
pub use material::{
    HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt, HkdfSha384Prk, HKDF_SHA384_PRK_LENGTH,
};
pub use policy::{DomainKeyPurpose, DomainTag, HkdfSuite};
pub use sha384::{expand_sha384, extract_sha384, HKDF_SHA384_MAX_OUTPUT_LENGTH};
