// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! HKDF (RFC 5869) extract-and-expand key derivation over SHA-2, with optional SHA-3 support.

#![forbid(unsafe_code)]

// These direct dependencies enable the shared entropy and clearing features
// used by the transitive digest implementation; HKDF itself needs no entropy.
#[cfg(feature = "wasm")]
use getrandom as _;
use hybrid_array as _;

#[cfg(feature = "proto")]
mod convert_proto_identity;
mod derive;
mod material;
mod policy;
/// Protected const-generic HKDF protobuf derivation adapters.
#[cfg(feature = "proto")]
pub mod proto_native;
/// Protected protobuf options and request adapters.
#[cfg(feature = "proto")]
pub mod proto_options;
mod sha384;

pub use derive::{derive, derive_domain_key_32, DeriveRequest};
pub use material::{
    HkdfInfo, HkdfInputKeyMaterial, HkdfOutput, HkdfSalt, HkdfSha384Prk, HKDF_SHA384_PRK_LENGTH,
};
pub use policy::{DomainKeyPurpose, DomainTag, HkdfSuite};
pub use sha384::{expand_sha384, extract_sha384, HKDF_SHA384_MAX_OUTPUT_LENGTH};
