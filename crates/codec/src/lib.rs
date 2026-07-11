// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! # reallyme-codec
//!
//! Codec-only utilities used by ReallyMe and DID tooling: base encodings,
//! canonical JSON/CBOR serialization, multicodec lookup, and multikey handling.
//! This crate deliberately has no cryptographic primitive dependencies.

#![forbid(unsafe_code)]

/// Standard (RFC 4648) base64 encode/decode.
#[cfg(feature = "base64")]
pub mod base64 {
    pub use codec_base64::{base64_to_bytes, bytes_to_base64, Base64Error};
}

/// URL-safe (RFC 4648 §5) base64 encode/decode without padding.
#[cfg(feature = "base64url")]
pub mod base64url {
    pub use codec_base64url::{
        base64url_bytes_to_bytes, base64url_to_bytes, bytes_to_base64url, Base64UrlError,
    };
}

/// DAG-CBOR encode/decode and content-identifier helpers.
#[cfg(feature = "cbor")]
pub mod cbor {
    pub use codec_cbor::{
        compute_cid_dag_cbor, dag_cbor_multihash, decode_dag_cbor, encode_dag_cbor,
        is_valid_cid_string, sha2_256_content_hash, try_parse_cid, verify_dag_cbor_cid, CborError,
        CborValue, ContentHash, DagCborMultihash, DAG_CBOR_CODEC,
    };
}

/// JSON Canonicalization Scheme (RFC 8785) serialization.
#[cfg(feature = "jcs")]
pub mod jcs {
    pub use codec_jcs::{canonicalize_json, JcsError};
}

/// Multibase self-describing base encodings.
#[cfg(feature = "multibase")]
pub mod multibase {
    pub use codec_multibase::{
        base58btc_decode, base58btc_encode, bytes_to_multibase58btc, bytes_to_multibase_base64url,
        multibase_to_bytes, Base58Error, MultibaseError,
    };
}

/// Multicodec varint prefix lookup and stripping.
#[cfg(feature = "multicodec")]
pub mod multicodec {
    pub use codec_multicodec::{
        lookup_codec_prefix, strip_codec_prefix, CodecLookupResult, CodecSpec, MULTICODEC_TABLE,
    };
}

/// Multikey encoding/parsing that binds an algorithm to opaque key bytes.
#[cfg(feature = "multikey")]
pub mod multikey {
    pub use codec_multikey::{
        binding_type_matches_codec, encode_multikey, parse_multikey, validate_key_binding,
        KeyBindingInput, MultikeyError, ParsedMultikey,
    };
}
