// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

use crypto_core::{CryptoError, HkdfFailureKind, HkdfHash};
use crypto_hkdf::{
    derive, expand_sha384, extract_sha384, DeriveRequest, HkdfInfo, HkdfInputKeyMaterial, HkdfSalt,
    HkdfSuite, HKDF_SHA384_MAX_OUTPUT_LENGTH, HKDF_SHA384_PRK_LENGTH,
};
use hex_literal::hex;

const IKM: [u8; 22] = [0x0b; 22];
const SALT: [u8; 13] = hex!("000102030405060708090a0b0c");
const INFO: [u8; 10] = hex!("f0f1f2f3f4f5f6f7f8f9");

#[test]
fn sha384_extract_and_expand_matches_independent_known_answer() {
    let ikm = HkdfInputKeyMaterial::from_slice(&IKM);
    let salt = HkdfSalt::from_slice(&SALT);
    let info = HkdfInfo::from_slice(&INFO);

    let prk = extract_sha384(Some(&salt), &ikm).unwrap();
    let output = expand_sha384::<42>(&prk, &info).unwrap();

    assert_eq!(
        prk.as_bytes(),
        &hex!(
            "704b39990779ce1dc548052c7dc39f303570dd13fb39f7ac"
            "c564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade"
        )
    );
    assert_eq!(
        output.as_bytes(),
        &hex!(
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf36"
            "9f394cfab43685f748b6457763e4f0204fc5"
        )
    );
    assert_eq!(prk.as_bytes().len(), HKDF_SHA384_PRK_LENGTH);
}

#[test]
fn sha384_combined_derivation_matches_extract_then_expand() {
    let ikm = HkdfInputKeyMaterial::from_slice(&IKM);
    let salt = HkdfSalt::from_slice(&SALT);
    let info = HkdfInfo::from_slice(&INFO);
    let prk = extract_sha384(Some(&salt), &ikm).unwrap();

    let split = expand_sha384::<64>(&prk, &info).unwrap();
    let combined = derive::<64>(&DeriveRequest {
        suite: HkdfSuite::Sha2_384,
        ikm: &ikm,
        salt: Some(&salt),
        info: &info,
    })
    .unwrap();

    assert_eq!(split.as_bytes(), combined.as_bytes());
}

#[test]
fn sha384_rejects_empty_ikm_and_invalid_output_lengths() {
    let empty_ikm = HkdfInputKeyMaterial::from_slice(&[]);
    let info = HkdfInfo::from_slice(b"context");
    let extract_error = extract_sha384(None, &empty_ikm).err().unwrap();
    assert_eq!(
        extract_error,
        CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::InvalidIkmLength,
        }
    );

    let ikm = HkdfInputKeyMaterial::from_slice(b"input keying material");
    let prk = extract_sha384(None, &ikm).unwrap();
    let zero_error = expand_sha384::<0>(&prk, &info).err().unwrap();
    assert_eq!(
        zero_error,
        CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::InvalidOutputLength,
        }
    );

    let oversized_error = expand_sha384::<{ HKDF_SHA384_MAX_OUTPUT_LENGTH + 1 }>(&prk, &info)
        .err()
        .unwrap();
    assert_eq!(
        oversized_error,
        CryptoError::Hkdf {
            hash: HkdfHash::Sha2_384,
            kind: HkdfFailureKind::InvalidOutputLength,
        }
    );
}
