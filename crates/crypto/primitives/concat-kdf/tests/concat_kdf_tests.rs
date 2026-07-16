// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]

use crypto_concat_kdf::{
    derive_jwa_concat_kdf_sha256, JwaAlgorithmId, JwaConcatKdfRequest, JwaPartyInfo,
    JwaSharedSecret,
};
use crypto_core::{CryptoError, KdfAlgorithm, KdfFailureKind, KdfProfile};

#[test]
fn rfc7518_appendix_c_a128gcm_vector_matches() {
    let shared_secret = JwaSharedSecret::from_slice(&[
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ])
    .expect("RFC vector shared secret must be valid");
    let algorithm_id = JwaAlgorithmId::from_slice(b"A128GCM").expect("algorithm ID must be valid");
    let party_u_info = JwaPartyInfo::from_slice(b"Alice").expect("PartyUInfo must be valid");
    let party_v_info = JwaPartyInfo::from_slice(b"Bob").expect("PartyVInfo must be valid");

    let output = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    })
    .expect("RFC vector derivation must succeed");

    assert_eq!(
        output.as_bytes(),
        &[86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
    );
}

#[test]
fn a256gcm_derivation_outputs_requested_length() {
    let shared_secret = JwaSharedSecret::from_slice(&[0x42u8; 32]).expect("secret must be valid");
    let algorithm_id = JwaAlgorithmId::from_slice(b"A256GCM").expect("algorithm ID must be valid");
    let party_info = JwaPartyInfo::from_slice(b"").expect("empty party info must be valid");

    let output = derive_jwa_concat_kdf_sha256::<32>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_info,
        party_v_info: &party_info,
    })
    .expect("derivation must succeed");

    assert_eq!(output.as_bytes().len(), 32);
}

#[test]
fn zero_length_output_is_rejected() {
    let shared_secret = JwaSharedSecret::from_slice(&[0x42u8; 32]).expect("secret must be valid");
    let algorithm_id = JwaAlgorithmId::from_slice(b"A128GCM").expect("algorithm ID must be valid");
    let party_info = JwaPartyInfo::from_slice(b"").expect("empty party info must be valid");

    let err = match derive_jwa_concat_kdf_sha256::<0>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_info,
        party_v_info: &party_info,
    }) {
        Err(err) => err,
        Ok(_) => panic!("zero output length must fail"),
    };

    assert_kdf_error(err, KdfFailureKind::InvalidOutputLength);
}

#[test]
fn empty_shared_secret_is_rejected() {
    let err = match JwaSharedSecret::from_slice(&[]) {
        Err(err) => err,
        Ok(_) => panic!("empty shared secret must fail"),
    };
    assert_kdf_error(err, KdfFailureKind::InvalidSecretLength);
}

#[test]
fn empty_algorithm_id_is_rejected() {
    let err = JwaAlgorithmId::from_slice(&[]).expect_err("empty algorithm ID must fail");
    assert_kdf_error(err, KdfFailureKind::InvalidParams);
}

#[test]
fn party_info_changes_output() {
    let shared_secret = JwaSharedSecret::from_slice(&[0x42u8; 32]).expect("secret must be valid");
    let algorithm_id = JwaAlgorithmId::from_slice(b"A128GCM").expect("algorithm ID must be valid");
    let alice = JwaPartyInfo::from_slice(b"Alice").expect("PartyUInfo must be valid");
    let bob = JwaPartyInfo::from_slice(b"Bob").expect("PartyVInfo must be valid");
    let empty = JwaPartyInfo::from_slice(b"").expect("empty PartyInfo must be valid");

    let with_parties = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &alice,
        party_v_info: &bob,
    })
    .expect("derivation must succeed");

    let without_parties = derive_jwa_concat_kdf_sha256::<16>(&JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &empty,
        party_v_info: &empty,
    })
    .expect("derivation must succeed");

    assert_ne!(with_parties.as_bytes(), without_parties.as_bytes());
}

fn assert_kdf_error(error: CryptoError, expected_kind: KdfFailureKind) {
    match error {
        CryptoError::Kdf {
            algorithm,
            profile,
            kind,
        } => {
            assert_eq!(algorithm, KdfAlgorithm::ConcatKdf);
            assert_eq!(profile, KdfProfile::JwaEcdhEsSha256);
            assert_eq!(kind, expected_kind);
        }
        _ => panic!("unexpected error variant"),
    }
}
