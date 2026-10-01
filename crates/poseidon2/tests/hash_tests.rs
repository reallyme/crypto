// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-implementation byte-sponge vectors and admission boundaries.

use crypto_poseidon2::{hash_bytes, Poseidon2ErrorReason, MAX_INPUT_BYTES};
use hex_literal::hex;

// These outputs come from the ReallyMe ZK checkout's pinned Noir
// bn254_blackbox_solver fixture oracle, not from this crate's permutation.
#[test]
fn matches_zk_byte_sponge_vectors() -> Result<(), crypto_poseidon2::Poseidon2Error> {
    let cases: &[(&[u8], [u8; 32])] = &[
        (
            &[],
            // An empty byte sponge applies the zero-state permutation. This
            // value is Noir's independently cross-checked all-zero state KAT.
            hex!("18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
        ),
        (
            &[0],
            hex!("2710144414c3a5f2354f4c08d52ed655b9fe253b4bf12cb9ad3de693d9b1db11"),
        ),
        (
            &[1, 2, 3],
            hex!("23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8"),
        ),
        (
            &[1, 2, 3, 4],
            hex!("130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9"),
        ),
        (
            &[255, 0, 128, 7, 9, 11],
            hex!("06e5a7d86b6db53b993788a22c92a3431b5299ad2b75152c2befa8785cb21450"),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(hash_bytes(input)?.as_bytes(), expected);
    }
    Ok(())
}

#[test]
fn accepts_largest_reviewed_circuit_preimage() -> Result<(), crypto_poseidon2::Poseidon2Error> {
    let input = vec![0_u8; MAX_INPUT_BYTES];
    assert_eq!(
        hash_bytes(&input)?.as_bytes(),
        &hex!("04f4f95442505d9014ed088448e9c26dd60b78fd09377b675642eec8294334d6")
    );
    Ok(())
}

#[test]
fn rejects_oversized_preimage_with_typed_reason() {
    let input = vec![0_u8; MAX_INPUT_BYTES + 1];
    assert!(matches!(
        hash_bytes(&input),
        Err(error) if error.reason() == Poseidon2ErrorReason::InputTooLong
    ));
}

#[test]
fn length_domain_separates_prefixes() -> Result<(), crypto_poseidon2::Poseidon2Error> {
    let short = hash_bytes(&[1, 2, 3])?;
    let long = hash_bytes(&[1, 2, 3, 0])?;
    assert_ne!(short.as_bytes(), long.as_bytes());
    Ok(())
}
