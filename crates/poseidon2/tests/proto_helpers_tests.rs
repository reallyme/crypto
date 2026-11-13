// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "proto")]
#![allow(missing_docs, clippy::expect_used)]
use buffa::Message;
use crypto_core::CryptoError;
use crypto_poseidon2::proto_helpers::Poseidon2Inputs;
use crypto_poseidon2::{hash_bytes, MAX_INPUT_BYTES};
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoPoseidon2HashRequest, CryptoPoseidon2HashResult,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
#[test]
fn fixed_poseidon_byte_profile_preserves_every_input_and_digest_byte() {
    for input in [
        Vec::new(),
        vec![0],
        vec![0, 0xff, 1],
        vec![0, 0xff, 1, 2],
        vec![0xa5; MAX_INPUT_BYTES],
    ] {
        let wire = CryptoPoseidon2HashRequest {
            input,
            __buffa_unknown_fields: Default::default(),
        };
        let owner = Poseidon2Inputs::try_from(&wire).expect("bounded input");
        assert_eq!(owner.as_bytes(), wire.input);
        let digest = owner.hash().expect("native fixed profile");
        let direct = hash_bytes(&wire.input).expect("existing native profile");
        assert_eq!(digest.as_bytes(), direct.as_bytes());
        assert_eq!(
            CryptoPoseidon2HashResult::try_from(&digest)
                .expect("digest owner")
                .digest,
            digest.as_bytes()
        );
    }
}
#[test]
fn poseidon_rejects_oversized_and_unknown_inputs_and_clears_owners(
) -> Result<(), buffa::DecodeError> {
    fn cleanup<T: ZeroizeOnDrop>() {}
    cleanup::<Poseidon2Inputs>();
    cleanup::<CryptoPoseidon2HashRequest>();
    cleanup::<CryptoPoseidon2HashResult>();
    let mut wire = CryptoPoseidon2HashRequest {
        input: vec![0; MAX_INPUT_BYTES.checked_add(1).expect("small bound")],
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        Poseidon2Inputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)
    );
    wire.input = vec![0, 0xff];
    let mut owner = Poseidon2Inputs::try_from(&wire).expect("bounded input");
    owner.zeroize();
    assert!(owner.as_bytes().is_empty());
    wire.merge_from_slice(&[0xa0, 0x06, 0x01])?;
    assert_eq!(
        Poseidon2Inputs::try_from(&wire).err(),
        Some(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    );
    Ok(())
}
