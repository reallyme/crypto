// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn protobuf_operation_contract_captures_public_facade_io() -> Result<(), VectorTestError> {
    const OPERATIONS: &[&str] = &[
        "authenticate",
        "decapsulate",
        "deriveArgon2id",
        "deriveHkdf",
        "deriveJwaConcatKdfSha256",
        "deriveKmac256",
        "deriveKemKeyPair",
        "deriveKey",
        "deriveKeyAgreementKeyPair",
        "deriveKeyPair",
        "deriveSharedSecret",
        "encapsulate",
        "generateKemKeyPair",
        "generateKeyPair",
        "hash",
        "open",
        "openHpke",
        "seal",
        "sealHpke",
        "sign",
        "signBip340Schnorr",
        "unwrapKey",
        "verify",
        "verifyMac",
        "verifyRsa",
        "wrapKey",
    ];

    let facade = read_repo_file("packages/ts/src/cryptoFacade.ts")?;
    let mut actual_operations = collect_ts_crypto_facade_methods(&facade);
    // These methods execute the operation already selected by the request
    // oneof. They are transport adapters, so requiring another oneof arm for
    // them would create a recursive wire operation instead of strengthening
    // operation coverage.
    for removed_method in ["processProto", "processProtoJson"] {
        assert!(
            !actual_operations.contains(removed_method),
            "ReallyMeCrypto must not retain removed {removed_method} forwarding boundary"
        );
    }
    for transport_method in ["processOperationResponse", "processOperationResponseJson"] {
        assert!(
            actual_operations.remove(transport_method),
            "ReallyMeCrypto must retain its {transport_method} transport boundary"
        );
    }
    let expected_operations = OPERATIONS
        .iter()
        .map(|operation| (*operation).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_operations, expected_operations,
        "ReallyMeCrypto facade methods must stay represented in the protobuf operation contract"
    );

    let proto = read_repo_file("crates/proto/proto/reallyme/crypto/v1/crypto.proto")?;
    let messages = parse_proto_messages(&proto);

    for (message, fields) in [
        (
            "CryptoHashRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("input", "bytes"),
            ][..],
        ),
        (
            "CryptoHashResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("digest", "bytes"),
            ],
        ),
        (
            "CryptoAeadSealRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("key", "bytes"),
                ("nonce", "bytes"),
                ("aad", "bytes"),
                ("plaintext", "bytes"),
            ],
        ),
        (
            "CryptoAeadSealResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("ciphertext_with_tag", "bytes"),
            ],
        ),
        (
            "CryptoAeadOpenRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("key", "bytes"),
                ("nonce", "bytes"),
                ("aad", "bytes"),
                ("ciphertext_with_tag", "bytes"),
            ],
        ),
        (
            "CryptoAeadOpenResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("plaintext", "bytes"),
            ],
        ),
        (
            "CryptoMacAuthenticateRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("key", "bytes"),
                ("message", "bytes"),
            ],
        ),
        (
            "CryptoMacAuthenticateResult",
            &[("algorithm", "CryptoAlgorithmIdentifier"), ("tag", "bytes")],
        ),
        (
            "CryptoMacVerifyRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("tag", "bytes"),
                ("key", "bytes"),
                ("message", "bytes"),
            ],
        ),
        (
            "CryptoArgon2idDeriveRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("kdf_version", "Argon2idKdfVersion"),
                ("secret", "bytes"),
                ("salt", "bytes"),
            ],
        ),
        (
            "CryptoKdfDeriveKeyRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("password", "bytes"),
                ("salt", "bytes"),
                ("iterations", "uint32"),
                ("output_length", "uint32"),
            ],
        ),
        (
            "CryptoKdfDeriveKeyResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("derived_key", "bytes"),
            ],
        ),
        (
            "CryptoHkdfDeriveRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("input_key_material", "bytes"),
                ("salt", "bytes"),
                ("info", "bytes"),
                ("output_length", "uint32"),
            ],
        ),
        (
            "CryptoHkdfDeriveResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("output_key_material", "bytes"),
            ],
        ),
        (
            "CryptoJwaConcatKdfSha256DeriveRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("shared_secret", "bytes"),
                ("algorithm_id", "bytes"),
                ("party_u_info", "bytes"),
                ("party_v_info", "bytes"),
                ("output_length", "uint32"),
            ],
        ),
        (
            "CryptoJwaConcatKdfSha256DeriveResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("derived_key", "bytes"),
            ],
        ),
        (
            "CryptoKeyWrapRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("wrapping_key", "bytes"),
                ("key_to_wrap", "bytes"),
            ],
        ),
        (
            "CryptoKeyWrapResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("wrapped_key", "bytes"),
            ],
        ),
        (
            "CryptoKeyUnwrapRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("wrapping_key", "bytes"),
                ("wrapped_key", "bytes"),
            ],
        ),
        (
            "CryptoKeyUnwrapResult",
            &[("algorithm", "CryptoAlgorithmIdentifier"), ("key", "bytes")],
        ),
        (
            "CryptoSignatureGenerateKeyPairRequest",
            &[("algorithm", "CryptoAlgorithmIdentifier")],
        ),
        (
            "CryptoSignatureDeriveKeyPairRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoSignatureSignRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("message", "bytes"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoSignatureSignResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("signature", "bytes"),
            ],
        ),
        (
            "CryptoBip340SchnorrSignRequest",
            &[
                ("message32", "bytes"),
                ("secret_key", "bytes"),
                ("aux_rand32", "bytes"),
            ],
        ),
        (
            "CryptoSignatureVerifyRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("signature", "bytes"),
                ("message", "bytes"),
                ("public_key", "bytes"),
            ],
        ),
        (
            "CryptoRsaVerifyRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("signature", "bytes"),
                ("message", "bytes"),
                ("public_key_der", "bytes"),
                ("public_key_encoding", "RsaPublicKeyDerEncoding"),
            ],
        ),
        (
            "CryptoKeyAgreementDeriveSharedSecretRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("public_key", "bytes"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoKeyAgreementDeriveSharedSecretResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("shared_secret", "bytes"),
            ],
        ),
        (
            "CryptoKeyAgreementDeriveKeyPairRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoKemGenerateKeyPairRequest",
            &[("algorithm", "CryptoAlgorithmIdentifier")],
        ),
        (
            "CryptoKemEncapsulateRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("public_key", "bytes"),
            ],
        ),
        (
            "CryptoKemDecapsulateRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("ciphertext", "bytes"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoKemDecapsulateResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("shared_secret", "bytes"),
            ],
        ),
        (
            "CryptoHpkeSealRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("recipient_public_key", "bytes"),
                ("info", "bytes"),
                ("aad", "bytes"),
                ("plaintext", "bytes"),
            ],
        ),
        (
            "CryptoHpkeOpenRequest",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("recipient_secret_key", "bytes"),
                ("encapsulated_key", "bytes"),
                ("info", "bytes"),
                ("aad", "bytes"),
                ("ciphertext", "bytes"),
            ],
        ),
        (
            "CryptoHpkeOpenResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("plaintext", "bytes"),
            ],
        ),
        (
            "CryptoKeyPair",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("public_key", "bytes"),
                ("secret_key", "bytes"),
            ],
        ),
        (
            "CryptoKemEncapsulation",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("ciphertext", "bytes"),
                ("shared_secret", "bytes"),
            ],
        ),
        (
            "CryptoHpkeSealedMessage",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("encapsulated_key", "bytes"),
                ("ciphertext", "bytes"),
            ],
        ),
        (
            "CryptoVerificationResult",
            &[
                ("algorithm", "CryptoAlgorithmIdentifier"),
                ("status", "CryptoVerificationStatus"),
                ("error", "CryptoError"),
            ],
        ),
    ] {
        assert_message_fields(&messages, message, fields)?;
    }

    Ok(())
}
