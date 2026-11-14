// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Generated from canonical descriptors by scripts/generate_protobuf.mjs.
pub mod reallyme {
    pub mod crypto {
        pub mod v1 {
            pub use crate::enum_contracts::AeadAlgorithm;
            pub use crate::enum_contracts::AppleKeychainAccessibility;
            pub use crate::enum_contracts::AppleSecureEnclaveAccessPolicy;
            pub use crate::enum_contracts::Argon2PlatformClass;
            pub use crate::enum_contracts::Argon2idKdfVersion;
            pub use crate::enum_contracts::BufferOwner;
            pub use crate::enum_contracts::CryptoAlgorithmFamily;
            pub use crate::enum_contracts::CryptoErrorReason;
            pub use crate::enum_contracts::CryptoProviderSupportStatus;
            pub use crate::enum_contracts::CryptoVerificationStatus;
            pub use crate::enum_contracts::DestructionPolicy;
            pub use crate::enum_contracts::EcdsaCurve;
            pub use crate::enum_contracts::EcdsaEncoding;
            pub use crate::enum_contracts::Ed448Operation;
            pub use crate::enum_contracts::ExportPolicy;
            pub use crate::enum_contracts::FallbackPolicy;
            pub use crate::enum_contracts::HashAlgorithm;
            pub use crate::enum_contracts::HkdfDomainKeyPurpose;
            pub use crate::enum_contracts::HpkeAeadId;
            pub use crate::enum_contracts::HpkeComponentSupport;
            pub use crate::enum_contracts::HpkeKdfId;
            pub use crate::enum_contracts::HpkeKemId;
            pub use crate::enum_contracts::KdfAlgorithm;
            pub use crate::enum_contracts::KemAlgorithm;
            pub use crate::enum_contracts::KeyAgreementAlgorithm;
            pub use crate::enum_contracts::KeyAlgorithm;
            pub use crate::enum_contracts::KeyCopyBoundary;
            pub use crate::enum_contracts::KeyResidency;
            pub use crate::enum_contracts::KeyWrapAlgorithm;
            pub use crate::enum_contracts::MacAlgorithm;
            pub use crate::enum_contracts::MulticodecKeyAlgorithm;
            pub use crate::enum_contracts::NativeKeySource;
            pub use crate::enum_contracts::OutputMaterial;
            pub use crate::enum_contracts::P256KeyContainerFormat;
            pub use crate::enum_contracts::PlatformKeyOperation;
            pub use crate::enum_contracts::PlatformKeyProvider;
            pub use crate::enum_contracts::PlatformKeyPurpose;
            pub use crate::enum_contracts::PlatformKeySecurityLevel;
            pub use crate::enum_contracts::PrimeGroup;
            pub use crate::enum_contracts::ProviderDisposition;
            pub use crate::enum_contracts::ProviderKind;
            pub use crate::enum_contracts::ProviderLane;
            pub use crate::enum_contracts::ProviderOperation;
            pub use crate::enum_contracts::ProviderOutputPolicy;
            pub use crate::enum_contracts::ProviderPolicyReason;
            pub use crate::enum_contracts::PublicKeyFormatOperation;
            pub use crate::enum_contracts::RetentionPolicy;
            pub use crate::enum_contracts::RngOutputKind;
            pub use crate::enum_contracts::RsaHashAlgorithm;
            pub use crate::enum_contracts::RsaPublicKeyDerEncoding;
            pub use crate::enum_contracts::SecretMaterialOperation;
            pub use crate::enum_contracts::SecretSensitivity;
            pub use crate::enum_contracts::SignatureAlgorithm;
            pub use crate::enum_contracts::ZeroizationPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::AndroidPlatformKeyPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::ApplePlatformKeyPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::Argon2Caps;
            pub use crate::generated::raw::reallyme::crypto::v1::Argon2ParamsProfile;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadOpenRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadOpenResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadSealRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadSealResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoAlgorithmIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2BudgetFitRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2FixedDeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2MobileUnlockRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2PlatformResolveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2idDeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2idProfileIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoBackendError;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoBip340SchnorrSignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeCompareRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeCompareResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeRequireEqualResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaAgreementRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaCurveIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaInput;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyDescriptor;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyGenerateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaMessageInput;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPrehashInput;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPublicKey;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPublicKeyValidationRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignOptions;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignatureTranscodeRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448KeyDescriptor;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448KeyImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448OrdinarySignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448OrdinaryVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448PublicKey;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448SupportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoError;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoGenerateMultikeyKeypairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoGenerateMultikeyKeypairResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHashRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHashResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveInputs;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDomainKey32Request;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDomainTag;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExpandSha384Request;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExtractSha384Request;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExtractSha384Result;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfNativeDeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfNativeDeriveResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfSuiteIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeBaseSealConformanceRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeComponentCapability;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeDeriveKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeExactWidthDeriveKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeGenerateKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeOpenRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeOpenResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseCapabilities;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseOpenRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseOpenResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BasePublicKey;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseRecipientGenerateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseRecipientImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseSealRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseSealedResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskOpenRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskReceiverSetupRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskReceiverSetupResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSealRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupConformanceRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePublicKeyDescriptor;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverExportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverExportResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverOpenRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverOpenResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSealRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSealedMessage;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportConformanceRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderSealRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderSealResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwaConcatKdfSha256DeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwaConcatKdfSha256DeriveResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkOptions;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkToMultikeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkToMultikeyResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKdfDeriveKeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKdfDeriveKeyResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemConformanceEncapsulateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDecapsulateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDecapsulateResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDeriveKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemEncapsulateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemEncapsulation;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemGenerateKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveSharedSecretRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveSharedSecretResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementGenerateKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAlgorithmIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyPair;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyUnwrapRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyUnwrapResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyWrapRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyWrapResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKmac256DeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoKmac256DeriveResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacAuthenticateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacAuthenticateResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMaterialPolicyQueryRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMultikeyToJwkRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoMultikeyToJwkResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeAgreementResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeKeyCapabilities;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeKeyGenerateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativePublicKeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeSignatureResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeVerificationResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationResponse;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256CompressedPublicKeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256LowSSignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256LowSVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256PrivateKeyContainerImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256PublicKeyContainerImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleDecodeRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleDecodeResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleEncodeRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleEncodeResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SignatureNormalizeRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPbkdf2PrfIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPbkdf2StandardsDeriveRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAgreementDeriveSharedSecretRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAgreementDeriveSharedSecretResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestationCertificate;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyDeleteRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyDeleteResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGenerateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGenerateResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGetPublicKeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGetPublicKeyResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformPrivateKeyHandle;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureSignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureSignResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPoseidon2HashRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPoseidon2HashResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupCurveCoefficients;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDhParametersValidationRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDhParametersValidationResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDomainRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDomainResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupElement;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupFieldValue;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupLinearCombinationRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupMultiplyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupReduceToFieldRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarDescriptor;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarGenerateRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarImportRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimitiveError;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderCapability;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderCapabilitySet;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderError;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyAffineCoordinates;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyBytes;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyFormatRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyFormatResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJcsResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJwkRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJwkResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToMultikeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToMultikeyResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomBytesRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomBytesResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomFillPolicyQueryRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaHashIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPssParams;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPssVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicKeyDerEncodingIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicRepresentativesRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicRepresentativesResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSecp256k1AgreementRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSecp256k1SignatureTranscodeRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoShake256ExpandRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoShake256ExpandResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureDeriveKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureGenerateKeyPairRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureSignRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureSignResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureVerifyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSubjectKeyIdentifierRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoSubjectKeyIdentifierResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationMethodMultikeyRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationMethodMultikeyResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationResult;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448AgreementRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448KeyDescriptor;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448PrivateKeyInput;
            pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448PublicKey;
            pub use crate::generated::raw::reallyme::crypto::v1::HpkeSuiteIdentifier;
            pub use crate::generated::raw::reallyme::crypto::v1::JsonWebKey;
            pub use crate::generated::raw::reallyme::crypto::v1::JsonWebKeySet;
            pub use crate::generated::raw::reallyme::crypto::v1::MaterialPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::OperationSecretMaterialPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::PlatformKeyPolicy;
            pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecision;
            pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecisionRequest;
            pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecisionResult;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicAkpJwk;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicEcJwk;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicJwk;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicJwkDocument;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicJwks;
            pub use crate::generated::raw::reallyme::crypto::v1::PublicOkpJwk;
            pub mod __buffa {
                pub mod oneof {
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_algorithm_identifier;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_ecdsa_input;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_error;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_hpke_component_capability;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_operation_request;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_operation_response;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::crypto_public_key_format_result;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::platform_key_policy;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::public_jwk;
                    pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::public_jwk_document;
                }
                pub mod view {
                    pub mod oneof {
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_algorithm_identifier;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_ecdsa_input;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_error;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_hpke_component_capability;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_operation_request;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_operation_response;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_operation_result;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::crypto_public_key_format_result;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::platform_key_policy;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::public_jwk;
                        pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::public_jwk_document;
                    }
                    pub use crate::generated::raw::reallyme::crypto::v1::Argon2CapsOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::Argon2CapsView;
                    pub use crate::generated::raw::reallyme::crypto::v1::Argon2ParamsProfileOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::Argon2ParamsProfileView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoBackendErrorOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoBackendErrorView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoErrorOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoErrorView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationRequestView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimitiveErrorOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimitiveErrorView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderErrorOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderErrorView;
                    pub use crate::generated::raw::reallyme::crypto::v1::MaterialPolicyOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::MaterialPolicyView;
                    pub use crate::generated::raw::reallyme::crypto::v1::OperationSecretMaterialPolicyOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::OperationSecretMaterialPolicyView;
                    pub type CryptoOperationRequestOwnedView =
                        crate::GuardedOwnedView<CryptoOperationRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationResponseView;
                    pub type CryptoOperationResponseOwnedView =
                        crate::GuardedOwnedView<CryptoOperationResponseView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoOperationResultView;
                    pub type CryptoOperationResultOwnedView =
                        crate::GuardedOwnedView<CryptoOperationResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecisionView;
                    pub type ProviderDecisionOwnedView =
                        crate::GuardedOwnedView<ProviderDecisionView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecisionRequestView;
                    pub type ProviderDecisionRequestOwnedView =
                        crate::GuardedOwnedView<ProviderDecisionRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::ProviderDecisionResultView;
                    pub type ProviderDecisionResultOwnedView =
                        crate::GuardedOwnedView<ProviderDecisionResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAlgorithmIdentifierView;
                    pub type CryptoKeyAlgorithmIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoKeyAlgorithmIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaCurveIdentifierView;
                    pub type CryptoEcdsaCurveIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaCurveIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupIdentifierView;
                    pub type CryptoPrimeGroupIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::HpkeSuiteIdentifierView;
                    pub type HpkeSuiteIdentifierOwnedView =
                        crate::GuardedOwnedView<HpkeSuiteIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfSuiteIdentifierView;
                    pub type CryptoHkdfSuiteIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfSuiteIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPbkdf2PrfIdentifierView;
                    pub type CryptoPbkdf2PrfIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoPbkdf2PrfIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2idProfileIdentifierView;
                    pub type CryptoArgon2idProfileIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2idProfileIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaHashIdentifierView;
                    pub type CryptoRsaHashIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoRsaHashIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicKeyDerEncodingIdentifierView;
                    pub type CryptoRsaPublicKeyDerEncodingIdentifierOwnedView =
                        crate::GuardedOwnedView<
                            CryptoRsaPublicKeyDerEncodingIdentifierView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPssParamsView;
                    pub type CryptoRsaPssParamsOwnedView =
                        crate::GuardedOwnedView<CryptoRsaPssParamsView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2FixedDeriveRequestView;
                    pub type CryptoArgon2FixedDeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2FixedDeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2PlatformResolveRequestView;
                    pub type CryptoArgon2PlatformResolveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2PlatformResolveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2BudgetFitRequestView;
                    pub type CryptoArgon2BudgetFitRequestOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2BudgetFitRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2MobileUnlockRequestView;
                    pub type CryptoArgon2MobileUnlockRequestOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2MobileUnlockRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMaterialPolicyQueryRequestView;
                    pub type CryptoMaterialPolicyQueryRequestOwnedView =
                        crate::GuardedOwnedView<CryptoMaterialPolicyQueryRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomFillPolicyQueryRequestView;
                    pub type CryptoRandomFillPolicyQueryRequestOwnedView =
                        crate::GuardedOwnedView<CryptoRandomFillPolicyQueryRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPbkdf2StandardsDeriveRequestView;
                    pub type CryptoPbkdf2StandardsDeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPbkdf2StandardsDeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDomainTagView;
                    pub type CryptoHkdfDomainTagOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfDomainTagView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveInputsView;
                    pub type CryptoHkdfDeriveInputsOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfDeriveInputsView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfNativeDeriveRequestView;
                    pub type CryptoHkdfNativeDeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfNativeDeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfNativeDeriveResultView;
                    pub type CryptoHkdfNativeDeriveResultOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfNativeDeriveResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExtractSha384RequestView;
                    pub type CryptoHkdfExtractSha384RequestOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfExtractSha384RequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExtractSha384ResultView;
                    pub type CryptoHkdfExtractSha384ResultOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfExtractSha384ResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfExpandSha384RequestView;
                    pub type CryptoHkdfExpandSha384RequestOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfExpandSha384RequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDomainKey32RequestView;
                    pub type CryptoHkdfDomainKey32RequestOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfDomainKey32RequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkOptionsView;
                    pub type CryptoJwkOptionsOwnedView =
                        crate::GuardedOwnedView<CryptoJwkOptionsView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicEcJwkView;
                    pub type PublicEcJwkOwnedView =
                        crate::GuardedOwnedView<PublicEcJwkView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicOkpJwkView;
                    pub type PublicOkpJwkOwnedView =
                        crate::GuardedOwnedView<PublicOkpJwkView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicAkpJwkView;
                    pub type PublicAkpJwkOwnedView =
                        crate::GuardedOwnedView<PublicAkpJwkView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicJwkView;
                    pub type PublicJwkOwnedView = crate::GuardedOwnedView<PublicJwkView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicJwksView;
                    pub type PublicJwksOwnedView = crate::GuardedOwnedView<PublicJwksView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PublicJwkDocumentView;
                    pub type PublicJwkDocumentOwnedView =
                        crate::GuardedOwnedView<PublicJwkDocumentView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoAlgorithmIdentifierView;
                    pub type CryptoAlgorithmIdentifierOwnedView =
                        crate::GuardedOwnedView<CryptoAlgorithmIdentifierView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHashRequestView;
                    pub type CryptoHashRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHashRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHashResultView;
                    pub type CryptoHashResultOwnedView =
                        crate::GuardedOwnedView<CryptoHashResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadSealRequestView;
                    pub type CryptoAeadSealRequestOwnedView =
                        crate::GuardedOwnedView<CryptoAeadSealRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadSealResultView;
                    pub type CryptoAeadSealResultOwnedView =
                        crate::GuardedOwnedView<CryptoAeadSealResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadOpenRequestView;
                    pub type CryptoAeadOpenRequestOwnedView =
                        crate::GuardedOwnedView<CryptoAeadOpenRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoAeadOpenResultView;
                    pub type CryptoAeadOpenResultOwnedView =
                        crate::GuardedOwnedView<CryptoAeadOpenResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacAuthenticateRequestView;
                    pub type CryptoMacAuthenticateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoMacAuthenticateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacAuthenticateResultView;
                    pub type CryptoMacAuthenticateResultOwnedView =
                        crate::GuardedOwnedView<CryptoMacAuthenticateResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMacVerifyRequestView;
                    pub type CryptoMacVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoMacVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKdfDeriveKeyRequestView;
                    pub type CryptoKdfDeriveKeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKdfDeriveKeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKdfDeriveKeyResultView;
                    pub type CryptoKdfDeriveKeyResultOwnedView =
                        crate::GuardedOwnedView<CryptoKdfDeriveKeyResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoArgon2idDeriveRequestView;
                    pub type CryptoArgon2idDeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoArgon2idDeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveRequestView;
                    pub type CryptoHkdfDeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfDeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHkdfDeriveResultView;
                    pub type CryptoHkdfDeriveResultOwnedView =
                        crate::GuardedOwnedView<CryptoHkdfDeriveResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwaConcatKdfSha256DeriveRequestView;
                    pub type CryptoJwaConcatKdfSha256DeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoJwaConcatKdfSha256DeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwaConcatKdfSha256DeriveResultView;
                    pub type CryptoJwaConcatKdfSha256DeriveResultOwnedView =
                        crate::GuardedOwnedView<CryptoJwaConcatKdfSha256DeriveResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKmac256DeriveRequestView;
                    pub type CryptoKmac256DeriveRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKmac256DeriveRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKmac256DeriveResultView;
                    pub type CryptoKmac256DeriveResultOwnedView =
                        crate::GuardedOwnedView<CryptoKmac256DeriveResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyWrapRequestView;
                    pub type CryptoKeyWrapRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKeyWrapRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyWrapResultView;
                    pub type CryptoKeyWrapResultOwnedView =
                        crate::GuardedOwnedView<CryptoKeyWrapResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyUnwrapRequestView;
                    pub type CryptoKeyUnwrapRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKeyUnwrapRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyUnwrapResultView;
                    pub type CryptoKeyUnwrapResultOwnedView =
                        crate::GuardedOwnedView<CryptoKeyUnwrapResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureGenerateKeyPairRequestView;
                    pub type CryptoSignatureGenerateKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSignatureGenerateKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureDeriveKeyPairRequestView;
                    pub type CryptoSignatureDeriveKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSignatureDeriveKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureSignRequestView;
                    pub type CryptoSignatureSignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSignatureSignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureSignResultView;
                    pub type CryptoSignatureSignResultOwnedView =
                        crate::GuardedOwnedView<CryptoSignatureSignResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoBip340SchnorrSignRequestView;
                    pub type CryptoBip340SchnorrSignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoBip340SchnorrSignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSignatureVerifyRequestView;
                    pub type CryptoSignatureVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSignatureVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaVerifyRequestView;
                    pub type CryptoRsaVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoRsaVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveSharedSecretRequestView;
                    pub type CryptoKeyAgreementDeriveSharedSecretRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoKeyAgreementDeriveSharedSecretRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveSharedSecretResultView;
                    pub type CryptoKeyAgreementDeriveSharedSecretResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoKeyAgreementDeriveSharedSecretResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementDeriveKeyPairRequestView;
                    pub type CryptoKeyAgreementDeriveKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoKeyAgreementDeriveKeyPairRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemGenerateKeyPairRequestView;
                    pub type CryptoKemGenerateKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKemGenerateKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDeriveKeyPairRequestView;
                    pub type CryptoKemDeriveKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKemDeriveKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemEncapsulateRequestView;
                    pub type CryptoKemEncapsulateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKemEncapsulateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDecapsulateRequestView;
                    pub type CryptoKemDecapsulateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoKemDecapsulateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemDecapsulateResultView;
                    pub type CryptoKemDecapsulateResultOwnedView =
                        crate::GuardedOwnedView<CryptoKemDecapsulateResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSealRequestView;
                    pub type CryptoHpkeSealRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSealRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeOpenRequestView;
                    pub type CryptoHpkeOpenRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeOpenRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeOpenResultView;
                    pub type CryptoHpkeOpenResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeOpenResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeGenerateKeyPairRequestView;
                    pub type CryptoHpkeGenerateKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeGenerateKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeDeriveKeyPairRequestView;
                    pub type CryptoHpkeDeriveKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeDeriveKeyPairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportRequestView;
                    pub type CryptoHpkeSenderExportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSenderExportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverExportRequestView;
                    pub type CryptoHpkeReceiverExportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeReceiverExportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportResultView;
                    pub type CryptoHpkeSenderExportResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSenderExportResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverExportResultView;
                    pub type CryptoHpkeReceiverExportResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeReceiverExportResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSealRequestView;
                    pub type CryptoHpkePskSealRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskSealRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskOpenRequestView;
                    pub type CryptoHpkePskOpenRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskOpenRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyPairView;
                    pub type CryptoKeyPairOwnedView =
                        crate::GuardedOwnedView<CryptoKeyPairView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemEncapsulationView;
                    pub type CryptoKemEncapsulationOwnedView =
                        crate::GuardedOwnedView<CryptoKemEncapsulationView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSealedMessageView;
                    pub type CryptoHpkeSealedMessageOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSealedMessageView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::AndroidPlatformKeyPolicyView;
                    pub use crate::generated::raw::reallyme::crypto::v1::ApplePlatformKeyPolicyOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::ApplePlatformKeyPolicyView;
                    pub type AndroidPlatformKeyPolicyOwnedView =
                        crate::GuardedOwnedView<AndroidPlatformKeyPolicyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::PlatformKeyPolicyView;
                    pub type PlatformKeyPolicyOwnedView =
                        crate::GuardedOwnedView<PlatformKeyPolicyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformPrivateKeyHandleView;
                    pub type CryptoPlatformPrivateKeyHandleOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformPrivateKeyHandleView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGenerateRequestView;
                    pub type CryptoPlatformKeyGenerateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyGenerateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGenerateResultView;
                    pub type CryptoPlatformKeyGenerateResultOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyGenerateResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGetPublicKeyRequestView;
                    pub type CryptoPlatformKeyGetPublicKeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyGetPublicKeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyGetPublicKeyResultView;
                    pub type CryptoPlatformKeyGetPublicKeyResultOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyGetPublicKeyResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureSignRequestView;
                    pub type CryptoPlatformSignatureSignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformSignatureSignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureSignResultView;
                    pub type CryptoPlatformSignatureSignResultOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformSignatureSignResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformSignatureVerifyRequestView;
                    pub type CryptoPlatformSignatureVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformSignatureVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAgreementDeriveSharedSecretRequestView;
                    pub type CryptoPlatformKeyAgreementDeriveSharedSecretRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPlatformKeyAgreementDeriveSharedSecretRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAgreementDeriveSharedSecretResultView;
                    pub type CryptoPlatformKeyAgreementDeriveSharedSecretResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPlatformKeyAgreementDeriveSharedSecretResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyDeleteRequestView;
                    pub type CryptoPlatformKeyDeleteRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyDeleteRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestRequestView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyDeleteResultOwnedView;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyDeleteResultView;
                    pub type CryptoPlatformKeyAttestRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyAttestRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestationCertificateView;
                    pub type CryptoPlatformKeyAttestationCertificateOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPlatformKeyAttestationCertificateView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPlatformKeyAttestResultView;
                    pub type CryptoPlatformKeyAttestResultOwnedView =
                        crate::GuardedOwnedView<CryptoPlatformKeyAttestResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationResultView;
                    pub type CryptoVerificationResultOwnedView =
                        crate::GuardedOwnedView<CryptoVerificationResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderCapabilityView;
                    pub type CryptoProviderCapabilityOwnedView =
                        crate::GuardedOwnedView<CryptoProviderCapabilityView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoProviderCapabilitySetView;
                    pub type CryptoProviderCapabilitySetOwnedView =
                        crate::GuardedOwnedView<CryptoProviderCapabilitySetView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupRequestView;
                    pub type CryptoHpkePskSenderSetupRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskSenderSetupRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupResultView;
                    pub type CryptoHpkePskSenderSetupResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskSenderSetupResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskReceiverSetupRequestView;
                    pub type CryptoHpkePskReceiverSetupRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskReceiverSetupRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskReceiverSetupResultView;
                    pub type CryptoHpkePskReceiverSetupResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePskReceiverSetupResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderSealRequestView;
                    pub type CryptoHpkeSenderSealRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSenderSealRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderSealResultView;
                    pub type CryptoHpkeSenderSealResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeSenderSealResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverOpenRequestView;
                    pub type CryptoHpkeReceiverOpenRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeReceiverOpenRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeReceiverOpenResultView;
                    pub type CryptoHpkeReceiverOpenResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeReceiverOpenResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseCapabilitiesView;
                    pub type CryptoHpkeP256BaseCapabilitiesOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BaseCapabilitiesView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BasePublicKeyView;
                    pub type CryptoHpkeP256BasePublicKeyOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BasePublicKeyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseSealRequestView;
                    pub type CryptoHpkeP256BaseSealRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BaseSealRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseOpenRequestView;
                    pub type CryptoHpkeP256BaseOpenRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BaseOpenRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseSealedResultView;
                    pub type CryptoHpkeP256BaseSealedResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BaseSealedResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseOpenResultView;
                    pub type CryptoHpkeP256BaseOpenResultOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeP256BaseOpenResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeComponentCapabilityView;
                    pub type CryptoHpkeComponentCapabilityOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeComponentCapabilityView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseRecipientImportRequestView;
                    pub type CryptoHpkeP256BaseRecipientImportRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoHpkeP256BaseRecipientImportRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeP256BaseRecipientGenerateRequestView;
                    pub type CryptoHpkeP256BaseRecipientGenerateRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoHpkeP256BaseRecipientGenerateRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomBytesRequestView;
                    pub type CryptoRandomBytesRequestOwnedView =
                        crate::GuardedOwnedView<CryptoRandomBytesRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRandomBytesResultView;
                    pub type CryptoRandomBytesResultOwnedView =
                        crate::GuardedOwnedView<CryptoRandomBytesResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeCompareRequestView;
                    pub type CryptoConstantTimeCompareRequestOwnedView =
                        crate::GuardedOwnedView<CryptoConstantTimeCompareRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeCompareResultView;
                    pub type CryptoConstantTimeCompareResultOwnedView =
                        crate::GuardedOwnedView<CryptoConstantTimeCompareResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoConstantTimeRequireEqualResultView;
                    pub type CryptoConstantTimeRequireEqualResultOwnedView =
                        crate::GuardedOwnedView<CryptoConstantTimeRequireEqualResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPoseidon2HashRequestView;
                    pub type CryptoPoseidon2HashRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPoseidon2HashRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPoseidon2HashResultView;
                    pub type CryptoPoseidon2HashResultOwnedView =
                        crate::GuardedOwnedView<CryptoPoseidon2HashResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJwkRequestView;
                    pub type CryptoPublicKeyToJwkRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyToJwkRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJwkResultView;
                    pub type CryptoPublicKeyToJwkResultOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyToJwkResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToJcsResultView;
                    pub type CryptoPublicKeyToJcsResultOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyToJcsResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkToMultikeyRequestView;
                    pub type CryptoJwkToMultikeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoJwkToMultikeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoJwkToMultikeyResultView;
                    pub type CryptoJwkToMultikeyResultOwnedView =
                        crate::GuardedOwnedView<CryptoJwkToMultikeyResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMultikeyToJwkRequestView;
                    pub type CryptoMultikeyToJwkRequestOwnedView =
                        crate::GuardedOwnedView<CryptoMultikeyToJwkRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoMultikeyToJwkResultView;
                    pub type CryptoMultikeyToJwkResultOwnedView =
                        crate::GuardedOwnedView<CryptoMultikeyToJwkResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoGenerateMultikeyKeypairRequestView;
                    pub type CryptoGenerateMultikeyKeypairRequestOwnedView =
                        crate::GuardedOwnedView<CryptoGenerateMultikeyKeypairRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoGenerateMultikeyKeypairResultView;
                    pub type CryptoGenerateMultikeyKeypairResultOwnedView =
                        crate::GuardedOwnedView<CryptoGenerateMultikeyKeypairResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToMultikeyRequestView;
                    pub type CryptoPublicKeyToMultikeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyToMultikeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyToMultikeyResultView;
                    pub type CryptoPublicKeyToMultikeyResultOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyToMultikeyResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationMethodMultikeyRequestView;
                    pub type CryptoVerificationMethodMultikeyRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoVerificationMethodMultikeyRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoVerificationMethodMultikeyResultView;
                    pub type CryptoVerificationMethodMultikeyResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoVerificationMethodMultikeyResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicRepresentativesRequestView;
                    pub type CryptoRsaPublicRepresentativesRequestOwnedView =
                        crate::GuardedOwnedView<CryptoRsaPublicRepresentativesRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPublicRepresentativesResultView;
                    pub type CryptoRsaPublicRepresentativesResultOwnedView =
                        crate::GuardedOwnedView<CryptoRsaPublicRepresentativesResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoRsaPssVerifyRequestView;
                    pub type CryptoRsaPssVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoRsaPssVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::JsonWebKeyView;
                    pub type JsonWebKeyOwnedView = crate::GuardedOwnedView<JsonWebKeyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::JsonWebKeySetView;
                    pub type JsonWebKeySetOwnedView =
                        crate::GuardedOwnedView<JsonWebKeySetView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeKeyCapabilitiesView;
                    pub type CryptoNativeKeyCapabilitiesOwnedView =
                        crate::GuardedOwnedView<CryptoNativeKeyCapabilitiesView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeKeyGenerateRequestView;
                    pub type CryptoNativeKeyGenerateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoNativeKeyGenerateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativePublicKeyRequestView;
                    pub type CryptoNativePublicKeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoNativePublicKeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaMessageInputView;
                    pub type CryptoEcdsaMessageInputOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaMessageInputView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPrehashInputView;
                    pub type CryptoEcdsaPrehashInputOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaPrehashInputView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaInputView;
                    pub type CryptoEcdsaInputOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaInputView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignOptionsView;
                    pub type CryptoEcdsaSignOptionsOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaSignOptionsView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyGenerateRequestView;
                    pub type CryptoEcdsaKeyGenerateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaKeyGenerateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyImportRequestView;
                    pub type CryptoEcdsaKeyImportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaKeyImportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPublicKeyView;
                    pub type CryptoEcdsaPublicKeyOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaPublicKeyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaKeyDescriptorView;
                    pub type CryptoEcdsaKeyDescriptorOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaKeyDescriptorView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignRequestView;
                    pub type CryptoEcdsaSignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaSignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeSignatureResultView;
                    pub type CryptoNativeSignatureResultOwnedView =
                        crate::GuardedOwnedView<CryptoNativeSignatureResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaVerifyRequestView;
                    pub type CryptoEcdsaVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeVerificationResultView;
                    pub type CryptoNativeVerificationResultOwnedView =
                        crate::GuardedOwnedView<CryptoNativeVerificationResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaAgreementRequestView;
                    pub type CryptoEcdsaAgreementRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaAgreementRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoNativeAgreementResultView;
                    pub type CryptoNativeAgreementResultOwnedView =
                        crate::GuardedOwnedView<CryptoNativeAgreementResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448SupportRequestView;
                    pub type CryptoEd448SupportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEd448SupportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448KeyImportRequestView;
                    pub type CryptoEd448KeyImportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEd448KeyImportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448PublicKeyView;
                    pub type CryptoEd448PublicKeyOwnedView =
                        crate::GuardedOwnedView<CryptoEd448PublicKeyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448KeyDescriptorView;
                    pub type CryptoEd448KeyDescriptorOwnedView =
                        crate::GuardedOwnedView<CryptoEd448KeyDescriptorView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448OrdinarySignRequestView;
                    pub type CryptoEd448OrdinarySignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEd448OrdinarySignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEd448OrdinaryVerifyRequestView;
                    pub type CryptoEd448OrdinaryVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEd448OrdinaryVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarGenerateRequestView;
                    pub type CryptoPrimeGroupScalarGenerateRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupScalarGenerateRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarImportRequestView;
                    pub type CryptoPrimeGroupScalarImportRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupScalarImportRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupElementView;
                    pub type CryptoPrimeGroupElementOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupElementView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupScalarDescriptorView;
                    pub type CryptoPrimeGroupScalarDescriptorOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupScalarDescriptorView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupMultiplyRequestView;
                    pub type CryptoPrimeGroupMultiplyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupMultiplyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupLinearCombinationRequestView;
                    pub type CryptoPrimeGroupLinearCombinationRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPrimeGroupLinearCombinationRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupReduceToFieldRequestView;
                    pub type CryptoPrimeGroupReduceToFieldRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupReduceToFieldRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupFieldValueView;
                    pub type CryptoPrimeGroupFieldValueOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupFieldValueView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDomainRequestView;
                    pub type CryptoPrimeGroupDomainRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupDomainRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDhParametersValidationRequestView;
                    pub type CryptoPrimeGroupDhParametersValidationRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPrimeGroupDhParametersValidationRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDhParametersValidationResultView;
                    pub type CryptoPrimeGroupDhParametersValidationResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoPrimeGroupDhParametersValidationResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupCurveCoefficientsView;
                    pub type CryptoPrimeGroupCurveCoefficientsOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupCurveCoefficientsView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPrimeGroupDomainResultView;
                    pub type CryptoPrimeGroupDomainResultOwnedView =
                        crate::GuardedOwnedView<CryptoPrimeGroupDomainResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448PrivateKeyInputView;
                    pub type CryptoX448PrivateKeyInputOwnedView =
                        crate::GuardedOwnedView<CryptoX448PrivateKeyInputView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448PublicKeyView;
                    pub type CryptoX448PublicKeyOwnedView =
                        crate::GuardedOwnedView<CryptoX448PublicKeyView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448KeyDescriptorView;
                    pub type CryptoX448KeyDescriptorOwnedView =
                        crate::GuardedOwnedView<CryptoX448KeyDescriptorView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoX448AgreementRequestView;
                    pub type CryptoX448AgreementRequestOwnedView =
                        crate::GuardedOwnedView<CryptoX448AgreementRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaSignatureTranscodeRequestView;
                    pub type CryptoEcdsaSignatureTranscodeRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaSignatureTranscodeRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSecp256k1SignatureTranscodeRequestView;
                    pub type CryptoSecp256k1SignatureTranscodeRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoSecp256k1SignatureTranscodeRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SignatureNormalizeRequestView;
                    pub type CryptoP256SignatureNormalizeRequestOwnedView =
                        crate::GuardedOwnedView<CryptoP256SignatureNormalizeRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256LowSSignRequestView;
                    pub type CryptoP256LowSSignRequestOwnedView =
                        crate::GuardedOwnedView<CryptoP256LowSSignRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256LowSVerifyRequestView;
                    pub type CryptoP256LowSVerifyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoP256LowSVerifyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256PrivateKeyContainerImportRequestView;
                    pub type CryptoP256PrivateKeyContainerImportRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256PrivateKeyContainerImportRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256PublicKeyContainerImportRequestView;
                    pub type CryptoP256PublicKeyContainerImportRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256PublicKeyContainerImportRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256CompressedPublicKeyRequestView;
                    pub type CryptoP256CompressedPublicKeyRequestOwnedView =
                        crate::GuardedOwnedView<CryptoP256CompressedPublicKeyRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoEcdsaPublicKeyValidationRequestView;
                    pub type CryptoEcdsaPublicKeyValidationRequestOwnedView =
                        crate::GuardedOwnedView<CryptoEcdsaPublicKeyValidationRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyFormatRequestView;
                    pub type CryptoPublicKeyFormatRequestOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyFormatRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyBytesView;
                    pub type CryptoPublicKeyBytesOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyBytesView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyAffineCoordinatesView;
                    pub type CryptoPublicKeyAffineCoordinatesOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyAffineCoordinatesView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoPublicKeyFormatResultView;
                    pub type CryptoPublicKeyFormatResultOwnedView =
                        crate::GuardedOwnedView<CryptoPublicKeyFormatResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSubjectKeyIdentifierRequestView;
                    pub type CryptoSubjectKeyIdentifierRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSubjectKeyIdentifierRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSubjectKeyIdentifierResultView;
                    pub type CryptoSubjectKeyIdentifierResultOwnedView =
                        crate::GuardedOwnedView<CryptoSubjectKeyIdentifierResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleEncodeRequestView;
                    pub type CryptoP256SecureEnclaveHandleEncodeRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256SecureEnclaveHandleEncodeRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleEncodeResultView;
                    pub type CryptoP256SecureEnclaveHandleEncodeResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256SecureEnclaveHandleEncodeResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleDecodeRequestView;
                    pub type CryptoP256SecureEnclaveHandleDecodeRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256SecureEnclaveHandleDecodeRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoP256SecureEnclaveHandleDecodeResultView;
                    pub type CryptoP256SecureEnclaveHandleDecodeResultOwnedView =
                        crate::GuardedOwnedView<
                            CryptoP256SecureEnclaveHandleDecodeResultView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKemConformanceEncapsulateRequestView;
                    pub type CryptoKemConformanceEncapsulateRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoKemConformanceEncapsulateRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeBaseSealConformanceRequestView;
                    pub type CryptoHpkeBaseSealConformanceRequestOwnedView =
                        crate::GuardedOwnedView<CryptoHpkeBaseSealConformanceRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeSenderExportConformanceRequestView;
                    pub type CryptoHpkeSenderExportConformanceRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoHpkeSenderExportConformanceRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePskSenderSetupConformanceRequestView;
                    pub type CryptoHpkePskSenderSetupConformanceRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoHpkePskSenderSetupConformanceRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkeExactWidthDeriveKeyPairRequestView;
                    pub type CryptoHpkeExactWidthDeriveKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoHpkeExactWidthDeriveKeyPairRequestView<'static>,
                        >;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoHpkePublicKeyDescriptorView;
                    pub type CryptoHpkePublicKeyDescriptorOwnedView =
                        crate::GuardedOwnedView<CryptoHpkePublicKeyDescriptorView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoShake256ExpandRequestView;
                    pub type CryptoShake256ExpandRequestOwnedView =
                        crate::GuardedOwnedView<CryptoShake256ExpandRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoShake256ExpandResultView;
                    pub type CryptoShake256ExpandResultOwnedView =
                        crate::GuardedOwnedView<CryptoShake256ExpandResultView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoSecp256k1AgreementRequestView;
                    pub type CryptoSecp256k1AgreementRequestOwnedView =
                        crate::GuardedOwnedView<CryptoSecp256k1AgreementRequestView<'static>>;
                    pub use crate::generated::raw::reallyme::crypto::v1::CryptoKeyAgreementGenerateKeyPairRequestView;
                    pub type CryptoKeyAgreementGenerateKeyPairRequestOwnedView =
                        crate::GuardedOwnedView<
                            CryptoKeyAgreementGenerateKeyPairRequestView<'static>,
                        >;
                }
                pub use crate::generated::raw::reallyme::crypto::v1::__buffa::register_types;
            }
            pub use self::__buffa::view::{
                AndroidPlatformKeyPolicyOwnedView, AndroidPlatformKeyPolicyView,
            };
            pub use self::__buffa::view::{
                ApplePlatformKeyPolicyOwnedView, ApplePlatformKeyPolicyView,
            };
            pub use self::__buffa::view::{Argon2CapsOwnedView, Argon2CapsView};
            pub use self::__buffa::view::{Argon2ParamsProfileOwnedView, Argon2ParamsProfileView};
            pub use self::__buffa::view::{
                CryptoAeadOpenRequestOwnedView, CryptoAeadOpenRequestView,
            };
            pub use self::__buffa::view::{
                CryptoAeadOpenResultOwnedView, CryptoAeadOpenResultView,
            };
            pub use self::__buffa::view::{
                CryptoAeadSealRequestOwnedView, CryptoAeadSealRequestView,
            };
            pub use self::__buffa::view::{
                CryptoAeadSealResultOwnedView, CryptoAeadSealResultView,
            };
            pub use self::__buffa::view::{
                CryptoAlgorithmIdentifierOwnedView, CryptoAlgorithmIdentifierView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2BudgetFitRequestOwnedView, CryptoArgon2BudgetFitRequestView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2FixedDeriveRequestOwnedView, CryptoArgon2FixedDeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2MobileUnlockRequestOwnedView, CryptoArgon2MobileUnlockRequestView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2PlatformResolveRequestOwnedView, CryptoArgon2PlatformResolveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2idDeriveRequestOwnedView, CryptoArgon2idDeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoArgon2idProfileIdentifierOwnedView, CryptoArgon2idProfileIdentifierView,
            };
            pub use self::__buffa::view::{CryptoBackendErrorOwnedView, CryptoBackendErrorView};
            pub use self::__buffa::view::{
                CryptoBip340SchnorrSignRequestOwnedView, CryptoBip340SchnorrSignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoConstantTimeCompareRequestOwnedView, CryptoConstantTimeCompareRequestView,
            };
            pub use self::__buffa::view::{
                CryptoConstantTimeCompareResultOwnedView, CryptoConstantTimeCompareResultView,
            };
            pub use self::__buffa::view::{
                CryptoConstantTimeRequireEqualResultOwnedView,
                CryptoConstantTimeRequireEqualResultView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaAgreementRequestOwnedView, CryptoEcdsaAgreementRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaCurveIdentifierOwnedView, CryptoEcdsaCurveIdentifierView,
            };
            pub use self::__buffa::view::{CryptoEcdsaInputOwnedView, CryptoEcdsaInputView};
            pub use self::__buffa::view::{
                CryptoEcdsaKeyDescriptorOwnedView, CryptoEcdsaKeyDescriptorView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaKeyGenerateRequestOwnedView, CryptoEcdsaKeyGenerateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaKeyImportRequestOwnedView, CryptoEcdsaKeyImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaMessageInputOwnedView, CryptoEcdsaMessageInputView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaPrehashInputOwnedView, CryptoEcdsaPrehashInputView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaPublicKeyOwnedView, CryptoEcdsaPublicKeyView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaPublicKeyValidationRequestOwnedView,
                CryptoEcdsaPublicKeyValidationRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaSignOptionsOwnedView, CryptoEcdsaSignOptionsView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaSignRequestOwnedView, CryptoEcdsaSignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaSignatureTranscodeRequestOwnedView,
                CryptoEcdsaSignatureTranscodeRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEcdsaVerifyRequestOwnedView, CryptoEcdsaVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEd448KeyDescriptorOwnedView, CryptoEd448KeyDescriptorView,
            };
            pub use self::__buffa::view::{
                CryptoEd448KeyImportRequestOwnedView, CryptoEd448KeyImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEd448OrdinarySignRequestOwnedView, CryptoEd448OrdinarySignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEd448OrdinaryVerifyRequestOwnedView, CryptoEd448OrdinaryVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoEd448PublicKeyOwnedView, CryptoEd448PublicKeyView,
            };
            pub use self::__buffa::view::{
                CryptoEd448SupportRequestOwnedView, CryptoEd448SupportRequestView,
            };
            pub use self::__buffa::view::{CryptoErrorOwnedView, CryptoErrorView};
            pub use self::__buffa::view::{
                CryptoGenerateMultikeyKeypairRequestOwnedView,
                CryptoGenerateMultikeyKeypairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoGenerateMultikeyKeypairResultOwnedView,
                CryptoGenerateMultikeyKeypairResultView,
            };
            pub use self::__buffa::view::{CryptoHashRequestOwnedView, CryptoHashRequestView};
            pub use self::__buffa::view::{CryptoHashResultOwnedView, CryptoHashResultView};
            pub use self::__buffa::view::{
                CryptoHkdfDeriveInputsOwnedView, CryptoHkdfDeriveInputsView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfDeriveRequestOwnedView, CryptoHkdfDeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfDeriveResultOwnedView, CryptoHkdfDeriveResultView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfDomainKey32RequestOwnedView, CryptoHkdfDomainKey32RequestView,
            };
            pub use self::__buffa::view::{CryptoHkdfDomainTagOwnedView, CryptoHkdfDomainTagView};
            pub use self::__buffa::view::{
                CryptoHkdfExpandSha384RequestOwnedView, CryptoHkdfExpandSha384RequestView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfExtractSha384RequestOwnedView, CryptoHkdfExtractSha384RequestView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfExtractSha384ResultOwnedView, CryptoHkdfExtractSha384ResultView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfNativeDeriveRequestOwnedView, CryptoHkdfNativeDeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfNativeDeriveResultOwnedView, CryptoHkdfNativeDeriveResultView,
            };
            pub use self::__buffa::view::{
                CryptoHkdfSuiteIdentifierOwnedView, CryptoHkdfSuiteIdentifierView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeBaseSealConformanceRequestOwnedView,
                CryptoHpkeBaseSealConformanceRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeComponentCapabilityOwnedView, CryptoHpkeComponentCapabilityView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeDeriveKeyPairRequestOwnedView, CryptoHpkeDeriveKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeExactWidthDeriveKeyPairRequestOwnedView,
                CryptoHpkeExactWidthDeriveKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeGenerateKeyPairRequestOwnedView, CryptoHpkeGenerateKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeOpenRequestOwnedView, CryptoHpkeOpenRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeOpenResultOwnedView, CryptoHpkeOpenResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseCapabilitiesOwnedView, CryptoHpkeP256BaseCapabilitiesView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseOpenRequestOwnedView, CryptoHpkeP256BaseOpenRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseOpenResultOwnedView, CryptoHpkeP256BaseOpenResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BasePublicKeyOwnedView, CryptoHpkeP256BasePublicKeyView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseRecipientGenerateRequestOwnedView,
                CryptoHpkeP256BaseRecipientGenerateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseRecipientImportRequestOwnedView,
                CryptoHpkeP256BaseRecipientImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseSealRequestOwnedView, CryptoHpkeP256BaseSealRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeP256BaseSealedResultOwnedView, CryptoHpkeP256BaseSealedResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskOpenRequestOwnedView, CryptoHpkePskOpenRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskReceiverSetupRequestOwnedView, CryptoHpkePskReceiverSetupRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskReceiverSetupResultOwnedView, CryptoHpkePskReceiverSetupResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskSealRequestOwnedView, CryptoHpkePskSealRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskSenderSetupConformanceRequestOwnedView,
                CryptoHpkePskSenderSetupConformanceRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskSenderSetupRequestOwnedView, CryptoHpkePskSenderSetupRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePskSenderSetupResultOwnedView, CryptoHpkePskSenderSetupResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkePublicKeyDescriptorOwnedView, CryptoHpkePublicKeyDescriptorView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeReceiverExportRequestOwnedView, CryptoHpkeReceiverExportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeReceiverExportResultOwnedView, CryptoHpkeReceiverExportResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeReceiverOpenRequestOwnedView, CryptoHpkeReceiverOpenRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeReceiverOpenResultOwnedView, CryptoHpkeReceiverOpenResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSealRequestOwnedView, CryptoHpkeSealRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSealedMessageOwnedView, CryptoHpkeSealedMessageView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSenderExportConformanceRequestOwnedView,
                CryptoHpkeSenderExportConformanceRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSenderExportRequestOwnedView, CryptoHpkeSenderExportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSenderExportResultOwnedView, CryptoHpkeSenderExportResultView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSenderSealRequestOwnedView, CryptoHpkeSenderSealRequestView,
            };
            pub use self::__buffa::view::{
                CryptoHpkeSenderSealResultOwnedView, CryptoHpkeSenderSealResultView,
            };
            pub use self::__buffa::view::{
                CryptoJwaConcatKdfSha256DeriveRequestOwnedView,
                CryptoJwaConcatKdfSha256DeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoJwaConcatKdfSha256DeriveResultOwnedView,
                CryptoJwaConcatKdfSha256DeriveResultView,
            };
            pub use self::__buffa::view::{CryptoJwkOptionsOwnedView, CryptoJwkOptionsView};
            pub use self::__buffa::view::{
                CryptoJwkToMultikeyRequestOwnedView, CryptoJwkToMultikeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoJwkToMultikeyResultOwnedView, CryptoJwkToMultikeyResultView,
            };
            pub use self::__buffa::view::{
                CryptoKdfDeriveKeyRequestOwnedView, CryptoKdfDeriveKeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKdfDeriveKeyResultOwnedView, CryptoKdfDeriveKeyResultView,
            };
            pub use self::__buffa::view::{
                CryptoKemConformanceEncapsulateRequestOwnedView,
                CryptoKemConformanceEncapsulateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKemDecapsulateRequestOwnedView, CryptoKemDecapsulateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKemDecapsulateResultOwnedView, CryptoKemDecapsulateResultView,
            };
            pub use self::__buffa::view::{
                CryptoKemDeriveKeyPairRequestOwnedView, CryptoKemDeriveKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKemEncapsulateRequestOwnedView, CryptoKemEncapsulateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKemEncapsulationOwnedView, CryptoKemEncapsulationView,
            };
            pub use self::__buffa::view::{
                CryptoKemGenerateKeyPairRequestOwnedView, CryptoKemGenerateKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKeyAgreementDeriveKeyPairRequestOwnedView,
                CryptoKeyAgreementDeriveKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKeyAgreementDeriveSharedSecretRequestOwnedView,
                CryptoKeyAgreementDeriveSharedSecretRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKeyAgreementDeriveSharedSecretResultOwnedView,
                CryptoKeyAgreementDeriveSharedSecretResultView,
            };
            pub use self::__buffa::view::{
                CryptoKeyAgreementGenerateKeyPairRequestOwnedView,
                CryptoKeyAgreementGenerateKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKeyAlgorithmIdentifierOwnedView, CryptoKeyAlgorithmIdentifierView,
            };
            pub use self::__buffa::view::{CryptoKeyPairOwnedView, CryptoKeyPairView};
            pub use self::__buffa::view::{
                CryptoKeyUnwrapRequestOwnedView, CryptoKeyUnwrapRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKeyUnwrapResultOwnedView, CryptoKeyUnwrapResultView,
            };
            pub use self::__buffa::view::{
                CryptoKeyWrapRequestOwnedView, CryptoKeyWrapRequestView,
            };
            pub use self::__buffa::view::{CryptoKeyWrapResultOwnedView, CryptoKeyWrapResultView};
            pub use self::__buffa::view::{
                CryptoKmac256DeriveRequestOwnedView, CryptoKmac256DeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoKmac256DeriveResultOwnedView, CryptoKmac256DeriveResultView,
            };
            pub use self::__buffa::view::{
                CryptoMacAuthenticateRequestOwnedView, CryptoMacAuthenticateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoMacAuthenticateResultOwnedView, CryptoMacAuthenticateResultView,
            };
            pub use self::__buffa::view::{
                CryptoMacVerifyRequestOwnedView, CryptoMacVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoMaterialPolicyQueryRequestOwnedView, CryptoMaterialPolicyQueryRequestView,
            };
            pub use self::__buffa::view::{
                CryptoMultikeyToJwkRequestOwnedView, CryptoMultikeyToJwkRequestView,
            };
            pub use self::__buffa::view::{
                CryptoMultikeyToJwkResultOwnedView, CryptoMultikeyToJwkResultView,
            };
            pub use self::__buffa::view::{
                CryptoNativeAgreementResultOwnedView, CryptoNativeAgreementResultView,
            };
            pub use self::__buffa::view::{
                CryptoNativeKeyCapabilitiesOwnedView, CryptoNativeKeyCapabilitiesView,
            };
            pub use self::__buffa::view::{
                CryptoNativeKeyGenerateRequestOwnedView, CryptoNativeKeyGenerateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoNativePublicKeyRequestOwnedView, CryptoNativePublicKeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoNativeSignatureResultOwnedView, CryptoNativeSignatureResultView,
            };
            pub use self::__buffa::view::{
                CryptoNativeVerificationResultOwnedView, CryptoNativeVerificationResultView,
            };
            pub use self::__buffa::view::{
                CryptoOperationRequestOwnedView, CryptoOperationRequestView,
            };
            pub use self::__buffa::view::{
                CryptoOperationResponseOwnedView, CryptoOperationResponseView,
            };
            pub use self::__buffa::view::{
                CryptoOperationResultOwnedView, CryptoOperationResultView,
            };
            pub use self::__buffa::view::{
                CryptoP256CompressedPublicKeyRequestOwnedView,
                CryptoP256CompressedPublicKeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256LowSSignRequestOwnedView, CryptoP256LowSSignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256LowSVerifyRequestOwnedView, CryptoP256LowSVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256PrivateKeyContainerImportRequestOwnedView,
                CryptoP256PrivateKeyContainerImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256PublicKeyContainerImportRequestOwnedView,
                CryptoP256PublicKeyContainerImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256SecureEnclaveHandleDecodeRequestOwnedView,
                CryptoP256SecureEnclaveHandleDecodeRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256SecureEnclaveHandleDecodeResultOwnedView,
                CryptoP256SecureEnclaveHandleDecodeResultView,
            };
            pub use self::__buffa::view::{
                CryptoP256SecureEnclaveHandleEncodeRequestOwnedView,
                CryptoP256SecureEnclaveHandleEncodeRequestView,
            };
            pub use self::__buffa::view::{
                CryptoP256SecureEnclaveHandleEncodeResultOwnedView,
                CryptoP256SecureEnclaveHandleEncodeResultView,
            };
            pub use self::__buffa::view::{
                CryptoP256SignatureNormalizeRequestOwnedView,
                CryptoP256SignatureNormalizeRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPbkdf2PrfIdentifierOwnedView, CryptoPbkdf2PrfIdentifierView,
            };
            pub use self::__buffa::view::{
                CryptoPbkdf2StandardsDeriveRequestOwnedView, CryptoPbkdf2StandardsDeriveRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyAgreementDeriveSharedSecretRequestOwnedView,
                CryptoPlatformKeyAgreementDeriveSharedSecretRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyAgreementDeriveSharedSecretResultOwnedView,
                CryptoPlatformKeyAgreementDeriveSharedSecretResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyAttestRequestOwnedView, CryptoPlatformKeyAttestRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyAttestResultOwnedView, CryptoPlatformKeyAttestResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyAttestationCertificateOwnedView,
                CryptoPlatformKeyAttestationCertificateView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyDeleteRequestOwnedView, CryptoPlatformKeyDeleteRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyDeleteResultOwnedView, CryptoPlatformKeyDeleteResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyGenerateRequestOwnedView, CryptoPlatformKeyGenerateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyGenerateResultOwnedView, CryptoPlatformKeyGenerateResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyGetPublicKeyRequestOwnedView,
                CryptoPlatformKeyGetPublicKeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformKeyGetPublicKeyResultOwnedView,
                CryptoPlatformKeyGetPublicKeyResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformPrivateKeyHandleOwnedView, CryptoPlatformPrivateKeyHandleView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformSignatureSignRequestOwnedView, CryptoPlatformSignatureSignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformSignatureSignResultOwnedView, CryptoPlatformSignatureSignResultView,
            };
            pub use self::__buffa::view::{
                CryptoPlatformSignatureVerifyRequestOwnedView,
                CryptoPlatformSignatureVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPoseidon2HashRequestOwnedView, CryptoPoseidon2HashRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPoseidon2HashResultOwnedView, CryptoPoseidon2HashResultView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupCurveCoefficientsOwnedView, CryptoPrimeGroupCurveCoefficientsView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupDhParametersValidationRequestOwnedView,
                CryptoPrimeGroupDhParametersValidationRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupDhParametersValidationResultOwnedView,
                CryptoPrimeGroupDhParametersValidationResultView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupDomainRequestOwnedView, CryptoPrimeGroupDomainRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupDomainResultOwnedView, CryptoPrimeGroupDomainResultView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupElementOwnedView, CryptoPrimeGroupElementView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupFieldValueOwnedView, CryptoPrimeGroupFieldValueView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupIdentifierOwnedView, CryptoPrimeGroupIdentifierView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupLinearCombinationRequestOwnedView,
                CryptoPrimeGroupLinearCombinationRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupMultiplyRequestOwnedView, CryptoPrimeGroupMultiplyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupReduceToFieldRequestOwnedView,
                CryptoPrimeGroupReduceToFieldRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupScalarDescriptorOwnedView, CryptoPrimeGroupScalarDescriptorView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupScalarGenerateRequestOwnedView,
                CryptoPrimeGroupScalarGenerateRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimeGroupScalarImportRequestOwnedView,
                CryptoPrimeGroupScalarImportRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPrimitiveErrorOwnedView, CryptoPrimitiveErrorView,
            };
            pub use self::__buffa::view::{
                CryptoProviderCapabilityOwnedView, CryptoProviderCapabilityView,
            };
            pub use self::__buffa::view::{
                CryptoProviderCapabilitySetOwnedView, CryptoProviderCapabilitySetView,
            };
            pub use self::__buffa::view::{CryptoProviderErrorOwnedView, CryptoProviderErrorView};
            pub use self::__buffa::view::{
                CryptoPublicKeyAffineCoordinatesOwnedView, CryptoPublicKeyAffineCoordinatesView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyBytesOwnedView, CryptoPublicKeyBytesView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyFormatRequestOwnedView, CryptoPublicKeyFormatRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyFormatResultOwnedView, CryptoPublicKeyFormatResultView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyToJcsResultOwnedView, CryptoPublicKeyToJcsResultView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyToJwkRequestOwnedView, CryptoPublicKeyToJwkRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyToJwkResultOwnedView, CryptoPublicKeyToJwkResultView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyToMultikeyRequestOwnedView, CryptoPublicKeyToMultikeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoPublicKeyToMultikeyResultOwnedView, CryptoPublicKeyToMultikeyResultView,
            };
            pub use self::__buffa::view::{
                CryptoRandomBytesRequestOwnedView, CryptoRandomBytesRequestView,
            };
            pub use self::__buffa::view::{
                CryptoRandomBytesResultOwnedView, CryptoRandomBytesResultView,
            };
            pub use self::__buffa::view::{
                CryptoRandomFillPolicyQueryRequestOwnedView, CryptoRandomFillPolicyQueryRequestView,
            };
            pub use self::__buffa::view::{
                CryptoRsaHashIdentifierOwnedView, CryptoRsaHashIdentifierView,
            };
            pub use self::__buffa::view::{CryptoRsaPssParamsOwnedView, CryptoRsaPssParamsView};
            pub use self::__buffa::view::{
                CryptoRsaPssVerifyRequestOwnedView, CryptoRsaPssVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoRsaPublicKeyDerEncodingIdentifierOwnedView,
                CryptoRsaPublicKeyDerEncodingIdentifierView,
            };
            pub use self::__buffa::view::{
                CryptoRsaPublicRepresentativesRequestOwnedView,
                CryptoRsaPublicRepresentativesRequestView,
            };
            pub use self::__buffa::view::{
                CryptoRsaPublicRepresentativesResultOwnedView,
                CryptoRsaPublicRepresentativesResultView,
            };
            pub use self::__buffa::view::{
                CryptoRsaVerifyRequestOwnedView, CryptoRsaVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSecp256k1AgreementRequestOwnedView, CryptoSecp256k1AgreementRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSecp256k1SignatureTranscodeRequestOwnedView,
                CryptoSecp256k1SignatureTranscodeRequestView,
            };
            pub use self::__buffa::view::{
                CryptoShake256ExpandRequestOwnedView, CryptoShake256ExpandRequestView,
            };
            pub use self::__buffa::view::{
                CryptoShake256ExpandResultOwnedView, CryptoShake256ExpandResultView,
            };
            pub use self::__buffa::view::{
                CryptoSignatureDeriveKeyPairRequestOwnedView,
                CryptoSignatureDeriveKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSignatureGenerateKeyPairRequestOwnedView,
                CryptoSignatureGenerateKeyPairRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSignatureSignRequestOwnedView, CryptoSignatureSignRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSignatureSignResultOwnedView, CryptoSignatureSignResultView,
            };
            pub use self::__buffa::view::{
                CryptoSignatureVerifyRequestOwnedView, CryptoSignatureVerifyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSubjectKeyIdentifierRequestOwnedView, CryptoSubjectKeyIdentifierRequestView,
            };
            pub use self::__buffa::view::{
                CryptoSubjectKeyIdentifierResultOwnedView, CryptoSubjectKeyIdentifierResultView,
            };
            pub use self::__buffa::view::{
                CryptoVerificationMethodMultikeyRequestOwnedView,
                CryptoVerificationMethodMultikeyRequestView,
            };
            pub use self::__buffa::view::{
                CryptoVerificationMethodMultikeyResultOwnedView,
                CryptoVerificationMethodMultikeyResultView,
            };
            pub use self::__buffa::view::{
                CryptoVerificationResultOwnedView, CryptoVerificationResultView,
            };
            pub use self::__buffa::view::{
                CryptoX448AgreementRequestOwnedView, CryptoX448AgreementRequestView,
            };
            pub use self::__buffa::view::{
                CryptoX448KeyDescriptorOwnedView, CryptoX448KeyDescriptorView,
            };
            pub use self::__buffa::view::{
                CryptoX448PrivateKeyInputOwnedView, CryptoX448PrivateKeyInputView,
            };
            pub use self::__buffa::view::{CryptoX448PublicKeyOwnedView, CryptoX448PublicKeyView};
            pub use self::__buffa::view::{HpkeSuiteIdentifierOwnedView, HpkeSuiteIdentifierView};
            pub use self::__buffa::view::{JsonWebKeyOwnedView, JsonWebKeyView};
            pub use self::__buffa::view::{JsonWebKeySetOwnedView, JsonWebKeySetView};
            pub use self::__buffa::view::{MaterialPolicyOwnedView, MaterialPolicyView};
            pub use self::__buffa::view::{
                OperationSecretMaterialPolicyOwnedView, OperationSecretMaterialPolicyView,
            };
            pub use self::__buffa::view::{PlatformKeyPolicyOwnedView, PlatformKeyPolicyView};
            pub use self::__buffa::view::{ProviderDecisionOwnedView, ProviderDecisionView};
            pub use self::__buffa::view::{
                ProviderDecisionRequestOwnedView, ProviderDecisionRequestView,
            };
            pub use self::__buffa::view::{
                ProviderDecisionResultOwnedView, ProviderDecisionResultView,
            };
            pub use self::__buffa::view::{PublicAkpJwkOwnedView, PublicAkpJwkView};
            pub use self::__buffa::view::{PublicEcJwkOwnedView, PublicEcJwkView};
            pub use self::__buffa::view::{PublicJwkDocumentOwnedView, PublicJwkDocumentView};
            pub use self::__buffa::view::{PublicJwkOwnedView, PublicJwkView};
            pub use self::__buffa::view::{PublicJwksOwnedView, PublicJwksView};
            pub use self::__buffa::view::{PublicOkpJwkOwnedView, PublicOkpJwkView};
        }
    }
}
