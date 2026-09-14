// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.crypto.proto

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import me.really.crypto.ReallyMeAeadAlgorithm
import me.really.crypto.ReallyMeCryptoException
import me.really.crypto.ReallyMeHashAlgorithm
import me.really.crypto.ReallyMeHpkeSuite
import me.really.crypto.ReallyMeHpkeSealedMessage
import me.really.crypto.ReallyMeJwk
import me.really.crypto.ReallyMeJwkAlgorithm
import me.really.crypto.ReallyMeJwkKey
import me.really.crypto.ReallyMeKdfAlgorithm
import me.really.crypto.ReallyMeKemAlgorithm
import me.really.crypto.ReallyMeKemEncapsulation
import me.really.crypto.ReallyMeKemKeyPair
import me.really.crypto.ReallyMeKeyAgreementKeyPair
import me.really.crypto.ReallyMeKeyAgreementAlgorithm
import me.really.crypto.ReallyMeKeyWrapAlgorithm
import me.really.crypto.ReallyMeMacAlgorithm
import me.really.crypto.ReallyMeNativeStatus
import me.really.crypto.ReallyMeMulticodecKeyAlgorithm
import me.really.crypto.ReallyMeSignatureKeyPair
import me.really.crypto.ReallyMeSignatureAlgorithm
import me.really.crypto.v1.AeadAlgorithm
import me.really.crypto.v1.CryptoAlgorithmFamily
import me.really.crypto.v1.CryptoAlgorithmIdentifier
import me.really.crypto.v1.CryptoBackendError
import me.really.crypto.v1.CryptoError
import me.really.crypto.v1.CryptoErrorReason
import me.really.crypto.v1.CryptoHpkeSealedMessage
import me.really.crypto.v1.CryptoKemEncapsulation
import me.really.crypto.v1.CryptoKeyPair
import me.really.crypto.v1.CryptoProviderCapability
import me.really.crypto.v1.CryptoProviderCapabilitySet
import me.really.crypto.v1.CryptoPrimitiveError
import me.really.crypto.v1.CryptoProviderError
import me.really.crypto.v1.CryptoProviderSupportStatus
import me.really.crypto.v1.CryptoVerificationResult
import me.really.crypto.v1.CryptoVerificationStatus
import me.really.crypto.v1.HashAlgorithm
import me.really.crypto.v1.HpkeAeadId
import me.really.crypto.v1.HpkeKdfId
import me.really.crypto.v1.HpkeKemId
import me.really.crypto.v1.HpkeSuiteIdentifier
import me.really.crypto.v1.JsonWebKey
import me.really.crypto.v1.JsonWebKeySet
import me.really.crypto.v1.KdfAlgorithm
import me.really.crypto.v1.KemAlgorithm
import me.really.crypto.v1.KeyAgreementAlgorithm
import me.really.crypto.v1.KeyWrapAlgorithm
import me.really.crypto.v1.MacAlgorithm
import me.really.crypto.v1.MulticodecKeyAlgorithm
import me.really.crypto.v1.SignatureAlgorithm

internal fun jwkAlgorithmToProto(
    value: ReallyMeJwkAlgorithm,
): CryptoAlgorithmIdentifier =
    when (value) {
        ReallyMeJwkAlgorithm.ED25519 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519)
            .build()
        ReallyMeJwkAlgorithm.X25519 -> CryptoAlgorithmIdentifier.newBuilder()
            .setKeyAgreement(KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519)
            .build()
        ReallyMeJwkAlgorithm.P256 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256)
            .build()
        ReallyMeJwkAlgorithm.SECP256K1 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256)
            .build()
        ReallyMeJwkAlgorithm.ML_DSA_44 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44)
            .build()
        ReallyMeJwkAlgorithm.ML_DSA_65 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65)
            .build()
        ReallyMeJwkAlgorithm.ML_DSA_87 -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87)
            .build()
        ReallyMeJwkAlgorithm.ML_KEM_512 -> CryptoAlgorithmIdentifier.newBuilder()
            .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_512)
            .build()
        ReallyMeJwkAlgorithm.ML_KEM_768 -> CryptoAlgorithmIdentifier.newBuilder()
            .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_768)
            .build()
        ReallyMeJwkAlgorithm.ML_KEM_1024 -> CryptoAlgorithmIdentifier.newBuilder()
            .setKem(KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024)
            .build()
        ReallyMeJwkAlgorithm.SLH_DSA_SHA2_128S -> CryptoAlgorithmIdentifier.newBuilder()
            .setSignature(SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S)
            .build()
        ReallyMeJwkAlgorithm.X_WING_768 -> CryptoAlgorithmIdentifier.newBuilder()
            .setKem(KemAlgorithm.KEM_ALGORITHM_X_WING_768)
            .build()
    }

internal fun jwkAlgorithmFromProto(
    value: CryptoAlgorithmIdentifier,
): ReallyMeJwkAlgorithm =
    when (value.algorithmCase) {
        CryptoAlgorithmIdentifier.AlgorithmCase.SIGNATURE -> when (value.signature) {
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519 ->
                ReallyMeJwkAlgorithm.ED25519
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 ->
                ReallyMeJwkAlgorithm.P256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 ->
                ReallyMeJwkAlgorithm.SECP256K1
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44 ->
                ReallyMeJwkAlgorithm.ML_DSA_44
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65 ->
                ReallyMeJwkAlgorithm.ML_DSA_65
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87 ->
                ReallyMeJwkAlgorithm.ML_DSA_87
            SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S ->
                ReallyMeJwkAlgorithm.SLH_DSA_SHA2_128S
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
        CryptoAlgorithmIdentifier.AlgorithmCase.KEY_AGREEMENT -> {
            if (value.keyAgreement == KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519) {
                ReallyMeJwkAlgorithm.X25519
            } else {
                throw ReallyMeCryptoException.UnsupportedAlgorithm()
            }
        }
        CryptoAlgorithmIdentifier.AlgorithmCase.KEM -> when (value.kem) {
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_512 -> ReallyMeJwkAlgorithm.ML_KEM_512
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_768 -> ReallyMeJwkAlgorithm.ML_KEM_768
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024 -> ReallyMeJwkAlgorithm.ML_KEM_1024
            KemAlgorithm.KEM_ALGORITHM_X_WING_768 -> ReallyMeJwkAlgorithm.X_WING_768
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }
        CryptoAlgorithmIdentifier.AlgorithmCase.ALGORITHM_NOT_SET ->
            throw ReallyMeCryptoException.InvalidInput()
        else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
    }

internal fun keyPairToProto(
    algorithm: CryptoAlgorithmIdentifier,
    publicKey: ByteArray,
    secretKey: ByteArray,
): CryptoKeyPair =
    CryptoKeyPair.newBuilder()
        .setAlgorithm(algorithm)
        .setPublicKey(ByteString.copyFrom(publicKey))
        .setSecretKey(ByteString.copyFrom(secretKey))
        .build()

internal fun signatureAlgorithmIdentifierToProto(
    value: ReallyMeSignatureAlgorithm,
): CryptoAlgorithmIdentifier =
    CryptoAlgorithmIdentifier.newBuilder()
        .setSignature(ReallyMeCryptoProtoAdapters.toProto(value))
        .build()

internal fun keyAgreementAlgorithmIdentifierToProto(
    value: ReallyMeKeyAgreementAlgorithm,
): CryptoAlgorithmIdentifier =
    CryptoAlgorithmIdentifier.newBuilder()
        .setKeyAgreement(ReallyMeCryptoProtoAdapters.toProto(value))
        .build()

internal fun kemAlgorithmIdentifierToProto(
    value: ReallyMeKemAlgorithm,
): CryptoAlgorithmIdentifier =
    CryptoAlgorithmIdentifier.newBuilder()
        .setKem(ReallyMeCryptoProtoAdapters.toProto(value))
        .build()

internal fun hpkeSuiteIdentifierToProto(
    value: ReallyMeHpkeSuite,
): CryptoAlgorithmIdentifier =
    CryptoAlgorithmIdentifier.newBuilder()
        .setHpkeSuite(ReallyMeCryptoProtoAdapters.toProto(value))
        .build()

internal fun signatureAlgorithmFromIdentifier(
    value: CryptoAlgorithmIdentifier,
    isPresent: Boolean,
): ReallyMeSignatureAlgorithm {
    if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.SIGNATURE) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    return ReallyMeCryptoProtoAdapters.fromProto(value.signature)
}

internal fun keyAgreementAlgorithmFromIdentifier(
    value: CryptoAlgorithmIdentifier,
    isPresent: Boolean,
): ReallyMeKeyAgreementAlgorithm {
    if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.KEY_AGREEMENT) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    return ReallyMeCryptoProtoAdapters.fromProto(value.keyAgreement)
}

internal fun kemAlgorithmFromIdentifier(
    value: CryptoAlgorithmIdentifier,
    isPresent: Boolean,
): ReallyMeKemAlgorithm {
    if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.KEM) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    return ReallyMeCryptoProtoAdapters.fromProto(value.kem)
}

internal fun hpkeSuiteFromIdentifier(
    value: CryptoAlgorithmIdentifier,
    isPresent: Boolean,
): ReallyMeHpkeSuite {
    if (!isPresent || value.algorithmCase != CryptoAlgorithmIdentifier.AlgorithmCase.HPKE_SUITE) {
        throw ReallyMeCryptoException.InvalidInput()
    }
    return ReallyMeCryptoProtoAdapters.fromProto(value.hpkeSuite)
}
