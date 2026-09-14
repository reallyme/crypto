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

public object ReallyMeCryptoProtoAdapters :
    ReallyMeCryptoProtoErrorAdapters,
    ReallyMeCryptoProtoAlgorithmAdapters {
    public fun fromProto(value: JsonWebKey): ReallyMeJwkKey {
        if (!value.hasAlgorithm()) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        val algorithm = jwkAlgorithmFromProto(value.algorithm)
        val publicKey = value.publicKey.toByteArray()
        val jwk = ReallyMeJwk.toJwk(algorithm, publicKey)
        if (!value.canonicalJcs.isEmpty) {
            val canonicalJcs = value.canonicalJcs.toStringUtf8()
            if (canonicalJcs != ReallyMeJwk.toJcs(jwk)) {
                throw ReallyMeCryptoException.InvalidInput()
            }
        }
        return ReallyMeJwkKey(algorithm, publicKey, jwk)
    }

    public fun fromProtoJsonWebKeyBytes(bytes: ByteArray): ReallyMeJwkKey =
        try {
            fromProto(JsonWebKey.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    public fun toProto(value: ReallyMeJwkKey): JsonWebKey =
        JsonWebKey.newBuilder()
            .setAlgorithm(jwkAlgorithmToProto(value.algorithm))
            .setPublicKey(ByteString.copyFrom(value.publicKey))
            .setCanonicalJcs(ByteString.copyFromUtf8(ReallyMeJwk.toJcs(value.jwk)))
            .build()

    public fun toProtoBytes(value: ReallyMeJwkKey): ByteArray =
        toProto(value).toByteArray()

    public fun fromProto(value: JsonWebKeySet): List<ReallyMeJwkKey> =
        value.keysList.map { fromProto(it) }

    public fun fromProtoJsonWebKeySetBytes(bytes: ByteArray): List<ReallyMeJwkKey> =
        try {
            fromProto(JsonWebKeySet.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    public fun toProtoJsonWebKeySet(values: List<ReallyMeJwkKey>): JsonWebKeySet =
        JsonWebKeySet.newBuilder()
            .addAllKeys(values.map { toProto(it) })
            .build()

    public fun toProtoJsonWebKeySetBytes(values: List<ReallyMeJwkKey>): ByteArray =
        toProtoJsonWebKeySet(values).toByteArray()

    @JvmStatic
    public fun signatureKeyPairToProto(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair,
    ): CryptoKeyPair = keyPairToProto(signatureAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun signatureKeyPairToProtoBytes(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair,
    ): ByteArray = signatureKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun signatureKeyPairFromProto(value: CryptoKeyPair): ReallyMeSignatureKeyPairProtoValue =
        ReallyMeSignatureKeyPairProtoValue(
            signatureAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeSignatureKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun signatureKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeSignatureKeyPairProtoValue =
        try {
            signatureKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun keyAgreementKeyPairToProto(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        keyPair: ReallyMeKeyAgreementKeyPair,
    ): CryptoKeyPair = keyPairToProto(keyAgreementAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun keyAgreementKeyPairToProtoBytes(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        keyPair: ReallyMeKeyAgreementKeyPair,
    ): ByteArray = keyAgreementKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun keyAgreementKeyPairFromProto(value: CryptoKeyPair): ReallyMeKeyAgreementKeyPairProtoValue =
        ReallyMeKeyAgreementKeyPairProtoValue(
            keyAgreementAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKeyAgreementKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun keyAgreementKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeKeyAgreementKeyPairProtoValue =
        try {
            keyAgreementKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun kemKeyPairToProto(
        algorithm: ReallyMeKemAlgorithm,
        keyPair: ReallyMeKemKeyPair,
    ): CryptoKeyPair = keyPairToProto(kemAlgorithmIdentifierToProto(algorithm), keyPair.publicKey, keyPair.secretKey)

    @JvmStatic
    public fun kemKeyPairToProtoBytes(
        algorithm: ReallyMeKemAlgorithm,
        keyPair: ReallyMeKemKeyPair,
    ): ByteArray = kemKeyPairToProto(algorithm, keyPair).toByteArray()

    @JvmStatic
    public fun kemKeyPairFromProto(value: CryptoKeyPair): ReallyMeKemKeyPairProtoValue =
        ReallyMeKemKeyPairProtoValue(
            kemAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKemKeyPair(value.publicKey.toByteArray(), value.secretKey.toByteArray()),
        )

    @JvmStatic
    public fun kemKeyPairFromProtoBytes(bytes: ByteArray): ReallyMeKemKeyPairProtoValue =
        try {
            kemKeyPairFromProto(CryptoKeyPair.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun kemEncapsulationToProto(
        algorithm: ReallyMeKemAlgorithm,
        encapsulation: ReallyMeKemEncapsulation,
    ): CryptoKemEncapsulation =
        CryptoKemEncapsulation.newBuilder()
            .setAlgorithm(kemAlgorithmIdentifierToProto(algorithm))
            .setCiphertext(ByteString.copyFrom(encapsulation.ciphertext))
            .setSharedSecret(ByteString.copyFrom(encapsulation.sharedSecret))
            .build()

    @JvmStatic
    public fun kemEncapsulationToProtoBytes(
        algorithm: ReallyMeKemAlgorithm,
        encapsulation: ReallyMeKemEncapsulation,
    ): ByteArray = kemEncapsulationToProto(algorithm, encapsulation).toByteArray()

    @JvmStatic
    public fun kemEncapsulationFromProto(value: CryptoKemEncapsulation): ReallyMeKemEncapsulationProtoValue =
        ReallyMeKemEncapsulationProtoValue(
            kemAlgorithmFromIdentifier(value.algorithm, value.hasAlgorithm()),
            ReallyMeKemEncapsulation(value.sharedSecret.toByteArray(), value.ciphertext.toByteArray()),
        )

    @JvmStatic
    public fun kemEncapsulationFromProtoBytes(bytes: ByteArray): ReallyMeKemEncapsulationProtoValue =
        try {
            kemEncapsulationFromProto(CryptoKemEncapsulation.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun hpkeSealedMessageToProto(
        suite: ReallyMeHpkeSuite,
        sealedMessage: ReallyMeHpkeSealedMessage,
    ): CryptoHpkeSealedMessage =
        CryptoHpkeSealedMessage.newBuilder()
            .setAlgorithm(hpkeSuiteIdentifierToProto(suite))
            .setEncapsulatedKey(ByteString.copyFrom(sealedMessage.encapsulatedKey))
            .setCiphertext(ByteString.copyFrom(sealedMessage.ciphertext))
            .build()

    @JvmStatic
    public fun hpkeSealedMessageToProtoBytes(
        suite: ReallyMeHpkeSuite,
        sealedMessage: ReallyMeHpkeSealedMessage,
    ): ByteArray = hpkeSealedMessageToProto(suite, sealedMessage).toByteArray()

    @JvmStatic
    public fun hpkeSealedMessageFromProto(value: CryptoHpkeSealedMessage): ReallyMeHpkeSealedMessageProtoValue =
        ReallyMeHpkeSealedMessageProtoValue(
            ReallyMeHpkeSealedMessage(value.encapsulatedKey.toByteArray(), value.ciphertext.toByteArray()),
            hpkeSuiteFromIdentifier(value.algorithm, value.hasAlgorithm()),
        )

    @JvmStatic
    public fun hpkeSealedMessageFromProtoBytes(bytes: ByteArray): ReallyMeHpkeSealedMessageProtoValue =
        try {
            hpkeSealedMessageFromProto(CryptoHpkeSealedMessage.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun verificationResultToProto(
        algorithm: CryptoAlgorithmIdentifier,
        valid: Boolean,
    ): CryptoVerificationResult =
        CryptoVerificationResult.newBuilder()
            .setAlgorithm(algorithm)
            .setStatus(
                if (valid) {
                    CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_VALID
                } else {
                    CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_INVALID
                },
            )
            .build()

    @JvmStatic
    public fun verificationErrorToProto(
        algorithm: CryptoAlgorithmIdentifier,
        error: ReallyMeCryptoException,
    ): CryptoVerificationResult =
        CryptoVerificationResult.newBuilder()
            .setAlgorithm(algorithm)
            .setStatus(CryptoVerificationStatus.CRYPTO_VERIFICATION_STATUS_ERROR)
            .setError(toProto(error))
            .build()

    @JvmStatic
    public fun verificationResultToProtoBytes(value: CryptoVerificationResult): ByteArray =
        value.toByteArray()

    @JvmStatic
    public fun verificationResultFromProtoBytes(bytes: ByteArray): CryptoVerificationResult =
        try {
            CryptoVerificationResult.parseFrom(bytes)
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

    @JvmStatic
    public fun providerCapabilityToProto(
        value: ReallyMeProviderCapabilityProtoValue,
    ): CryptoProviderCapability {
        if (
            value.algorithm.algorithmCase == CryptoAlgorithmIdentifier.AlgorithmCase.ALGORITHM_NOT_SET ||
            value.family == CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.UNRECOGNIZED
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return CryptoProviderCapability.newBuilder()
            .setAlgorithm(value.algorithm)
            .setFamily(value.family)
            .addAllProviderNames(value.providerNames)
            .setStatus(value.status)
            .setUsesRust(value.usesRust)
            .build()
    }

    @JvmStatic
    public fun providerCapabilityFromProto(value: CryptoProviderCapability): ReallyMeProviderCapabilityProtoValue {
        if (
            !value.hasAlgorithm() ||
            value.family == CryptoAlgorithmFamily.CRYPTO_ALGORITHM_FAMILY_UNSPECIFIED ||
            value.family == CryptoAlgorithmFamily.UNRECOGNIZED ||
            value.status == CryptoProviderSupportStatus.CRYPTO_PROVIDER_SUPPORT_STATUS_UNSPECIFIED ||
            value.status == CryptoProviderSupportStatus.UNRECOGNIZED
        ) {
            throw ReallyMeCryptoException.InvalidInput()
        }
        return ReallyMeProviderCapabilityProtoValue(
            value.algorithm,
            value.family,
            value.providerNamesList,
            value.status,
            value.usesRust,
        )
    }

    @JvmStatic
    public fun providerCapabilitySetToProto(
        values: List<ReallyMeProviderCapabilityProtoValue>,
    ): CryptoProviderCapabilitySet =
        CryptoProviderCapabilitySet.newBuilder()
            .addAllCapabilities(values.map { providerCapabilityToProto(it) })
            .build()

    @JvmStatic
    public fun providerCapabilitySetToProtoBytes(
        values: List<ReallyMeProviderCapabilityProtoValue>,
    ): ByteArray = providerCapabilitySetToProto(values).toByteArray()

    @JvmStatic
    public fun providerCapabilitySetFromProto(
        value: CryptoProviderCapabilitySet,
    ): List<ReallyMeProviderCapabilityProtoValue> =
        value.capabilitiesList.map { providerCapabilityFromProto(it) }

    @JvmStatic
    public fun providerCapabilitySetFromProtoBytes(bytes: ByteArray): List<ReallyMeProviderCapabilityProtoValue> =
        try {
            providerCapabilitySetFromProto(CryptoProviderCapabilitySet.parseFrom(bytes))
        } catch (error: ReallyMeCryptoException) {
            throw error
        } catch (_: InvalidProtocolBufferException) {
            throw ReallyMeCryptoException.InvalidInput()
        }

}
