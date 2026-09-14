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

public interface ReallyMeCryptoProtoAlgorithmAdapters {
    public fun fromProto(value: SignatureAlgorithm): ReallyMeSignatureAlgorithm =
        when (value) {
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519 -> ReallyMeSignatureAlgorithm.ED25519
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 ->
                ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 ->
                ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P521_SHA512 ->
                ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256 ->
                ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256 ->
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA1
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512 ->
                ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384
            SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512 ->
                ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44 -> ReallyMeSignatureAlgorithm.ML_DSA_44
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65 -> ReallyMeSignatureAlgorithm.ML_DSA_65
            SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87 -> ReallyMeSignatureAlgorithm.ML_DSA_87
            SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S ->
                ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeSignatureAlgorithm): SignatureAlgorithm =
        when (value) {
            ReallyMeSignatureAlgorithm.ED25519 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519
            ReallyMeSignatureAlgorithm.ECDSA_P256_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P256_SHA256
            ReallyMeSignatureAlgorithm.ECDSA_P384_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P384_SHA384
            ReallyMeSignatureAlgorithm.ECDSA_P521_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_P521_SHA512
            ReallyMeSignatureAlgorithm.ECDSA_SECP256K1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ECDSA_SECP256K1_SHA256
            ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA1 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA1
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA256
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA384
            ReallyMeSignatureAlgorithm.RSA_PKCS1V15_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PKCS1V15_SHA512
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA1_MGF1_SHA1
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA384_MGF1_SHA384
            ReallyMeSignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512 ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_RSA_PSS_SHA512_MGF1_SHA512
            ReallyMeSignatureAlgorithm.ML_DSA_44 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_44
            ReallyMeSignatureAlgorithm.ML_DSA_65 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_65
            ReallyMeSignatureAlgorithm.ML_DSA_87 -> SignatureAlgorithm.SIGNATURE_ALGORITHM_ML_DSA_87
            ReallyMeSignatureAlgorithm.SLH_DSA_SHA2_128S ->
                SignatureAlgorithm.SIGNATURE_ALGORITHM_SLH_DSA_SHA2_128S
        }

    public fun fromProto(value: HashAlgorithm): ReallyMeHashAlgorithm =
        when (value) {
            HashAlgorithm.HASH_ALGORITHM_SHA2_256 -> ReallyMeHashAlgorithm.SHA2_256
            HashAlgorithm.HASH_ALGORITHM_SHA2_384 -> ReallyMeHashAlgorithm.SHA2_384
            HashAlgorithm.HASH_ALGORITHM_SHA2_512 -> ReallyMeHashAlgorithm.SHA2_512
            HashAlgorithm.HASH_ALGORITHM_SHA3_224 -> ReallyMeHashAlgorithm.SHA3_224
            HashAlgorithm.HASH_ALGORITHM_SHA3_256 -> ReallyMeHashAlgorithm.SHA3_256
            HashAlgorithm.HASH_ALGORITHM_SHA3_384 -> ReallyMeHashAlgorithm.SHA3_384
            HashAlgorithm.HASH_ALGORITHM_SHA3_512 -> ReallyMeHashAlgorithm.SHA3_512
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeHashAlgorithm): HashAlgorithm =
        when (value) {
            ReallyMeHashAlgorithm.SHA2_256 -> HashAlgorithm.HASH_ALGORITHM_SHA2_256
            ReallyMeHashAlgorithm.SHA2_384 -> HashAlgorithm.HASH_ALGORITHM_SHA2_384
            ReallyMeHashAlgorithm.SHA2_512 -> HashAlgorithm.HASH_ALGORITHM_SHA2_512
            ReallyMeHashAlgorithm.SHA3_224 -> HashAlgorithm.HASH_ALGORITHM_SHA3_224
            ReallyMeHashAlgorithm.SHA3_256 -> HashAlgorithm.HASH_ALGORITHM_SHA3_256
            ReallyMeHashAlgorithm.SHA3_384 -> HashAlgorithm.HASH_ALGORITHM_SHA3_384
            ReallyMeHashAlgorithm.SHA3_512 -> HashAlgorithm.HASH_ALGORITHM_SHA3_512
        }

    public fun fromProto(value: AeadAlgorithm): ReallyMeAeadAlgorithm =
        when (value) {
            AeadAlgorithm.AEAD_ALGORITHM_AES_128_GCM -> ReallyMeAeadAlgorithm.AES_128_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_192_GCM -> ReallyMeAeadAlgorithm.AES_192_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM -> ReallyMeAeadAlgorithm.AES_256_GCM
            AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM_SIV -> ReallyMeAeadAlgorithm.AES_256_GCM_SIV
            AeadAlgorithm.AEAD_ALGORITHM_CHACHA20_POLY1305 ->
                ReallyMeAeadAlgorithm.CHACHA20_POLY1305
            AeadAlgorithm.AEAD_ALGORITHM_XCHACHA20_POLY1305 ->
                ReallyMeAeadAlgorithm.XCHACHA20_POLY1305
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeAeadAlgorithm): AeadAlgorithm =
        when (value) {
            ReallyMeAeadAlgorithm.AES_128_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_128_GCM
            ReallyMeAeadAlgorithm.AES_192_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_192_GCM
            ReallyMeAeadAlgorithm.AES_256_GCM -> AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM
            ReallyMeAeadAlgorithm.AES_256_GCM_SIV -> AeadAlgorithm.AEAD_ALGORITHM_AES_256_GCM_SIV
            ReallyMeAeadAlgorithm.CHACHA20_POLY1305 -> AeadAlgorithm.AEAD_ALGORITHM_CHACHA20_POLY1305
            ReallyMeAeadAlgorithm.XCHACHA20_POLY1305 ->
                AeadAlgorithm.AEAD_ALGORITHM_XCHACHA20_POLY1305
        }

    public fun fromProto(value: KemAlgorithm): ReallyMeKemAlgorithm =
        when (value) {
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_512 -> ReallyMeKemAlgorithm.ML_KEM_512
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_768 -> ReallyMeKemAlgorithm.ML_KEM_768
            KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024 -> ReallyMeKemAlgorithm.ML_KEM_1024
            KemAlgorithm.KEM_ALGORITHM_X_WING_768 -> ReallyMeKemAlgorithm.X_WING_768
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKemAlgorithm): KemAlgorithm =
        when (value) {
            ReallyMeKemAlgorithm.ML_KEM_512 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_512
            ReallyMeKemAlgorithm.ML_KEM_768 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_768
            ReallyMeKemAlgorithm.ML_KEM_1024 -> KemAlgorithm.KEM_ALGORITHM_ML_KEM_1024
            ReallyMeKemAlgorithm.X_WING_768 -> KemAlgorithm.KEM_ALGORITHM_X_WING_768
        }

    public fun fromProto(value: KeyAgreementAlgorithm): ReallyMeKeyAgreementAlgorithm =
        when (value) {
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519 -> ReallyMeKeyAgreementAlgorithm.X25519
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P256_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P256_ECDH
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P384_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P384_ECDH
            KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P521_ECDH ->
                ReallyMeKeyAgreementAlgorithm.P521_ECDH
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKeyAgreementAlgorithm): KeyAgreementAlgorithm =
        when (value) {
            ReallyMeKeyAgreementAlgorithm.X25519 -> KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_X25519
            ReallyMeKeyAgreementAlgorithm.P256_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P256_ECDH
            ReallyMeKeyAgreementAlgorithm.P384_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P384_ECDH
            ReallyMeKeyAgreementAlgorithm.P521_ECDH ->
                KeyAgreementAlgorithm.KEY_AGREEMENT_ALGORITHM_P521_ECDH
        }

    public fun fromProto(value: MacAlgorithm): ReallyMeMacAlgorithm =
        when (value) {
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA256 -> ReallyMeMacAlgorithm.HMAC_SHA256
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA384 -> ReallyMeMacAlgorithm.HMAC_SHA384
            MacAlgorithm.MAC_ALGORITHM_HMAC_SHA512 -> ReallyMeMacAlgorithm.HMAC_SHA512
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeMacAlgorithm): MacAlgorithm =
        when (value) {
            ReallyMeMacAlgorithm.HMAC_SHA256 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA256
            ReallyMeMacAlgorithm.HMAC_SHA384 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA384
            ReallyMeMacAlgorithm.HMAC_SHA512 -> MacAlgorithm.MAC_ALGORITHM_HMAC_SHA512
        }

    public fun fromProto(value: KdfAlgorithm): ReallyMeKdfAlgorithm =
        when (value) {
            KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA256 -> ReallyMeKdfAlgorithm.HKDF_SHA256
            KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA384 -> ReallyMeKdfAlgorithm.HKDF_SHA384
            KdfAlgorithm.KDF_ALGORITHM_ARGON2ID -> ReallyMeKdfAlgorithm.ARGON2ID
            KdfAlgorithm.KDF_ALGORITHM_KMAC_256 -> ReallyMeKdfAlgorithm.KMAC256
            KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA256 -> ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256
            KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA512 -> ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512
            KdfAlgorithm.KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256 ->
                ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKdfAlgorithm): KdfAlgorithm =
        when (value) {
            ReallyMeKdfAlgorithm.HKDF_SHA256 -> KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA256
            ReallyMeKdfAlgorithm.HKDF_SHA384 -> KdfAlgorithm.KDF_ALGORITHM_HKDF_SHA384
            ReallyMeKdfAlgorithm.ARGON2ID -> KdfAlgorithm.KDF_ALGORITHM_ARGON2ID
            ReallyMeKdfAlgorithm.KMAC256 -> KdfAlgorithm.KDF_ALGORITHM_KMAC_256
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA256 -> KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA256
            ReallyMeKdfAlgorithm.PBKDF2_HMAC_SHA512 -> KdfAlgorithm.KDF_ALGORITHM_PBKDF2_HMAC_SHA512
            ReallyMeKdfAlgorithm.JWA_CONCAT_KDF_SHA256 ->
                KdfAlgorithm.KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256
        }

    public fun fromProto(value: KeyWrapAlgorithm): ReallyMeKeyWrapAlgorithm =
        when (value) {
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_128_KW -> ReallyMeKeyWrapAlgorithm.AES_128_KW
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_192_KW -> ReallyMeKeyWrapAlgorithm.AES_192_KW
            KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_256_KW -> ReallyMeKeyWrapAlgorithm.AES_256_KW
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeKeyWrapAlgorithm): KeyWrapAlgorithm =
        when (value) {
            ReallyMeKeyWrapAlgorithm.AES_128_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_128_KW
            ReallyMeKeyWrapAlgorithm.AES_192_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_192_KW
            ReallyMeKeyWrapAlgorithm.AES_256_KW -> KeyWrapAlgorithm.KEY_WRAP_ALGORITHM_AES_256_KW
        }

    public fun fromProto(value: HpkeSuiteIdentifier): ReallyMeHpkeSuite =
        when {
            value.kem == HpkeKemId.HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256 &&
                value.kdf == HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256 &&
                value.aead == HpkeAeadId.HPKE_AEAD_ID_AES_256_GCM ->
                ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM
            value.kem == HpkeKemId.HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256 &&
                value.kdf == HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256 &&
                value.aead == HpkeAeadId.HPKE_AEAD_ID_CHACHA20_POLY1305 ->
                ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeHpkeSuite): HpkeSuiteIdentifier {
        val builder = HpkeSuiteIdentifier.newBuilder()
            .setKdf(HpkeKdfId.HPKE_KDF_ID_HKDF_SHA256)
        return when (value) {
            ReallyMeHpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM ->
                builder
                    .setKem(HpkeKemId.HPKE_KEM_ID_DHKEM_P256_HKDF_SHA256)
                    .setAead(HpkeAeadId.HPKE_AEAD_ID_AES_256_GCM)
                    .build()
            ReallyMeHpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305 ->
                builder
                    .setKem(HpkeKemId.HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256)
                    .setAead(HpkeAeadId.HPKE_AEAD_ID_CHACHA20_POLY1305)
                    .build()
        }
    }

    public fun fromProto(value: MulticodecKeyAlgorithm): ReallyMeMulticodecKeyAlgorithm =
        when (value) {
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ED25519_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_X25519_PUB ->
                ReallyMeMulticodecKeyAlgorithm.X25519_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB ->
                ReallyMeMulticodecKeyAlgorithm.SECP256K1_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P256_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P256_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P384_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P384_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P521_PUB ->
                ReallyMeMulticodecKeyAlgorithm.P521_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED448_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ED448_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_RSA_PUB ->
                ReallyMeMulticodecKeyAlgorithm.RSA_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_512_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_KEM_1024_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_44_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_65_PUBLIC_KEY
            MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB ->
                ReallyMeMulticodecKeyAlgorithm.ML_DSA_87_PUBLIC_KEY
            else -> throw ReallyMeCryptoException.UnsupportedAlgorithm()
        }

    public fun toProto(value: ReallyMeMulticodecKeyAlgorithm): MulticodecKeyAlgorithm =
        when (value) {
            ReallyMeMulticodecKeyAlgorithm.ED25519_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PUB
            ReallyMeMulticodecKeyAlgorithm.X25519_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_X25519_PUB
            ReallyMeMulticodecKeyAlgorithm.SECP256K1_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_SECP256K1_PUB
            ReallyMeMulticodecKeyAlgorithm.P256_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P256_PUB
            ReallyMeMulticodecKeyAlgorithm.P384_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P384_PUB
            ReallyMeMulticodecKeyAlgorithm.P521_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_P521_PUB
            ReallyMeMulticodecKeyAlgorithm.ED448_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED448_PUB
            ReallyMeMulticodecKeyAlgorithm.RSA_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_RSA_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_512_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_512_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_1024_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_1024_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_44_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_44_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_65_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_65_PUB
            ReallyMeMulticodecKeyAlgorithm.ML_DSA_87_PUBLIC_KEY ->
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_DSA_87_PUB
        }

}
