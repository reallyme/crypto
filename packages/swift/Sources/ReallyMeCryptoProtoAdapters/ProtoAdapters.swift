// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import ReallyMeCrypto
import ReallyMeCryptoProto

public enum ReallyMeCryptoProtoAdapters {
    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm
    ) throws -> ReallyMeSignatureAlgorithm {
        switch value {
        case .ed25519:
            .ed25519
        case .ecdsaP256Sha256:
            .ecdsaP256Sha256
        case .ecdsaP384Sha384:
            .ecdsaP384Sha384
        case .ecdsaP521Sha512:
            .ecdsaP521Sha512
        case .ecdsaSecp256K1Sha256:
            .ecdsaSecp256k1Sha256
        case .bip340SchnorrSecp256K1Sha256:
            .bip340SchnorrSecp256k1Sha256
        case .rsaPkcs1V15Sha1:
            .rsaPkcs1v15Sha1
        case .rsaPkcs1V15Sha256:
            .rsaPkcs1v15Sha256
        case .rsaPkcs1V15Sha384:
            .rsaPkcs1v15Sha384
        case .rsaPkcs1V15Sha512:
            .rsaPkcs1v15Sha512
        case .rsaPssSha1Mgf1Sha1:
            .rsaPssSha1Mgf1Sha1
        case .rsaPssSha256Mgf1Sha256:
            .rsaPssSha256Mgf1Sha256
        case .rsaPssSha384Mgf1Sha384:
            .rsaPssSha384Mgf1Sha384
        case .rsaPssSha512Mgf1Sha512:
            .rsaPssSha512Mgf1Sha512
        case .mlDsa44:
            .mlDsa44
        case .mlDsa65:
            .mlDsa65
        case .mlDsa87:
            .mlDsa87
        case .slhDsaSha2128S:
            .slhDsaSha2_128s
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeSignatureAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm {
        switch value {
        case .ed25519:
            .ed25519
        case .ecdsaP256Sha256:
            .ecdsaP256Sha256
        case .ecdsaP384Sha384:
            .ecdsaP384Sha384
        case .ecdsaP521Sha512:
            .ecdsaP521Sha512
        case .ecdsaSecp256k1Sha256:
            .ecdsaSecp256K1Sha256
        case .bip340SchnorrSecp256k1Sha256:
            .bip340SchnorrSecp256K1Sha256
        case .rsaPkcs1v15Sha1:
            .rsaPkcs1V15Sha1
        case .rsaPkcs1v15Sha256:
            .rsaPkcs1V15Sha256
        case .rsaPkcs1v15Sha384:
            .rsaPkcs1V15Sha384
        case .rsaPkcs1v15Sha512:
            .rsaPkcs1V15Sha512
        case .rsaPssSha1Mgf1Sha1:
            .rsaPssSha1Mgf1Sha1
        case .rsaPssSha256Mgf1Sha256:
            .rsaPssSha256Mgf1Sha256
        case .rsaPssSha384Mgf1Sha384:
            .rsaPssSha384Mgf1Sha384
        case .rsaPssSha512Mgf1Sha512:
            .rsaPssSha512Mgf1Sha512
        case .mlDsa44:
            .mlDsa44
        case .mlDsa65:
            .mlDsa65
        case .mlDsa87:
            .mlDsa87
        case .slhDsaSha2_128s:
            .slhDsaSha2128S
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm
    ) throws -> ReallyMeHashAlgorithm {
        switch value {
        case .sha2256:
            .sha2_256
        case .sha2384:
            .sha2_384
        case .sha2512:
            .sha2_512
        case .sha3224:
            .sha3_224
        case .sha3256:
            .sha3_256
        case .sha3384:
            .sha3_384
        case .sha3512:
            .sha3_512
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeHashAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm {
        switch value {
        case .sha2_256:
            .sha2256
        case .sha2_384:
            .sha2384
        case .sha2_512:
            .sha2512
        case .sha3_224:
            .sha3224
        case .sha3_256:
            .sha3256
        case .sha3_384:
            .sha3384
        case .sha3_512:
            .sha3512
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm
    ) throws -> ReallyMeAeadAlgorithm {
        switch value {
        case .aes256Gcm:
            .aes256Gcm
        case .aes256GcmSiv:
            .aes256GcmSiv
        case .chacha20Poly1305:
            .chacha20Poly1305
        case .xchacha20Poly1305:
            .xchacha20Poly1305
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeAeadAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm {
        switch value {
        case .aes256Gcm:
            .aes256Gcm
        case .aes256GcmSiv:
            .aes256GcmSiv
        case .chacha20Poly1305:
            .chacha20Poly1305
        case .xchacha20Poly1305:
            .xchacha20Poly1305
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm
    ) throws -> ReallyMeKemAlgorithm {
        switch value {
        case .mlKem512:
            .mlKem512
        case .mlKem768:
            .mlKem768
        case .mlKem1024:
            .mlKem1024
        case .xWing768:
            .xWing768
        case .xWing1024:
            .xWing1024
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKemAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm {
        switch value {
        case .mlKem512:
            .mlKem512
        case .mlKem768:
            .mlKem768
        case .mlKem1024:
            .mlKem1024
        case .xWing768:
            .xWing768
        case .xWing1024:
            .xWing1024
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm
    ) throws -> ReallyMeKeyAgreementAlgorithm {
        switch value {
        case .x25519:
            .x25519
        case .p256Ecdh:
            .p256Ecdh
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKeyAgreementAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm {
        switch value {
        case .x25519:
            .x25519
        case .p256Ecdh:
            .p256Ecdh
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm
    ) throws -> ReallyMeMacAlgorithm {
        switch value {
        case .hmacSha256:
            .hmacSha256
        case .hmacSha512:
            .hmacSha512
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeMacAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm {
        switch value {
        case .hmacSha256:
            .hmacSha256
        case .hmacSha512:
            .hmacSha512
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm
    ) throws -> ReallyMeKdfAlgorithm {
        switch value {
        case .hkdfSha256:
            .hkdfSha256
        case .argon2ID:
            .argon2id
        case .pbkdf2HmacSha256:
            .pbkdf2HmacSha256
        case .pbkdf2HmacSha512:
            .pbkdf2HmacSha512
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKdfAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm {
        switch value {
        case .hkdfSha256:
            .hkdfSha256
        case .argon2id:
            .argon2ID
        case .pbkdf2HmacSha256:
            .pbkdf2HmacSha256
        case .pbkdf2HmacSha512:
            .pbkdf2HmacSha512
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm
    ) throws -> ReallyMeKeyWrapAlgorithm {
        switch value {
        case .aes256Kw:
            .aes256Kw
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKeyWrapAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm {
        switch value {
        case .aes256Kw:
            .aes256Kw
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoHpkeSuite
    ) throws -> ReallyMeHpkeSuite {
        switch value {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
            .dhkemP256HkdfSha256HkdfSha256Aes256Gcm
        case .dhkemX25519HkdfSha256HkdfSha256Chacha20Poly1305:
            .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeHpkeSuite
    ) -> ReallyMeCryptoProto.ReallyMeProtoHpkeSuite {
        switch value {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
            .dhkemP256HkdfSha256HkdfSha256Aes256Gcm
        case .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
            .dhkemX25519HkdfSha256HkdfSha256Chacha20Poly1305
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm
    ) throws -> ReallyMeMulticodecKeyAlgorithm {
        switch value {
        case .ed25519Pub:
            .ed25519PublicKey
        case .x25519Pub:
            .x25519PublicKey
        case .secp256K1Pub:
            .secp256k1PublicKey
        case .p256Pub:
            .p256PublicKey
        case .p384Pub:
            .p384PublicKey
        case .p521Pub:
            .p521PublicKey
        case .ed448Pub:
            .ed448PublicKey
        case .rsaPub:
            .rsaPublicKey
        case .mlKem512Pub:
            .mlKem512PublicKey
        case .mlKem768Pub:
            .mlKem768PublicKey
        case .mlKem1024Pub:
            .mlKem1024PublicKey
        case .mlDsa44Pub:
            .mlDsa44PublicKey
        case .mlDsa65Pub:
            .mlDsa65PublicKey
        case .mlDsa87Pub:
            .mlDsa87PublicKey
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeMulticodecKeyAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm {
        switch value {
        case .ed25519PublicKey:
            .ed25519Pub
        case .x25519PublicKey:
            .x25519Pub
        case .secp256k1PublicKey:
            .secp256K1Pub
        case .p256PublicKey:
            .p256Pub
        case .p384PublicKey:
            .p384Pub
        case .p521PublicKey:
            .p521Pub
        case .ed448PublicKey:
            .ed448Pub
        case .rsaPublicKey:
            .rsaPub
        case .mlKem512PublicKey:
            .mlKem512Pub
        case .mlKem768PublicKey:
            .mlKem768Pub
        case .mlKem1024PublicKey:
            .mlKem1024Pub
        case .mlDsa44PublicKey:
            .mlDsa44Pub
        case .mlDsa65PublicKey:
            .mlDsa65Pub
        case .mlDsa87PublicKey:
            .mlDsa87Pub
        }
    }
}
