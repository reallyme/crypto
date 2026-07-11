// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Public/secret keypair returned by generic package facade key generation.
public struct ReallyMeSignatureKeyPair: Equatable, Sendable {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }
}

public struct ReallyMeKemKeyPair: Equatable, Sendable {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }
}

public struct ReallyMeKeyAgreementKeyPair: Equatable, Sendable {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }
}

public struct ReallyMeKemEncapsulation: Equatable, Sendable {
    public let sharedSecret: [UInt8]
    public let ciphertext: [UInt8]

    public init(sharedSecret: [UInt8], ciphertext: [UInt8]) {
        self.sharedSecret = sharedSecret
        self.ciphertext = ciphertext
    }
}

public struct ReallyMeHpkeSealedMessage: Equatable, Sendable {
    public let encapsulatedKey: [UInt8]
    public let ciphertext: [UInt8]

    public init(encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
        self.encapsulatedKey = encapsulatedKey
        self.ciphertext = ciphertext
    }
}

/// Generic package facade. Algorithm-specific types remain available for
/// callers that want direct provider access; this facade gives consumers a
/// stable typed route that fails closed for not-yet-exposed algorithms.
public enum ReallyMeCrypto {
    public static func hash(_ algorithm: ReallyMeHashAlgorithm, _ bytes: [UInt8]) throws -> [UInt8] {
        switch algorithm {
        case .sha2_256:
            return ReallyMeDigest.sha256(bytes)
        case .sha2_384:
            return ReallyMeDigest.sha384(bytes)
        case .sha2_512:
            return ReallyMeDigest.sha512(bytes)
        case .sha3_224:
            return ReallyMeDigest.sha3_224(bytes)
        case .sha3_256:
            return ReallyMeDigest.sha3_256(bytes)
        case .sha3_384:
            return ReallyMeDigest.sha3_384(bytes)
        case .sha3_512:
            return ReallyMeDigest.sha3_512(bytes)
        }
    }

    public static func seal(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Gcm:
            return try ReallyMeAesGcm.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .chacha20Poly1305:
            return try ReallyMeChaCha20Poly1305.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes256GcmSiv, .xchacha20Poly1305:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func open(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Gcm:
            return try ReallyMeAesGcm.open(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .chacha20Poly1305:
            return try ReallyMeChaCha20Poly1305.open(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes256GcmSiv, .xchacha20Poly1305:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func authenticate(
        _ algorithm: ReallyMeMacAlgorithm,
        key: [UInt8],
        message: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .hmacSha256:
            return try ReallyMeHmac.authenticateSha256(key: key, message: message)
        case .hmacSha512:
            return try ReallyMeHmac.authenticateSha512(key: key, message: message)
        }
    }

    public static func verifyMac(
        _ algorithm: ReallyMeMacAlgorithm,
        tag: [UInt8],
        key: [UInt8],
        message: [UInt8]
    ) throws -> Bool {
        switch algorithm {
        case .hmacSha256:
            return try ReallyMeHmac.verifySha256(tag: tag, key: key, message: message)
        case .hmacSha512:
            return try ReallyMeHmac.verifySha512(tag: tag, key: key, message: message)
        }
    }

    public static func deriveKey(
        _ algorithm: ReallyMeKdfAlgorithm,
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws -> [UInt8] {
        switch algorithm {
        case .pbkdf2HmacSha256:
            return try ReallyMePbkdf2.deriveHmacSha256(
                password: password,
                salt: salt,
                iterations: iterations,
                outputLength: outputLength
            )
        case .pbkdf2HmacSha512:
            return try ReallyMePbkdf2.deriveHmacSha512(
                password: password,
                salt: salt,
                iterations: iterations,
                outputLength: outputLength
            )
        case .hkdfSha256, .argon2id:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func deriveHkdf(
        _ algorithm: ReallyMeKdfAlgorithm,
        inputKeyMaterial: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        switch algorithm {
        case .hkdfSha256:
            return try ReallyMeHkdf.deriveSha256(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                info: info,
                outputLength: outputLength
            )
        case .argon2id, .pbkdf2HmacSha256, .pbkdf2HmacSha512:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func wrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        keyToWrap: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Kw:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func unwrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        wrappedKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Kw:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func generateKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm
    ) throws -> ReallyMeSignatureKeyPair {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            let keyPair = try ReallyMeSecp256k1.generateKeyPair()
            return ReallyMeSignatureKeyPair(
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            return try ReallyMeSecp256k1.sign(message: message, secretKey: secretKey)
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            try ReallyMeSecp256k1.verify(
                signature: signature,
                message: message,
                publicKey: publicKey
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func deriveSharedSecret(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        publicKey: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .x25519:
            return try ReallyMeX25519.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
        case .p256Ecdh:
            return try ReallyMeP256Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
        }
    }

    public static func deriveKeyAgreementKeyPair(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeKeyAgreementKeyPair {
        switch algorithm {
        case .x25519:
            let keyPair = try ReallyMeX25519.deriveKeyPair(secretKey: secretKey)
            return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        case .p256Ecdh:
            let keyPair = try ReallyMeP256Ecdh.deriveKeyPair(secretKey: secretKey)
            return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        }
    }

    public static func generateKemKeyPair(_ algorithm: ReallyMeKemAlgorithm) throws -> ReallyMeKemKeyPair {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024, .xWing768, .xWing1024:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func encapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        publicKey: [UInt8]
    ) throws -> ReallyMeKemEncapsulation {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024, .xWing768, .xWing1024:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func decapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        ciphertext: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024, .xWing768, .xWing1024:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func sealHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientPublicKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> ReallyMeHpkeSealedMessage {
        switch suite {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
             .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func openHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientSecretKey: [UInt8],
        encapsulatedKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        ciphertext: [UInt8]
    ) throws -> [UInt8] {
        switch suite {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
             .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }
}
