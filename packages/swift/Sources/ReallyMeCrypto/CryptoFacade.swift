// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Public/secret keypair returned by generic package facade key generation.
public struct ReallyMeSignatureKeyPair: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    public var description: String {
        "ReallyMeSignatureKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
    }

    public var debugDescription: String { description }
}

public struct ReallyMeKemKeyPair: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    public var description: String {
        "ReallyMeKemKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
    }

    public var debugDescription: String { description }
}

public struct ReallyMeKeyAgreementKeyPair: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let publicKey: [UInt8]
    public let secretKey: [UInt8]

    public init(publicKey: [UInt8], secretKey: [UInt8]) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    public var description: String {
        "ReallyMeKeyAgreementKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
    }

    public var debugDescription: String { description }
}

public struct ReallyMeKemEncapsulation: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let sharedSecret: [UInt8]
    public let ciphertext: [UInt8]

    public init(sharedSecret: [UInt8], ciphertext: [UInt8]) {
        self.sharedSecret = sharedSecret
        self.ciphertext = ciphertext
    }

    public var description: String {
        "ReallyMeKemEncapsulation(sharedSecret: <redacted>, ciphertextLength: \(ciphertext.count))"
    }

    public var debugDescription: String { description }
}

public struct ReallyMeHpkeSealedMessage: Equatable, Sendable {
    public let encapsulatedKey: [UInt8]
    public let ciphertext: [UInt8]

    public init(encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
        self.encapsulatedKey = encapsulatedKey
        self.ciphertext = ciphertext
    }
}

private let genericFacadeArgon2idDerivedKeyLength = 32

/// Provider configuration for the Swift facade.
///
/// Apple-native providers are always available through the package's normal
/// platform APIs. Release SwiftPM packages also ship and link the Rust C ABI
/// provider; local source-tree development can still pass an explicitly loaded
/// dynamic library when testing a freshly built `crypto-ffi`.
public struct ReallyMeCryptoProviders: Sendable {
    public let rustCAbiLibrary: ReallyMeRustCAbiLibrary?

    public init(rustCAbiLibrary: ReallyMeRustCAbiLibrary? = nil) {
        self.rustCAbiLibrary = rustCAbiLibrary
    }

    public static var `default`: ReallyMeCryptoProviders {
        #if REALLYME_CRYPTO_LINKED_FFI
        return ReallyMeCryptoProviders(rustCAbiLibrary: try? ReallyMeRustCAbiLibrary.bundledProvider())
        #else
        return ReallyMeCryptoProviders()
        #endif
    }
}

/// Generic package facade. Algorithm-specific types remain available for
/// callers that want direct provider access; this facade gives consumers a
/// stable typed route that fails closed for not-yet-exposed algorithms.
public struct ReallyMeCrypto: Sendable {
    public let providers: ReallyMeCryptoProviders

    public init(providers: ReallyMeCryptoProviders = .default) {
        self.providers = providers
    }

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
        case .aes128Gcm:
            return try ReallyMeAesGcm.sealAes128Gcm(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes192Gcm:
            return try ReallyMeAesGcm.sealAes192Gcm(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
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
        case .aes128Gcm:
            return try ReallyMeAesGcm.openAes128Gcm(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes192Gcm:
            return try ReallyMeAesGcm.openAes192Gcm(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
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
        case .hkdfSha256, .argon2id, .jwaConcatKdfSha256:
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
        case .argon2id, .pbkdf2HmacSha256, .pbkdf2HmacSha512, .jwaConcatKdfSha256:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func deriveJwaConcatKdfSha256(
        _ algorithm: ReallyMeKdfAlgorithm,
        sharedSecret: [UInt8],
        algorithmId: [UInt8],
        partyUInfo: [UInt8],
        partyVInfo: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        switch algorithm {
        case .jwaConcatKdfSha256:
            return try ReallyMeJwaConcatKdf.deriveSha256(
                sharedSecret: sharedSecret,
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: outputLength
            )
        case .argon2id, .hkdfSha256, .pbkdf2HmacSha256, .pbkdf2HmacSha512:
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
        case .p384Ecdh:
            return try ReallyMeP384Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
        case .p521Ecdh:
            return try ReallyMeP521Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
        }
    }

    public static func generateSecureEnclaveKeyAgreementKeyPair(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        tag: [UInt8],
        overwriteExisting: Bool = false
    ) throws -> ReallyMeKeyAgreementHandleKeyPair {
        switch algorithm {
        case .p256Ecdh:
            return try ReallyMeP256SecureEnclaveEcdh.generateKeyPair(
                tag: tag,
                overwriteExisting: overwriteExisting
            )
        case .x25519, .p384Ecdh, .p521Ecdh:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func deriveSharedSecretWithPrivateKeyHandle(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        publicKey: [UInt8],
        privateKeyHandle: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .p256Ecdh:
            return try ReallyMeP256SecureEnclaveEcdh.deriveSharedSecret(
                publicKey: publicKey,
                privateKeyHandle: privateKeyHandle
            )
        case .x25519, .p384Ecdh, .p521Ecdh:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func deleteSecureEnclaveKeyAgreementKey(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        privateKeyHandle: [UInt8]
    ) throws {
        switch algorithm {
        case .p256Ecdh:
            try ReallyMeP256SecureEnclaveEcdh.deleteKey(privateKeyHandle: privateKeyHandle)
        case .x25519, .p384Ecdh, .p521Ecdh:
            throw ReallyMeCryptoError.unsupportedAlgorithm
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
        case .p384Ecdh:
            let keyPair = try ReallyMeP384Ecdh.deriveKeyPair(secretKey: secretKey)
            return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        case .p521Ecdh:
            let keyPair = try ReallyMeP521Ecdh.deriveKeyPair(secretKey: secretKey)
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

    public func hash(_ algorithm: ReallyMeHashAlgorithm, _ bytes: [UInt8]) throws -> [UInt8] {
        try Self.hash(algorithm, bytes)
    }

    public func seal(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes128Gcm, .aes192Gcm, .aes256Gcm, .chacha20Poly1305:
            return try Self.seal(algorithm, key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes256GcmSiv, .xchacha20Poly1305:
            return try Self.seal(
                algorithm,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        }
    }

    public func open(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes128Gcm, .aes192Gcm, .aes256Gcm, .chacha20Poly1305:
            return try Self.open(
                algorithm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes256GcmSiv, .xchacha20Poly1305:
            return try Self.open(
                algorithm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        }
    }

    public func authenticate(
        _ algorithm: ReallyMeMacAlgorithm,
        key: [UInt8],
        message: [UInt8]
    ) throws -> [UInt8] {
        try Self.authenticate(algorithm, key: key, message: message)
    }

    public func verifyMac(
        _ algorithm: ReallyMeMacAlgorithm,
        tag: [UInt8],
        key: [UInt8],
        message: [UInt8]
    ) throws -> Bool {
        try Self.verifyMac(algorithm, tag: tag, key: key, message: message)
    }

    public func deriveKey(
        _ algorithm: ReallyMeKdfAlgorithm,
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws -> [UInt8] {
        switch algorithm {
        case .argon2id:
            guard outputLength == genericFacadeArgon2idDerivedKeyLength else {
                throw ReallyMeCryptoError.invalidInput
            }
            return try Self.deriveArgon2idKey(
                kdfVersion: iterations,
                secret: password,
                salt: salt,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .pbkdf2HmacSha256, .pbkdf2HmacSha512:
            return try Self.deriveKey(
                algorithm,
                password: password,
                salt: salt,
                iterations: iterations,
                outputLength: outputLength
            )
        case .hkdfSha256, .jwaConcatKdfSha256:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func deriveArgon2idKey(
        kdfVersion: UInt32,
        secret: [UInt8],
        salt: [UInt8]
    ) throws -> [UInt8] {
        try Self.deriveArgon2idKey(
            kdfVersion: kdfVersion,
            secret: secret,
            salt: salt,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func deriveHkdf(
        _ algorithm: ReallyMeKdfAlgorithm,
        inputKeyMaterial: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        try Self.deriveHkdf(
            algorithm,
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputLength: outputLength
        )
    }

    public func deriveJwaConcatKdfSha256(
        _ algorithm: ReallyMeKdfAlgorithm,
        sharedSecret: [UInt8],
        algorithmId: [UInt8],
        partyUInfo: [UInt8],
        partyVInfo: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        try Self.deriveJwaConcatKdfSha256(
            algorithm,
            sharedSecret: sharedSecret,
            algorithmId: algorithmId,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            outputLength: outputLength
        )
    }

    public func wrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        keyToWrap: [UInt8]
    ) throws -> [UInt8] {
        try Self.wrapKey(
            algorithm,
            wrappingKey: wrappingKey,
            keyToWrap: keyToWrap,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func unwrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        wrappedKey: [UInt8]
    ) throws -> [UInt8] {
        try Self.unwrapKey(
            algorithm,
            wrappingKey: wrappingKey,
            wrappedKey: wrappedKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func generateKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm
    ) throws -> ReallyMeSignatureKeyPair {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            return try Self.generateKeyPair(algorithm)
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            return try Self.generateKeyPair(algorithm, rustCAbiLibrary: requireRustCAbiLibrary())
        case .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func deriveKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeSignatureKeyPair {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            let keyPair = try ReallyMeSecp256k1.deriveKeyPair(secretKey: secretKey)
            return ReallyMeSignatureKeyPair(
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .bip340SchnorrSecp256k1Sha256,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            return try Self.deriveKeyPair(algorithm, secretKey: secretKey, rustCAbiLibrary: requireRustCAbiLibrary())
        case .slhDsaSha2_128s,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func deriveMlDsaKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeSignatureKeyPair {
        try Self.deriveMlDsaKeyPair(
            algorithm,
            secretKey: secretKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func deriveSlhDsaSha2_128sKeyPair(
        skSeed: [UInt8],
        skPrf: [UInt8],
        pkSeed: [UInt8]
    ) throws -> ReallyMeSignatureKeyPair {
        try Self.deriveSlhDsaSha2_128sKeyPair(
            skSeed: skSeed,
            skPrf: skPrf,
            pkSeed: pkSeed,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            return try Self.sign(algorithm, message: message, secretKey: secretKey)
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            return try Self.sign(
                algorithm,
                message: message,
                secretKey: secretKey,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func deriveBip340SchnorrPublicKey(secretKey: [UInt8]) throws -> [UInt8] {
        try Self.deriveBip340SchnorrPublicKey(
            secretKey: secretKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message32: [UInt8],
        secretKey: [UInt8],
        auxRand32: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .bip340SchnorrSecp256k1Sha256:
            return try Self.sign(
                algorithm,
                message32: message32,
                secretKey: secretKey,
                auxRand32: auxRand32,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .ecdsaSecp256k1Sha256,
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

    public func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        switch algorithm {
        case .ecdsaSecp256k1Sha256:
            try Self.verify(algorithm, signature: signature, message: message, publicKey: publicKey)
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .bip340SchnorrSecp256k1Sha256,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            try Self.verify(
                algorithm,
                signature: signature,
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKeyDer: [UInt8],
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding
    ) throws {
        switch algorithm {
        case .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512:
            try Self.verify(
                algorithm,
                signature: signature,
                message: message,
                publicKeyDer: publicKeyDer,
                publicKeyEncoding: publicKeyEncoding,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .ecdsaSecp256k1Sha256,
             .bip340SchnorrSecp256k1Sha256,
             .mlDsa44,
             .mlDsa65,
             .mlDsa87,
             .slhDsaSha2_128s:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public func deriveSharedSecret(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        publicKey: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        try Self.deriveSharedSecret(algorithm, publicKey: publicKey, secretKey: secretKey)
    }

    public func deriveKeyAgreementKeyPair(
        _ algorithm: ReallyMeKeyAgreementAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeKeyAgreementKeyPair {
        try Self.deriveKeyAgreementKeyPair(algorithm, secretKey: secretKey)
    }

    public func generateKemKeyPair(_ algorithm: ReallyMeKemAlgorithm) throws -> ReallyMeKemKeyPair {
        try Self.generateKemKeyPair(algorithm, rustCAbiLibrary: requireRustCAbiLibrary())
    }

    public func deriveXWingKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeKemKeyPair {
        try Self.deriveXWingKeyPair(
            algorithm,
            secretKey: secretKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func deriveMlKemKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeKemKeyPair {
        try Self.deriveMlKemKeyPair(
            algorithm,
            secretKey: secretKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func encapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        publicKey: [UInt8]
    ) throws -> ReallyMeKemEncapsulation {
        switch algorithm {
        case .xWing768, .xWing1024:
            return try Self.encapsulate(
                algorithm,
                publicKey: publicKey,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        case .mlKem512, .mlKem768, .mlKem1024:
            return try Self.encapsulate(
                algorithm,
                publicKey: publicKey,
                rustCAbiLibrary: requireRustCAbiLibrary()
            )
        }
    }

    public func encapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        publicKey: [UInt8],
        seed: [UInt8]
    ) throws -> ReallyMeKemEncapsulation {
        try Self.encapsulate(
            algorithm,
            publicKey: publicKey,
            seed: seed,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func decapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        ciphertext: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        try Self.decapsulate(
            algorithm,
            ciphertext: ciphertext,
            secretKey: secretKey,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func sealHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientPublicKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> ReallyMeHpkeSealedMessage {
        try Self.sealHpke(
            suite,
            recipientPublicKey: recipientPublicKey,
            info: info,
            aad: aad,
            plaintext: plaintext,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    public func openHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientSecretKey: [UInt8],
        encapsulatedKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        ciphertext: [UInt8]
    ) throws -> [UInt8] {
        try Self.openHpke(
            suite,
            recipientSecretKey: recipientSecretKey,
            encapsulatedKey: encapsulatedKey,
            info: info,
            aad: aad,
            ciphertext: ciphertext,
            rustCAbiLibrary: requireRustCAbiLibrary()
        )
    }

    private func requireRustCAbiLibrary() throws -> ReallyMeRustCAbiLibrary {
        guard let library = providers.rustCAbiLibrary else {
            throw ReallyMeCryptoError.providerFailure
        }
        return library
    }
}
