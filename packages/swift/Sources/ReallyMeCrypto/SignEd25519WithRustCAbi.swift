// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiEd25519PublicKeyLength = 32
private let rustCAbiEd25519SecretKeyLength = 32
private let rustCAbiEd25519SignatureLength = 64

private typealias Ed25519GenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias Ed25519GenerateKeyPairFromSeedFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias Ed25519SignFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias Ed25519VerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// Ed25519 operations backed by the ReallyMe Rust C ABI.
///
/// CryptoKit verification is useful, but CryptoKit signing on this target is
/// randomized and therefore cannot satisfy the repository's cross-lane KAT.
/// This explicit provider gives Swift callers deterministic RFC 8032 Ed25519
/// while keeping the default Swift facade fail-closed.
public struct ReallyMeRustCAbiEd25519: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let generateKeyPairFunction: Ed25519GenerateKeyPairFunction
    private let generateKeyPairFromSeedFunction: Ed25519GenerateKeyPairFromSeedFunction
    private let signFunction: Ed25519SignFunction
    private let verifyFunction: Ed25519VerifyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        generateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ed25519_generate_keypair",
            as: Ed25519GenerateKeyPairFunction.self
        )
        generateKeyPairFromSeedFunction = try library.loadFunction(
            "rm_crypto_ed25519_generate_keypair_from_seed",
            as: Ed25519GenerateKeyPairFromSeedFunction.self
        )
        signFunction = try library.loadFunction(
            "rm_crypto_ed25519_sign",
            as: Ed25519SignFunction.self
        )
        verifyFunction = try library.loadFunction(
            "rm_crypto_ed25519_verify",
            as: Ed25519VerifyFunction.self
        )
    }

    public func generateKeyPair() throws -> ReallyMeSignatureKeyPair {
        var publicKey = [UInt8](repeating: 0, count: rustCAbiEd25519PublicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiEd25519SecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = secretKey.count

        let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
            secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                generateKeyPairFunction(
                    publicBuffer.baseAddress,
                    publicKeyCapacity,
                    secretBuffer.baseAddress,
                    secretKeyCapacity
                )
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&secretKey)
            throw error
        }
        return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func deriveKeyPair(secretKey: [UInt8]) throws -> ReallyMeSignatureKeyPair {
        guard secretKey.count == rustCAbiEd25519SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: rustCAbiEd25519PublicKeyLength)
        var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiEd25519SecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = returnedSecretKey.count

        let status = secretKey.withUnsafeBufferPointer { seedBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                returnedSecretKey.withUnsafeMutableBufferPointer { secretBuffer in
                    generateKeyPairFromSeedFunction(
                        seedBuffer.baseAddress,
                        secretKey.count,
                        publicBuffer.baseAddress,
                        publicKeyCapacity,
                        secretBuffer.baseAddress,
                        secretKeyCapacity
                    )
                }
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&returnedSecretKey)
            throw error
        }
        return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: returnedSecretKey)
    }

    public func sign(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == rustCAbiEd25519SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: rustCAbiEd25519SignatureLength)
        let signatureCapacity = signature.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeMutableBufferPointer { signatureBuffer in
                    signFunction(
                        secretBuffer.baseAddress,
                        secretKey.count,
                        messageBuffer.baseAddress,
                        message.count,
                        signatureBuffer.baseAddress,
                        signatureCapacity
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return signature
    }

    public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) throws {
        guard publicKey.count == rustCAbiEd25519PublicKeyLength,
              signature.count == rustCAbiEd25519SignatureLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let status = publicKey.withUnsafeBufferPointer { publicBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeBufferPointer { signatureBuffer in
                    verifyFunction(
                        publicBuffer.baseAddress,
                        publicKey.count,
                        messageBuffer.baseAddress,
                        message.count,
                        signatureBuffer.baseAddress,
                        signature.count
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
    }
}

public extension ReallyMeCrypto {
    static func generateKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeSignatureKeyPair {
        switch algorithm {
        case .ed25519:
            return try ReallyMeRustCAbiEd25519(library: rustCAbiLibrary).generateKeyPair()
        case .ecdsaP256Sha256:
            return try ReallyMeRustCAbiP256Ecdsa(library: rustCAbiLibrary).generateKeyPair()
        case .ecdsaP384Sha384:
            return try ReallyMeRustCAbiP384Ecdsa(library: rustCAbiLibrary).generateKeyPair()
        case .ecdsaP521Sha512:
            return try ReallyMeRustCAbiP521Ecdsa(library: rustCAbiLibrary).generateKeyPair()
        case .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            return try ReallyMeRustCAbiMlDsa(library: rustCAbiLibrary).generateKeyPair(algorithm)
        case .slhDsaSha2_128s:
            return try ReallyMeRustCAbiSlhDsa(library: rustCAbiLibrary).generateKeyPair(algorithm)
        case .ecdsaSecp256k1Sha256,
             .bip340SchnorrSecp256k1Sha256,
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

    static func deriveMlDsaKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeSignatureKeyPair {
        try ReallyMeRustCAbiMlDsa(library: rustCAbiLibrary)
            .deriveKeyPair(algorithm, secretKey: secretKey)
    }

    static func deriveKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeSignatureKeyPair {
        switch algorithm {
        case .ed25519:
            return try ReallyMeRustCAbiEd25519(library: rustCAbiLibrary)
                .deriveKeyPair(secretKey: secretKey)
        case .ecdsaP256Sha256:
            return try ReallyMeRustCAbiP256Ecdsa(library: rustCAbiLibrary)
                .deriveKeyPair(secretKey: secretKey)
        case .ecdsaP384Sha384:
            return try ReallyMeRustCAbiP384Ecdsa(library: rustCAbiLibrary)
                .deriveKeyPair(secretKey: secretKey)
        case .ecdsaP521Sha512:
            return try ReallyMeRustCAbiP521Ecdsa(library: rustCAbiLibrary)
                .deriveKeyPair(secretKey: secretKey)
        case .ecdsaSecp256k1Sha256:
            let keyPair = try ReallyMeSecp256k1.deriveKeyPair(secretKey: secretKey)
            return ReallyMeSignatureKeyPair(
                publicKey: keyPair.publicKey,
                secretKey: keyPair.secretKey
            )
        case .bip340SchnorrSecp256k1Sha256:
            return try ReallyMeRustCAbiBip340Schnorr(library: rustCAbiLibrary)
                .deriveKeyPair(secretKey: secretKey)
        case .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            return try ReallyMeRustCAbiMlDsa(library: rustCAbiLibrary)
                .deriveKeyPair(algorithm, secretKey: secretKey)
        case .rsaPkcs1v15Sha1,
             .rsaPkcs1v15Sha256,
             .rsaPkcs1v15Sha384,
             .rsaPkcs1v15Sha512,
             .rsaPssSha1Mgf1Sha1,
             .rsaPssSha256Mgf1Sha256,
             .rsaPssSha384Mgf1Sha384,
             .rsaPssSha512Mgf1Sha512,
             .slhDsaSha2_128s:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    static func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message: [UInt8],
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .ed25519:
            return try ReallyMeRustCAbiEd25519(library: rustCAbiLibrary)
                .sign(message: message, secretKey: secretKey)
        case .ecdsaP256Sha256:
            return try ReallyMeRustCAbiP256Ecdsa(library: rustCAbiLibrary)
                .sign(message: message, secretKey: secretKey)
        case .ecdsaP384Sha384:
            return try ReallyMeRustCAbiP384Ecdsa(library: rustCAbiLibrary)
                .sign(message: message, secretKey: secretKey)
        case .ecdsaP521Sha512:
            return try ReallyMeRustCAbiP521Ecdsa(library: rustCAbiLibrary)
                .sign(message: message, secretKey: secretKey)
        case .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            return try ReallyMeRustCAbiMlDsa(library: rustCAbiLibrary)
                .sign(algorithm, message: message, secretKey: secretKey)
        case .slhDsaSha2_128s:
            return try ReallyMeRustCAbiSlhDsa(library: rustCAbiLibrary)
                .sign(algorithm, message: message, secretKey: secretKey)
        case .ecdsaSecp256k1Sha256,
             .bip340SchnorrSecp256k1Sha256,
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

    static func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws {
        switch algorithm {
        case .ed25519:
            return try ReallyMeRustCAbiEd25519(library: rustCAbiLibrary)
                .verify(signature: signature, message: message, publicKey: publicKey)
        case .ecdsaP256Sha256:
            return try ReallyMeRustCAbiP256Ecdsa(library: rustCAbiLibrary)
                .verify(signature: signature, message: message, publicKey: publicKey)
        case .ecdsaP384Sha384:
            return try ReallyMeRustCAbiP384Ecdsa(library: rustCAbiLibrary)
                .verify(signature: signature, message: message, publicKey: publicKey)
        case .ecdsaP521Sha512:
            return try ReallyMeRustCAbiP521Ecdsa(library: rustCAbiLibrary)
                .verify(signature: signature, message: message, publicKey: publicKey)
        case .bip340SchnorrSecp256k1Sha256:
            return try ReallyMeRustCAbiBip340Schnorr(library: rustCAbiLibrary)
                .verify(signature: signature, message32: message, publicKeyXOnly: publicKey)
        case .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            return try ReallyMeRustCAbiMlDsa(library: rustCAbiLibrary)
                .verify(algorithm, signature: signature, message: message, publicKey: publicKey)
        case .slhDsaSha2_128s:
            return try ReallyMeRustCAbiSlhDsa(library: rustCAbiLibrary)
                .verify(algorithm, signature: signature, message: message, publicKey: publicKey)
        case .ecdsaSecp256k1Sha256,
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
}
