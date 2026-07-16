// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiMlDsa44PublicKeyLength = 1_312
private let rustCAbiMlDsa44SignatureLength = 2_420
private let rustCAbiMlDsa65PublicKeyLength = 1_952
private let rustCAbiMlDsa65SignatureLength = 3_309
private let rustCAbiMlDsa87PublicKeyLength = 2_592
private let rustCAbiMlDsa87SignatureLength = 4_627
private let rustCAbiMlDsaSecretSeedLength = 32

private typealias MlDsaGenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlDsaDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlDsaSignFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlDsaVerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

private struct RustCAbiMlDsaSuite {
    let publicKeyLength: Int
    let signatureLength: Int
    let generateKeyPairFunction: MlDsaGenerateKeyPairFunction
    let deriveKeyPairFunction: MlDsaDeriveKeyPairFunction
    let signFunction: MlDsaSignFunction
    let verifyFunction: MlDsaVerifyFunction
}

/// ML-DSA operations backed by the ReallyMe Rust C ABI.
///
/// The Swift package keeps the same FIPS 204 seed-format secret key contract
/// as Rust. That avoids accidental expansion-format drift between package
/// lanes and lets conformance vectors compare signatures byte-for-byte.
public struct ReallyMeRustCAbiMlDsa: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let mlDsa44GenerateKeyPairFunction: MlDsaGenerateKeyPairFunction
    private let mlDsa44DeriveKeyPairFunction: MlDsaDeriveKeyPairFunction
    private let mlDsa44SignFunction: MlDsaSignFunction
    private let mlDsa44VerifyFunction: MlDsaVerifyFunction
    private let mlDsa65GenerateKeyPairFunction: MlDsaGenerateKeyPairFunction
    private let mlDsa65DeriveKeyPairFunction: MlDsaDeriveKeyPairFunction
    private let mlDsa65SignFunction: MlDsaSignFunction
    private let mlDsa65VerifyFunction: MlDsaVerifyFunction
    private let mlDsa87GenerateKeyPairFunction: MlDsaGenerateKeyPairFunction
    private let mlDsa87DeriveKeyPairFunction: MlDsaDeriveKeyPairFunction
    private let mlDsa87SignFunction: MlDsaSignFunction
    private let mlDsa87VerifyFunction: MlDsaVerifyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        mlDsa44GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_44_generate_keypair",
            as: MlDsaGenerateKeyPairFunction.self
        )
        mlDsa44DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_44_generate_keypair_from_seed",
            as: MlDsaDeriveKeyPairFunction.self
        )
        mlDsa44SignFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_44_sign",
            as: MlDsaSignFunction.self
        )
        mlDsa44VerifyFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_44_verify",
            as: MlDsaVerifyFunction.self
        )
        mlDsa65GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_65_generate_keypair",
            as: MlDsaGenerateKeyPairFunction.self
        )
        mlDsa65DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_65_generate_keypair_from_seed",
            as: MlDsaDeriveKeyPairFunction.self
        )
        mlDsa65SignFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_65_sign",
            as: MlDsaSignFunction.self
        )
        mlDsa65VerifyFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_65_verify",
            as: MlDsaVerifyFunction.self
        )
        mlDsa87GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_87_generate_keypair",
            as: MlDsaGenerateKeyPairFunction.self
        )
        mlDsa87DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_87_generate_keypair_from_seed",
            as: MlDsaDeriveKeyPairFunction.self
        )
        mlDsa87SignFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_87_sign",
            as: MlDsaSignFunction.self
        )
        mlDsa87VerifyFunction = try library.loadFunction(
            "rm_crypto_ml_dsa_87_verify",
            as: MlDsaVerifyFunction.self
        )
    }

    public func generateKeyPair(_ algorithm: ReallyMeSignatureAlgorithm) throws -> ReallyMeSignatureKeyPair {
        let suite = try rustSuite(for: algorithm)
        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiMlDsaSecretSeedLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = secretKey.count
        let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
            secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                suite.generateKeyPairFunction(
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

    public func deriveKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeSignatureKeyPair {
        let suite = try rustSuite(for: algorithm)
        guard secretKey.count == rustCAbiMlDsaSecretSeedLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiMlDsaSecretSeedLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = returnedSecretKey.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                returnedSecretKey.withUnsafeMutableBufferPointer { returnedSecretBuffer in
                    suite.deriveKeyPairFunction(
                        secretBuffer.baseAddress,
                        secretKey.count,
                        publicBuffer.baseAddress,
                        publicKeyCapacity,
                        returnedSecretBuffer.baseAddress,
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

    public func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        let suite = try rustSuite(for: algorithm)
        guard secretKey.count == rustCAbiMlDsaSecretSeedLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: suite.signatureLength)
        let signatureCapacity = signature.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeMutableBufferPointer { signatureBuffer in
                    suite.signFunction(
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

    public func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        let suite = try rustSuite(for: algorithm)
        guard publicKey.count == suite.publicKeyLength,
              signature.count == suite.signatureLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let status = publicKey.withUnsafeBufferPointer { publicBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeBufferPointer { signatureBuffer in
                    suite.verifyFunction(
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

    private func rustSuite(for algorithm: ReallyMeSignatureAlgorithm) throws -> RustCAbiMlDsaSuite {
        switch algorithm {
        case .mlDsa44:
            return RustCAbiMlDsaSuite(
                publicKeyLength: rustCAbiMlDsa44PublicKeyLength,
                signatureLength: rustCAbiMlDsa44SignatureLength,
                generateKeyPairFunction: mlDsa44GenerateKeyPairFunction,
                deriveKeyPairFunction: mlDsa44DeriveKeyPairFunction,
                signFunction: mlDsa44SignFunction,
                verifyFunction: mlDsa44VerifyFunction
            )
        case .mlDsa65:
            return RustCAbiMlDsaSuite(
                publicKeyLength: rustCAbiMlDsa65PublicKeyLength,
                signatureLength: rustCAbiMlDsa65SignatureLength,
                generateKeyPairFunction: mlDsa65GenerateKeyPairFunction,
                deriveKeyPairFunction: mlDsa65DeriveKeyPairFunction,
                signFunction: mlDsa65SignFunction,
                verifyFunction: mlDsa65VerifyFunction
            )
        case .mlDsa87:
            return RustCAbiMlDsaSuite(
                publicKeyLength: rustCAbiMlDsa87PublicKeyLength,
                signatureLength: rustCAbiMlDsa87SignatureLength,
                generateKeyPairFunction: mlDsa87GenerateKeyPairFunction,
                deriveKeyPairFunction: mlDsa87DeriveKeyPairFunction,
                signFunction: mlDsa87SignFunction,
                verifyFunction: mlDsa87VerifyFunction
            )
        case .ed25519,
             .ecdsaP256Sha256,
             .ecdsaP384Sha384,
             .ecdsaP521Sha512,
             .ecdsaSecp256k1Sha256,
             .bip340SchnorrSecp256k1Sha256,
             .rsaPkcs1v15Sha1,
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
}
