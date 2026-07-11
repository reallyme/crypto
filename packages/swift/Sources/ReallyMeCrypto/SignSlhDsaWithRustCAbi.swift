// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiSlhDsaSha2_128sPublicKeyLength = 32
private let rustCAbiSlhDsaSha2_128sSecretKeyLength = 64
private let rustCAbiSlhDsaSha2_128sSignatureLength = 7_856
private let rustCAbiSlhDsaSha2_128sKeygenSeedLength = 16

private typealias SlhDsaGenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias SlhDsaDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias SlhDsaSignFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias SlhDsaVerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// SLH-DSA-SHA2-128s operations backed by the ReallyMe Rust C ABI.
///
/// The seed-derived keypair route is intentionally exposed because FIPS 205
/// vectors define three independent 16-byte keygen seeds. Keeping that shape
/// visible prevents package lanes from silently inventing a different private
/// key format.
public struct ReallyMeRustCAbiSlhDsa: Sendable {
    private let generateKeyPairFunction: SlhDsaGenerateKeyPairFunction
    private let deriveKeyPairFunction: SlhDsaDeriveKeyPairFunction
    private let signFunction: SlhDsaSignFunction
    private let verifyFunction: SlhDsaVerifyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        generateKeyPairFunction = try library.loadFunction(
            "rm_crypto_slh_dsa_sha2_128s_generate_keypair",
            as: SlhDsaGenerateKeyPairFunction.self
        )
        deriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_slh_dsa_sha2_128s_derive_keypair",
            as: SlhDsaDeriveKeyPairFunction.self
        )
        signFunction = try library.loadFunction(
            "rm_crypto_slh_dsa_sha2_128s_sign",
            as: SlhDsaSignFunction.self
        )
        verifyFunction = try library.loadFunction(
            "rm_crypto_slh_dsa_sha2_128s_verify",
            as: SlhDsaVerifyFunction.self
        )
    }

    public func generateKeyPair(_ algorithm: ReallyMeSignatureAlgorithm) throws -> ReallyMeSignatureKeyPair {
        try requireSlhDsaSha2_128s(algorithm)

        var publicKey = [UInt8](repeating: 0, count: rustCAbiSlhDsaSha2_128sPublicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiSlhDsaSha2_128sSecretKeyLength)
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

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func deriveKeyPair(
        _ algorithm: ReallyMeSignatureAlgorithm,
        skSeed: [UInt8],
        skPrf: [UInt8],
        pkSeed: [UInt8]
    ) throws -> ReallyMeSignatureKeyPair {
        try requireSlhDsaSha2_128s(algorithm)
        guard skSeed.count == rustCAbiSlhDsaSha2_128sKeygenSeedLength,
              skPrf.count == rustCAbiSlhDsaSha2_128sKeygenSeedLength,
              pkSeed.count == rustCAbiSlhDsaSha2_128sKeygenSeedLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: rustCAbiSlhDsaSha2_128sPublicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiSlhDsaSha2_128sSecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = secretKey.count
        let status = skSeed.withUnsafeBufferPointer { skSeedBuffer in
            skPrf.withUnsafeBufferPointer { skPrfBuffer in
                pkSeed.withUnsafeBufferPointer { pkSeedBuffer in
                    publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                        secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                            deriveKeyPairFunction(
                                skSeedBuffer.baseAddress,
                                skSeed.count,
                                skPrfBuffer.baseAddress,
                                skPrf.count,
                                pkSeedBuffer.baseAddress,
                                pkSeed.count,
                                publicBuffer.baseAddress,
                                publicKeyCapacity,
                                secretBuffer.baseAddress,
                                secretKeyCapacity
                            )
                        }
                    }
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        try requireSlhDsaSha2_128s(algorithm)
        guard secretKey.count == rustCAbiSlhDsaSha2_128sSecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: rustCAbiSlhDsaSha2_128sSignatureLength)
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

    public func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        try requireSlhDsaSha2_128s(algorithm)
        guard publicKey.count == rustCAbiSlhDsaSha2_128sPublicKeyLength,
              signature.count == rustCAbiSlhDsaSha2_128sSignatureLength
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

    private func requireSlhDsaSha2_128s(_ algorithm: ReallyMeSignatureAlgorithm) throws {
        switch algorithm {
        case .slhDsaSha2_128s:
            return
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
             .mlDsa44,
             .mlDsa65,
             .mlDsa87:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }
}

public extension ReallyMeCrypto {
    static func deriveSlhDsaSha2_128sKeyPair(
        skSeed: [UInt8],
        skPrf: [UInt8],
        pkSeed: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeSignatureKeyPair {
        try ReallyMeRustCAbiSlhDsa(library: rustCAbiLibrary).deriveKeyPair(
            .slhDsaSha2_128s,
            skSeed: skSeed,
            skPrf: skPrf,
            pkSeed: pkSeed
        )
    }
}
