// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiBip340SchnorrSecretKeyLength = 32
private let rustCAbiBip340SchnorrPublicKeyLength = 32
private let rustCAbiBip340SchnorrMessageLength = 32
private let rustCAbiBip340SchnorrAuxRandLength = 32
private let rustCAbiBip340SchnorrSignatureLength = 64

private typealias Bip340SchnorrDerivePublicKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias Bip340SchnorrSignFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias Bip340SchnorrVerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// BIP-340 Schnorr operations backed by the ReallyMe Rust C ABI.
///
/// BIP-340 signs a 32-byte message digest and takes 32 bytes of auxiliary
/// randomness. The package keeps that input explicit so callers do not confuse
/// this primitive with arbitrary-message signing.
public struct ReallyMeRustCAbiBip340Schnorr: Sendable {
    private let derivePublicKeyFunction: Bip340SchnorrDerivePublicKeyFunction
    private let signFunction: Bip340SchnorrSignFunction
    private let verifyFunction: Bip340SchnorrVerifyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        derivePublicKeyFunction = try library.loadFunction(
            "rm_crypto_bip340_schnorr_derive_public_key",
            as: Bip340SchnorrDerivePublicKeyFunction.self
        )
        signFunction = try library.loadFunction(
            "rm_crypto_bip340_schnorr_sign",
            as: Bip340SchnorrSignFunction.self
        )
        verifyFunction = try library.loadFunction(
            "rm_crypto_bip340_schnorr_verify",
            as: Bip340SchnorrVerifyFunction.self
        )
    }

    public func derivePublicKey(secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == rustCAbiBip340SchnorrSecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: rustCAbiBip340SchnorrPublicKeyLength)
        let publicKeyCapacity = publicKey.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                derivePublicKeyFunction(
                    secretBuffer.baseAddress,
                    secretKey.count,
                    publicBuffer.baseAddress,
                    publicKeyCapacity
                )
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return publicKey
    }

    public func deriveKeyPair(secretKey: [UInt8]) throws -> ReallyMeSignatureKeyPair {
        ReallyMeSignatureKeyPair(
            publicKey: try derivePublicKey(secretKey: secretKey),
            secretKey: secretKey
        )
    }

    public func sign(message32: [UInt8], secretKey: [UInt8], auxRand32: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == rustCAbiBip340SchnorrSecretKeyLength,
              message32.count == rustCAbiBip340SchnorrMessageLength,
              auxRand32.count == rustCAbiBip340SchnorrAuxRandLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: rustCAbiBip340SchnorrSignatureLength)
        let signatureCapacity = signature.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            message32.withUnsafeBufferPointer { messageBuffer in
                auxRand32.withUnsafeBufferPointer { auxRandBuffer in
                    signature.withUnsafeMutableBufferPointer { signatureBuffer in
                        signFunction(
                            secretBuffer.baseAddress,
                            secretKey.count,
                            messageBuffer.baseAddress,
                            message32.count,
                            auxRandBuffer.baseAddress,
                            auxRand32.count,
                            signatureBuffer.baseAddress,
                            signatureCapacity
                        )
                    }
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return signature
    }

    public func verify(signature: [UInt8], message32: [UInt8], publicKeyXOnly: [UInt8]) throws {
        guard signature.count == rustCAbiBip340SchnorrSignatureLength,
              message32.count == rustCAbiBip340SchnorrMessageLength,
              publicKeyXOnly.count == rustCAbiBip340SchnorrPublicKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let status = signature.withUnsafeBufferPointer { signatureBuffer in
            message32.withUnsafeBufferPointer { messageBuffer in
                publicKeyXOnly.withUnsafeBufferPointer { publicKeyBuffer in
                    verifyFunction(
                        signatureBuffer.baseAddress,
                        signature.count,
                        messageBuffer.baseAddress,
                        message32.count,
                        publicKeyBuffer.baseAddress,
                        publicKeyXOnly.count
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
    }
}

public extension ReallyMeCrypto {
    static func deriveBip340SchnorrPublicKey(
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        try ReallyMeRustCAbiBip340Schnorr(library: rustCAbiLibrary)
            .derivePublicKey(secretKey: secretKey)
    }

    static func sign(
        _ algorithm: ReallyMeSignatureAlgorithm,
        message32: [UInt8],
        secretKey: [UInt8],
        auxRand32: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .bip340SchnorrSecp256k1Sha256:
            return try ReallyMeRustCAbiBip340Schnorr(library: rustCAbiLibrary)
                .sign(message32: message32, secretKey: secretKey, auxRand32: auxRand32)
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
}
