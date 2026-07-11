// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiP521SecretKeyLength = 66
private let rustCAbiP521CompressedPublicKeyLength = 67
private let rustCAbiP521UncompressedPublicKeyLength = 133
private let rustCAbiP521SignatureDerMaxLength = 144

private typealias P521GenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias P521GenerateKeyPairFromSecretKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias P521SignDerPrehashFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt>?
) -> Int32

private typealias P521VerifyDerPrehashFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// P-521 ECDSA operations backed by the ReallyMe Rust C ABI.
///
/// This explicit provider preserves the repository's deterministic
/// DER/SHA-512 signature contract for Swift package consumers without relying
/// on whichever Apple provider behavior is available at runtime.
public struct ReallyMeRustCAbiP521Ecdsa: Sendable {
    private let generateKeyPairFunction: P521GenerateKeyPairFunction
    private let generateKeyPairFromSecretKeyFunction: P521GenerateKeyPairFromSecretKeyFunction
    private let signFunction: P521SignDerPrehashFunction
    private let verifyFunction: P521VerifyDerPrehashFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        generateKeyPairFunction = try library.loadFunction(
            "rm_crypto_p521_generate_keypair",
            as: P521GenerateKeyPairFunction.self
        )
        generateKeyPairFromSecretKeyFunction = try library.loadFunction(
            "rm_crypto_p521_generate_keypair_from_secret_key",
            as: P521GenerateKeyPairFromSecretKeyFunction.self
        )
        signFunction = try library.loadFunction(
            "rm_crypto_p521_sign_der_prehash",
            as: P521SignDerPrehashFunction.self
        )
        verifyFunction = try library.loadFunction(
            "rm_crypto_p521_verify_der_prehash",
            as: P521VerifyDerPrehashFunction.self
        )
    }

    public func generateKeyPair() throws -> ReallyMeSignatureKeyPair {
        var publicKey = [UInt8](repeating: 0, count: rustCAbiP521CompressedPublicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiP521SecretKeyLength)
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

    public func deriveKeyPair(secretKey: [UInt8]) throws -> ReallyMeSignatureKeyPair {
        guard secretKey.count == rustCAbiP521SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: rustCAbiP521CompressedPublicKeyLength)
        var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiP521SecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = returnedSecretKey.count

        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                returnedSecretKey.withUnsafeMutableBufferPointer { returnedSecretBuffer in
                    generateKeyPairFromSecretKeyFunction(
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

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: returnedSecretKey)
    }

    public func sign(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == rustCAbiP521SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: rustCAbiP521SignatureDerMaxLength)
        var signatureLength: UInt = 0
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
                        signatureCapacity,
                        &signatureLength
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        guard let length = Int(exactly: signatureLength),
              length > 0,
              length <= rustCAbiP521SignatureDerMaxLength
        else {
            throw ReallyMeCryptoError.providerFailure
        }
        return Array(signature.prefix(length))
    }

    public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) throws {
        guard publicKey.count == rustCAbiP521CompressedPublicKeyLength
            || publicKey.count == rustCAbiP521UncompressedPublicKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let status = signature.withUnsafeBufferPointer { signatureBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                publicKey.withUnsafeBufferPointer { publicKeyBuffer in
                    verifyFunction(
                        signatureBuffer.baseAddress,
                        signature.count,
                        messageBuffer.baseAddress,
                        message.count,
                        publicKeyBuffer.baseAddress,
                        publicKey.count
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
    }
}
