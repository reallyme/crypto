// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiP384SecretKeyLength = 48
private let rustCAbiP384CompressedPublicKeyLength = 49
private let rustCAbiP384UncompressedPublicKeyLength = 97
private let rustCAbiP384SignatureDerMaxLength = 104

private typealias P384GenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias P384GenerateKeyPairFromSecretKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias P384SignDerPrehashFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt>?
) -> Int32

private typealias P384VerifyDerPrehashFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// P-384 ECDSA operations backed by the ReallyMe Rust C ABI.
///
/// Apple APIs are available for P-384, but this package route is reserved for
/// the repository's deterministic DER/SHA-384 vector contract. Keeping it
/// explicit prevents silent provider drift between Swift and Rust.
public struct ReallyMeRustCAbiP384Ecdsa: Sendable {
    private let generateKeyPairFunction: P384GenerateKeyPairFunction
    private let generateKeyPairFromSecretKeyFunction: P384GenerateKeyPairFromSecretKeyFunction
    private let signFunction: P384SignDerPrehashFunction
    private let verifyFunction: P384VerifyDerPrehashFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        generateKeyPairFunction = try library.loadFunction(
            "rm_crypto_p384_generate_keypair",
            as: P384GenerateKeyPairFunction.self
        )
        generateKeyPairFromSecretKeyFunction = try library.loadFunction(
            "rm_crypto_p384_generate_keypair_from_secret_key",
            as: P384GenerateKeyPairFromSecretKeyFunction.self
        )
        signFunction = try library.loadFunction(
            "rm_crypto_p384_sign_der_prehash",
            as: P384SignDerPrehashFunction.self
        )
        verifyFunction = try library.loadFunction(
            "rm_crypto_p384_verify_der_prehash",
            as: P384VerifyDerPrehashFunction.self
        )
    }

    public func generateKeyPair() throws -> ReallyMeSignatureKeyPair {
        var publicKey = [UInt8](repeating: 0, count: rustCAbiP384CompressedPublicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiP384SecretKeyLength)
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
        guard secretKey.count == rustCAbiP384SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: rustCAbiP384CompressedPublicKeyLength)
        var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiP384SecretKeyLength)
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
        guard secretKey.count == rustCAbiP384SecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var signature = [UInt8](repeating: 0, count: rustCAbiP384SignatureDerMaxLength)
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
              length <= rustCAbiP384SignatureDerMaxLength
        else {
            throw ReallyMeCryptoError.providerFailure
        }
        return Array(signature.prefix(length))
    }

    public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) throws {
        guard publicKey.count == rustCAbiP384CompressedPublicKeyLength
            || publicKey.count == rustCAbiP384UncompressedPublicKeyLength
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
