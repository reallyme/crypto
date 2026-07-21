// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

public enum ReallyMeRsaPublicKeyDerEncoding: Sendable {
    case pkcs1
    case spki

    fileprivate var ffiId: UInt32 {
        switch self {
        case .pkcs1:
            return 1
        case .spki:
            return 2
        }
    }
}

private struct RsaPkcs1v15Suite {
    let hashSuite: UInt32
}

private struct RsaPssSuite {
    let messageHashSuite: UInt32
    let mgf1HashSuite: UInt32
    let saltLength: Int
}

private typealias RsaVerifyPkcs1v15Function = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UInt32,
    UInt32,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

private typealias RsaVerifyPssFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UInt32,
    UInt32,
    UInt32,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
) -> Int32

/// RSA signature verification backed by the ReallyMe Rust C ABI.
///
/// The SDK exposes RSA only as verification. These routes exist for X.509,
/// eMRTD passive authentication, and historical document verification;
/// package code must not add RSA signing without a separate key-residency and
/// padding policy review.
public struct ReallyMeRustCAbiRsa: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let verifyPkcs1v15Function: RsaVerifyPkcs1v15Function
    private let verifyPssFunction: RsaVerifyPssFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        verifyPkcs1v15Function = try library.loadFunction(
            "rm_crypto_rsa_verify_pkcs1v15",
            as: RsaVerifyPkcs1v15Function.self
        )
        verifyPssFunction = try library.loadFunction(
            "rm_crypto_rsa_verify_pss",
            as: RsaVerifyPssFunction.self
        )
    }

    public func verify(
        algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKeyDer: [UInt8],
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding
    ) throws {
        if let suite = pkcs1v15Suite(for: algorithm) {
            return try verifyPkcs1v15(
                suite: suite,
                signature: signature,
                message: message,
                publicKeyDer: publicKeyDer,
                publicKeyEncoding: publicKeyEncoding
            )
        }
        if let suite = pssSuite(for: algorithm) {
            return try verifyPss(
                suite: suite,
                signature: signature,
                message: message,
                publicKeyDer: publicKeyDer,
                publicKeyEncoding: publicKeyEncoding
            )
        }
        throw ReallyMeCryptoError.unsupportedAlgorithm
    }

    private func verifyPkcs1v15(
        suite: RsaPkcs1v15Suite,
        signature: [UInt8],
        message: [UInt8],
        publicKeyDer: [UInt8],
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding
    ) throws {
        let status = publicKeyDer.withUnsafeBufferPointer { publicKeyBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeBufferPointer { signatureBuffer in
                    verifyPkcs1v15Function(
                        publicKeyBuffer.baseAddress,
                        publicKeyDer.count,
                        publicKeyEncoding.ffiId,
                        suite.hashSuite,
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

    private func verifyPss(
        suite: RsaPssSuite,
        signature: [UInt8],
        message: [UInt8],
        publicKeyDer: [UInt8],
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding
    ) throws {
        let status = publicKeyDer.withUnsafeBufferPointer { publicKeyBuffer in
            message.withUnsafeBufferPointer { messageBuffer in
                signature.withUnsafeBufferPointer { signatureBuffer in
                    verifyPssFunction(
                        publicKeyBuffer.baseAddress,
                        publicKeyDer.count,
                        publicKeyEncoding.ffiId,
                        suite.messageHashSuite,
                        suite.mgf1HashSuite,
                        suite.saltLength,
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

    private func pkcs1v15Suite(for algorithm: ReallyMeSignatureAlgorithm) -> RsaPkcs1v15Suite? {
        switch algorithm {
        case .rsaPkcs1v15Sha1:
            return RsaPkcs1v15Suite(hashSuite: 1)
        case .rsaPkcs1v15Sha256:
            return RsaPkcs1v15Suite(hashSuite: 2)
        case .rsaPkcs1v15Sha384:
            return RsaPkcs1v15Suite(hashSuite: 3)
        case .rsaPkcs1v15Sha512:
            return RsaPkcs1v15Suite(hashSuite: 4)
        default:
            return nil
        }
    }

    private func pssSuite(for algorithm: ReallyMeSignatureAlgorithm) -> RsaPssSuite? {
        switch algorithm {
        case .rsaPssSha1Mgf1Sha1:
            return RsaPssSuite(messageHashSuite: 1, mgf1HashSuite: 1, saltLength: 20)
        case .rsaPssSha256Mgf1Sha256:
            return RsaPssSuite(messageHashSuite: 2, mgf1HashSuite: 2, saltLength: 32)
        case .rsaPssSha384Mgf1Sha384:
            return RsaPssSuite(messageHashSuite: 3, mgf1HashSuite: 3, saltLength: 48)
        case .rsaPssSha512Mgf1Sha512:
            return RsaPssSuite(messageHashSuite: 4, mgf1HashSuite: 4, saltLength: 64)
        default:
            return nil
        }
    }
}

public extension ReallyMeCrypto {
    static func verify(
        _ algorithm: ReallyMeSignatureAlgorithm,
        signature: [UInt8],
        message: [UInt8],
        publicKeyDer: [UInt8],
        publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws {
        try ReallyMeRustCAbiRsa(library: rustCAbiLibrary).verify(
            algorithm: algorithm,
            signature: signature,
            message: message,
            publicKeyDer: publicKeyDer,
            publicKeyEncoding: publicKeyEncoding
        )
    }
}
