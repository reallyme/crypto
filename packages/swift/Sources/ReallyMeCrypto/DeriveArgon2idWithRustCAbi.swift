// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiArgon2idDerivedKeyLength = 32
private let rustCAbiArgon2idSaltMinLength = 16
private let rustCAbiArgon2idSaltMaxLength = 32

private typealias Argon2idDeriveKeyFunction = @convention(c) (
    UInt32,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

/// Argon2id key derivation backed by the ReallyMe Rust C ABI.
///
/// Argon2id uses versioned fixed-cost profiles in Rust rather than arbitrary
/// caller-supplied iteration/output parameters. The Swift facade preserves
/// that contract so package callers do not accidentally weaken unlock costs.
public struct ReallyMeRustCAbiArgon2id: Sendable {
    private let deriveKeyFunction: Argon2idDeriveKeyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        deriveKeyFunction = try library.loadFunction(
            "rm_crypto_argon2id_derive_key",
            as: Argon2idDeriveKeyFunction.self
        )
    }

    public func deriveKey(kdfVersion: UInt32, secret: [UInt8], salt: [UInt8]) throws -> [UInt8] {
        guard !secret.isEmpty,
              (rustCAbiArgon2idSaltMinLength...rustCAbiArgon2idSaltMaxLength).contains(salt.count)
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var derivedKey = [UInt8](repeating: 0, count: rustCAbiArgon2idDerivedKeyLength)
        let outputCapacity = derivedKey.count
        let status = secret.withUnsafeBufferPointer { secretBuffer in
            salt.withUnsafeBufferPointer { saltBuffer in
                derivedKey.withUnsafeMutableBufferPointer { outputBuffer in
                    deriveKeyFunction(
                        kdfVersion,
                        secretBuffer.baseAddress,
                        secret.count,
                        saltBuffer.baseAddress,
                        salt.count,
                        outputBuffer.baseAddress,
                        outputCapacity
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return derivedKey
    }
}

public extension ReallyMeCrypto {
    static func deriveArgon2idKey(
        kdfVersion: UInt32,
        secret: [UInt8],
        salt: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        try ReallyMeRustCAbiArgon2id(library: rustCAbiLibrary)
            .deriveKey(kdfVersion: kdfVersion, secret: secret, salt: salt)
    }
}
