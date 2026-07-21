// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiKmac256MinKeyLength = 32
private let rustCAbiKmac256MaxKeyLength = 4_096
private let rustCAbiKmac256MaxContextLength = 65_536
private let rustCAbiKmac256MaxCustomizationLength = 4_096
private let rustCAbiKmac256MinOutputLength = 1
private let rustCAbiKmac256MaxOutputLength = 65_536

private typealias Kmac256DeriveFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

/// KMAC256 key derivation backed by the ReallyMe Rust C ABI.
///
/// KMAC256 is exposed as an explicit Rust-backed KDF because Apple platforms do
/// not provide a CryptoKit KMAC primitive. The provider keeps its context and
/// customization strings separate so protocol layers can serialize their
/// domains deterministically before derivation.
public struct ReallyMeRustCAbiKmac: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let deriveFunction: Kmac256DeriveFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        deriveFunction = try library.loadFunction(
            "rm_crypto_kmac256_derive",
            as: Kmac256DeriveFunction.self
        )
    }

    public func deriveKmac256(
        key: [UInt8],
        context: [UInt8],
        customization: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        guard (rustCAbiKmac256MinKeyLength...rustCAbiKmac256MaxKeyLength).contains(key.count),
              context.count <= rustCAbiKmac256MaxContextLength,
              customization.count <= rustCAbiKmac256MaxCustomizationLength,
              (rustCAbiKmac256MinOutputLength...rustCAbiKmac256MaxOutputLength).contains(outputLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var output = [UInt8](repeating: 0, count: outputLength)
        let outputCapacity = output.count
        let status = key.withUnsafeBufferPointer { keyBuffer in
            context.withUnsafeBufferPointer { contextBuffer in
                customization.withUnsafeBufferPointer { customizationBuffer in
                    output.withUnsafeMutableBufferPointer { outputBuffer in
                        deriveFunction(
                            keyBuffer.baseAddress,
                            key.count,
                            contextBuffer.baseAddress,
                            context.count,
                            customizationBuffer.baseAddress,
                            customization.count,
                            outputBuffer.baseAddress,
                            outputCapacity
                        )
                    }
                }
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&output)
            throw error
        }
        return output
    }
}

public extension ReallyMeCrypto {
    static func deriveKmac256(
        _ algorithm: ReallyMeKdfAlgorithm,
        key: [UInt8],
        context: [UInt8],
        customization: [UInt8],
        outputLength: Int,
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .kmac256:
            return try ReallyMeRustCAbiKmac(library: rustCAbiLibrary).deriveKmac256(
                key: key,
                context: context,
                customization: customization,
                outputLength: outputLength
            )
        case .argon2id, .hkdfSha256, .hkdfSha384, .pbkdf2HmacSha256, .pbkdf2HmacSha512, .jwaConcatKdfSha256:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }
}
