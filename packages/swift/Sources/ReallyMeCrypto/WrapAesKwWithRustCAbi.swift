// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let aes256KwKekLength = 32
private let aesKwIntegrityLength = 8
private let aesKwMinKeyDataLength = 16
private let aesKwMinWrappedKeyLength = 24
private let aesKwMaxKeyDataLength = 4096

private typealias Aes256KwWrapKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

private typealias Aes256KwUnwrapKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

/// AES-256-KW operations backed by the ReallyMe Rust C ABI.
///
/// This provider is explicit because loading a Rust dynamic library is a
/// deployment choice. The default Swift facade stays fail-closed unless callers
/// pass a `ReallyMeRustCAbiLibrary` into the provider-aware overloads.
public struct ReallyMeRustCAbiAesKw: Sendable {
    private let wrapKeyFunction: Aes256KwWrapKeyFunction
    private let unwrapKeyFunction: Aes256KwUnwrapKeyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        wrapKeyFunction = try library.loadFunction(
            "rm_crypto_aes256_kw_wrap_key",
            as: Aes256KwWrapKeyFunction.self
        )
        unwrapKeyFunction = try library.loadFunction(
            "rm_crypto_aes256_kw_unwrap_key",
            as: Aes256KwUnwrapKeyFunction.self
        )
    }

    public func wrapKey(wrappingKey: [UInt8], keyToWrap: [UInt8]) throws -> [UInt8] {
        try validateWrappingKey(wrappingKey)
        try validateKeyData(keyToWrap)

        let outputLength = keyToWrap.count.addingReportingOverflow(aesKwIntegrityLength)
        guard !outputLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }

        return try call(
            wrapKeyFunction,
            wrappingKey: wrappingKey,
            input: keyToWrap,
            outputLength: outputLength.partialValue
        )
    }

    public func unwrapKey(wrappingKey: [UInt8], wrappedKey: [UInt8]) throws -> [UInt8] {
        try validateWrappingKey(wrappingKey)
        try validateWrappedKey(wrappedKey)

        let outputLength = wrappedKey.count - aesKwIntegrityLength
        return try call(
            unwrapKeyFunction,
            wrappingKey: wrappingKey,
            input: wrappedKey,
            outputLength: outputLength
        )
    }

    private func call(
        _ function: Aes256KwWrapKeyFunction,
        wrappingKey: [UInt8],
        input: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: outputLength)
        let outputCapacity = output.count
        var producedLength = 0
        let status = wrappingKey.withUnsafeBufferPointer { keyBuffer in
            input.withUnsafeBufferPointer { inputBuffer in
                output.withUnsafeMutableBufferPointer { outputBuffer in
                    function(
                        keyBuffer.baseAddress,
                        wrappingKey.count,
                        inputBuffer.baseAddress,
                        input.count,
                        outputBuffer.baseAddress,
                        outputCapacity,
                        &producedLength
                    )
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        guard producedLength <= output.count else {
            throw ReallyMeCryptoError.providerFailure
        }
        return Array(output.prefix(producedLength))
    }

    private func validateWrappingKey(_ key: [UInt8]) throws {
        guard key.count == aes256KwKekLength else {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private func validateKeyData(_ keyData: [UInt8]) throws {
        guard keyData.count >= aesKwMinKeyDataLength,
              keyData.count <= aesKwMaxKeyDataLength,
              keyData.count.isMultiple(of: aesKwIntegrityLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private func validateWrappedKey(_ wrappedKey: [UInt8]) throws {
        guard wrappedKey.count >= aesKwMinWrappedKeyLength,
              wrappedKey.count <= aesKwMaxKeyDataLength + aesKwIntegrityLength,
              wrappedKey.count.isMultiple(of: aesKwIntegrityLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}

public extension ReallyMeCrypto {
    static func wrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        keyToWrap: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Kw:
            return try ReallyMeRustCAbiAesKw(library: rustCAbiLibrary)
                .wrapKey(wrappingKey: wrappingKey, keyToWrap: keyToWrap)
        }
    }

    static func unwrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        wrappedKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes256Kw:
            return try ReallyMeRustCAbiAesKw(library: rustCAbiLibrary)
                .unwrapKey(wrappingKey: wrappingKey, wrappedKey: wrappedKey)
        }
    }
}
