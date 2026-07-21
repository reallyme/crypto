// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let aes128KwKekLength = 16
private let aes192KwKekLength = 24
private let aes256KwKekLength = 32
private let aesKwIntegrityLength = 8
private let aesKwMinKeyDataLength = 16
private let aesKwMinWrappedKeyLength = 24
private let aesKwMaxKeyDataLength = 4096

private typealias AesKwWrapKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

private typealias AesKwUnwrapKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

/// AES-128/192/256-KW operations backed by the ReallyMe Rust C ABI.
///
/// This provider is explicit because loading a Rust dynamic library is a
/// deployment choice. The default Swift facade stays fail-closed unless callers
/// pass a `ReallyMeRustCAbiLibrary` into the provider-aware overloads.
public struct ReallyMeRustCAbiAesKw: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let wrap128KeyFunction: AesKwWrapKeyFunction
    private let unwrap128KeyFunction: AesKwUnwrapKeyFunction
    private let wrap192KeyFunction: AesKwWrapKeyFunction
    private let unwrap192KeyFunction: AesKwUnwrapKeyFunction
    private let wrap256KeyFunction: AesKwWrapKeyFunction
    private let unwrap256KeyFunction: AesKwUnwrapKeyFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        wrap128KeyFunction = try library.loadFunction(
            "rm_crypto_aes128_kw_wrap_key",
            as: AesKwWrapKeyFunction.self
        )
        unwrap128KeyFunction = try library.loadFunction(
            "rm_crypto_aes128_kw_unwrap_key",
            as: AesKwUnwrapKeyFunction.self
        )
        wrap192KeyFunction = try library.loadFunction(
            "rm_crypto_aes192_kw_wrap_key",
            as: AesKwWrapKeyFunction.self
        )
        unwrap192KeyFunction = try library.loadFunction(
            "rm_crypto_aes192_kw_unwrap_key",
            as: AesKwUnwrapKeyFunction.self
        )
        wrap256KeyFunction = try library.loadFunction(
            "rm_crypto_aes256_kw_wrap_key",
            as: AesKwWrapKeyFunction.self
        )
        unwrap256KeyFunction = try library.loadFunction(
            "rm_crypto_aes256_kw_unwrap_key",
            as: AesKwUnwrapKeyFunction.self
        )
    }

    public func wrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        keyToWrap: [UInt8]
    ) throws -> [UInt8] {
        try validateWrappingKey(wrappingKey, algorithm: algorithm)
        try validateKeyData(keyToWrap)

        let outputLength = keyToWrap.count.addingReportingOverflow(aesKwIntegrityLength)
        guard !outputLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }

        return try call(
            wrapFunction(for: algorithm),
            wrappingKey: wrappingKey,
            input: keyToWrap,
            outputLength: outputLength.partialValue
        )
    }

    public func unwrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        wrappedKey: [UInt8]
    ) throws -> [UInt8] {
        try validateWrappingKey(wrappingKey, algorithm: algorithm)
        try validateWrappedKey(wrappedKey)

        let outputLength = wrappedKey.count - aesKwIntegrityLength
        return try call(
            unwrapFunction(for: algorithm),
            wrappingKey: wrappingKey,
            input: wrappedKey,
            outputLength: outputLength
        )
    }

    private func wrapFunction(for algorithm: ReallyMeKeyWrapAlgorithm) -> AesKwWrapKeyFunction {
        switch algorithm {
        case .aes128Kw:
            return wrap128KeyFunction
        case .aes192Kw:
            return wrap192KeyFunction
        case .aes256Kw:
            return wrap256KeyFunction
        }
    }

    private func unwrapFunction(for algorithm: ReallyMeKeyWrapAlgorithm) -> AesKwUnwrapKeyFunction {
        switch algorithm {
        case .aes128Kw:
            return unwrap128KeyFunction
        case .aes192Kw:
            return unwrap192KeyFunction
        case .aes256Kw:
            return unwrap256KeyFunction
        }
    }

    private func call(
        _ function: AesKwWrapKeyFunction,
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

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&output)
            throw error
        }
        guard producedLength == output.count else {
            ReallyMeCryptoMemory.bestEffortClear(&output)
            throw ReallyMeCryptoError.providerFailure
        }
        // Transfer the validated allocation directly to the caller. Creating a
        // second array would briefly duplicate unwrapped key material and add
        // another managed allocation whose lifetime cannot be controlled.
        return output
    }

    private func validateWrappingKey(_ key: [UInt8], algorithm: ReallyMeKeyWrapAlgorithm) throws {
        guard key.count == kekLength(for: algorithm) else {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private func kekLength(for algorithm: ReallyMeKeyWrapAlgorithm) -> Int {
        switch algorithm {
        case .aes128Kw:
            return aes128KwKekLength
        case .aes192Kw:
            return aes192KwKekLength
        case .aes256Kw:
            return aes256KwKekLength
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
        case .aes128Kw, .aes192Kw, .aes256Kw:
            return try ReallyMeRustCAbiAesKw(library: rustCAbiLibrary)
                .wrapKey(algorithm, wrappingKey: wrappingKey, keyToWrap: keyToWrap)
        }
    }

    static func unwrapKey(
        _ algorithm: ReallyMeKeyWrapAlgorithm,
        wrappingKey: [UInt8],
        wrappedKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes128Kw, .aes192Kw, .aes256Kw:
            return try ReallyMeRustCAbiAesKw(library: rustCAbiLibrary)
                .unwrapKey(algorithm, wrappingKey: wrappingKey, wrappedKey: wrappedKey)
        }
    }
}
