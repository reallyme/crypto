// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiAes192GcmKeyLength = 24
private let rustCAbiAeadKeyLength = 32
private let rustCAbiAeadNonceLength = 12
private let rustCAbiXChaCha20Poly1305NonceLength = 24
private let rustCAbiAeadTagLength = 16

private typealias RustCAbiAeadFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

/// AEAD provider backed by the ReallyMe Rust C ABI.
///
/// Swift keeps AES-GCM and RFC 8439 ChaCha20-Poly1305 on CryptoKit. GCM-SIV
/// and XChaCha are Rust-only because Apple does not expose first-party APIs
/// with those exact semantics.
public struct ReallyMeRustCAbiAead: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let aes192GcmSealFunction: RustCAbiAeadFunction
    private let aes192GcmOpenFunction: RustCAbiAeadFunction
    private let aes256GcmSivSealFunction: RustCAbiAeadFunction
    private let aes256GcmSivOpenFunction: RustCAbiAeadFunction
    private let xchacha20Poly1305SealFunction: RustCAbiAeadFunction
    private let xchacha20Poly1305OpenFunction: RustCAbiAeadFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        aes192GcmSealFunction = try library.loadFunction(
            "rm_crypto_aes192_gcm_encrypt",
            as: RustCAbiAeadFunction.self
        )
        aes192GcmOpenFunction = try library.loadFunction(
            "rm_crypto_aes192_gcm_decrypt",
            as: RustCAbiAeadFunction.self
        )
        aes256GcmSivSealFunction = try library.loadFunction(
            "rm_crypto_aes256_gcm_siv_encrypt",
            as: RustCAbiAeadFunction.self
        )
        aes256GcmSivOpenFunction = try library.loadFunction(
            "rm_crypto_aes256_gcm_siv_decrypt",
            as: RustCAbiAeadFunction.self
        )
        xchacha20Poly1305SealFunction = try library.loadFunction(
            "rm_crypto_xchacha20_poly1305_encrypt",
            as: RustCAbiAeadFunction.self
        )
        xchacha20Poly1305OpenFunction = try library.loadFunction(
            "rm_crypto_xchacha20_poly1305_decrypt",
            as: RustCAbiAeadFunction.self
        )
    }

    public func sealAes192Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: rustCAbiAes192GcmKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiAeadNonceLength,
            aad: aad,
            plaintext: plaintext,
            function: aes192GcmSealFunction
        )
    }

    public func openAes192Gcm(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: rustCAbiAes192GcmKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiAeadNonceLength,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag,
            function: aes192GcmOpenFunction
        )
    }

    public func sealAes256GcmSiv(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: rustCAbiAeadKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiAeadNonceLength,
            aad: aad,
            plaintext: plaintext,
            function: aes256GcmSivSealFunction
        )
    }

    public func openAes256GcmSiv(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: rustCAbiAeadKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiAeadNonceLength,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag,
            function: aes256GcmSivOpenFunction
        )
    }

    public func sealXChaCha20Poly1305(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> [UInt8] {
        try seal(
            key: key,
            expectedKeyLength: rustCAbiAeadKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiXChaCha20Poly1305NonceLength,
            aad: aad,
            plaintext: plaintext,
            function: xchacha20Poly1305SealFunction
        )
    }

    public func openXChaCha20Poly1305(
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8]
    ) throws -> [UInt8] {
        try open(
            key: key,
            expectedKeyLength: rustCAbiAeadKeyLength,
            nonce: nonce,
            expectedNonceLength: rustCAbiXChaCha20Poly1305NonceLength,
            aad: aad,
            ciphertextWithTag: ciphertextWithTag,
            function: xchacha20Poly1305OpenFunction
        )
    }

    private func seal(
        key: [UInt8],
        expectedKeyLength: Int,
        nonce: [UInt8],
        expectedNonceLength: Int,
        aad: [UInt8],
        plaintext: [UInt8],
        function: RustCAbiAeadFunction
    ) throws -> [UInt8] {
        try validate(
            key: key,
            expectedKeyLength: expectedKeyLength,
            nonce: nonce,
            expectedNonceLength: expectedNonceLength
        )
        let outputLength = plaintext.count.addingReportingOverflow(rustCAbiAeadTagLength)
        guard !outputLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }
        var ciphertext = [UInt8](repeating: 0, count: outputLength.partialValue)
        var producedLength = 0
        let capacity = ciphertext.count
        let status = key.withUnsafeBufferPointer { keyBuffer in
            nonce.withUnsafeBufferPointer { nonceBuffer in
                aad.withUnsafeBufferPointer { aadBuffer in
                    plaintext.withUnsafeBufferPointer { plaintextBuffer in
                        ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
                            function(
                                keyBuffer.baseAddress,
                                key.count,
                                nonceBuffer.baseAddress,
                                nonce.count,
                                aadBuffer.baseAddress,
                                aad.count,
                                plaintextBuffer.baseAddress,
                                plaintext.count,
                                ciphertextBuffer.baseAddress,
                                capacity,
                                &producedLength
                            )
                        }
                    }
                }
            }
        }
        try ReallyMeRustCAbiStatus.throwIfError(status)
        guard producedLength <= ciphertext.count else {
            throw ReallyMeCryptoError.providerFailure
        }
        return Array(ciphertext.prefix(producedLength))
    }

    private func open(
        key: [UInt8],
        expectedKeyLength: Int,
        nonce: [UInt8],
        expectedNonceLength: Int,
        aad: [UInt8],
        ciphertextWithTag: [UInt8],
        function: RustCAbiAeadFunction
    ) throws -> [UInt8] {
        try validate(
            key: key,
            expectedKeyLength: expectedKeyLength,
            nonce: nonce,
            expectedNonceLength: expectedNonceLength
        )
        guard ciphertextWithTag.count >= rustCAbiAeadTagLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let outputLength = ciphertextWithTag.count - rustCAbiAeadTagLength
        var plaintext = [UInt8](repeating: 0, count: outputLength)
        var producedLength = 0
        let capacity = plaintext.count
        let status = key.withUnsafeBufferPointer { keyBuffer in
            nonce.withUnsafeBufferPointer { nonceBuffer in
                aad.withUnsafeBufferPointer { aadBuffer in
                    ciphertextWithTag.withUnsafeBufferPointer { ciphertextBuffer in
                        plaintext.withUnsafeMutableBufferPointer { plaintextBuffer in
                            function(
                                keyBuffer.baseAddress,
                                key.count,
                                nonceBuffer.baseAddress,
                                nonce.count,
                                aadBuffer.baseAddress,
                                aad.count,
                                ciphertextBuffer.baseAddress,
                                ciphertextWithTag.count,
                                plaintextBuffer.baseAddress,
                                capacity,
                                &producedLength
                            )
                        }
                    }
                }
            }
        }
        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&plaintext)
            throw error
        }
        guard producedLength <= plaintext.count else {
            ReallyMeCryptoMemory.bestEffortClear(&plaintext)
            throw ReallyMeCryptoError.providerFailure
        }
        let output = Array(plaintext.prefix(producedLength))
        ReallyMeCryptoMemory.bestEffortClear(&plaintext)
        return output
    }

    private func validate(
        key: [UInt8],
        expectedKeyLength: Int,
        nonce: [UInt8],
        expectedNonceLength: Int
    ) throws {
        guard key.count == expectedKeyLength,
              nonce.count == expectedNonceLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}

public extension ReallyMeCrypto {
    static func seal(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes128Gcm:
            return try ReallyMeAesGcm.sealAes128Gcm(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes192Gcm:
            return try ReallyMeAesGcm.sealAes192Gcm(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes256Gcm:
            return try ReallyMeAesGcm.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .chacha20Poly1305:
            return try ReallyMeChaCha20Poly1305.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .aes256GcmSiv:
            return try ReallyMeRustCAbiAead(library: rustCAbiLibrary)
                .sealAes256GcmSiv(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        case .xchacha20Poly1305:
            return try ReallyMeRustCAbiAead(library: rustCAbiLibrary)
                .sealXChaCha20Poly1305(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        }
    }

    static func open(
        _ algorithm: ReallyMeAeadAlgorithm,
        key: [UInt8],
        nonce: [UInt8],
        aad: [UInt8],
        ciphertextWithTag: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .aes128Gcm:
            return try ReallyMeAesGcm.openAes128Gcm(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes192Gcm:
            return try ReallyMeAesGcm.openAes192Gcm(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes256Gcm:
            return try ReallyMeAesGcm.open(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .chacha20Poly1305:
            return try ReallyMeChaCha20Poly1305.open(
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertextWithTag
            )
        case .aes256GcmSiv:
            return try ReallyMeRustCAbiAead(library: rustCAbiLibrary)
                .openAes256GcmSiv(key: key, nonce: nonce, aad: aad, ciphertextWithTag: ciphertextWithTag)
        case .xchacha20Poly1305:
            return try ReallyMeRustCAbiAead(library: rustCAbiLibrary)
                .openXChaCha20Poly1305(key: key, nonce: nonce, aad: aad, ciphertextWithTag: ciphertextWithTag)
        }
    }
}
