// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let hpkeAeadTagLength = 16
private let hpkeEncapsulatedKeyMaxLength = 65

private struct RustCAbiHpkeSuite {
    let ffiId: UInt32
    let publicKeyLength: Int
    let privateKeyLength: Int
}

private typealias HpkeSealBaseFunction = @convention(c) (
    UInt32,
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
    UnsafeMutablePointer<Int>?,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

private typealias HpkeOpenBaseFunction = @convention(c) (
    UInt32,
    UnsafePointer<UInt8>?,
    Int,
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

/// HPKE Base-mode operations backed by the ReallyMe Rust C ABI.
///
/// CryptoKit HPKE is not available on the package's iOS 16 floor. The Rust ABI
/// route keeps the public SDK usable on that floor while preserving an explicit
/// provider boundary.
public struct ReallyMeRustCAbiHpke: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let sealBaseFunction: HpkeSealBaseFunction
    private let openBaseFunction: HpkeOpenBaseFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        sealBaseFunction = try library.loadFunction(
            "rm_crypto_hpke_seal_base",
            as: HpkeSealBaseFunction.self
        )
        openBaseFunction = try library.loadFunction(
            "rm_crypto_hpke_open_base",
            as: HpkeOpenBaseFunction.self
        )
    }

    public func sealBase(
        suite: ReallyMeHpkeSuite,
        recipientPublicKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8]
    ) throws -> ReallyMeHpkeSealedMessage {
        let suite = try rustSuite(for: suite)
        guard recipientPublicKey.count == suite.publicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let ciphertextLength = plaintext.count.addingReportingOverflow(hpkeAeadTagLength)
        guard !ciphertextLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }

        var encapsulatedKey = [UInt8](repeating: 0, count: hpkeEncapsulatedKeyMaxLength)
        var encapsulatedKeyLength = 0
        var ciphertext = [UInt8](repeating: 0, count: ciphertextLength.partialValue)
        var producedCiphertextLength = 0
        let encapsulatedKeyCapacity = encapsulatedKey.count
        let ciphertextCapacity = ciphertext.count

        let status = recipientPublicKey.withUnsafeBufferPointer { publicKeyBuffer in
            info.withUnsafeBufferPointer { infoBuffer in
                aad.withUnsafeBufferPointer { aadBuffer in
                    plaintext.withUnsafeBufferPointer { plaintextBuffer in
                        encapsulatedKey.withUnsafeMutableBufferPointer { encapsulatedKeyBuffer in
                            ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
                                sealBaseFunction(
                                    suite.ffiId,
                                    publicKeyBuffer.baseAddress,
                                    recipientPublicKey.count,
                                    infoBuffer.baseAddress,
                                    info.count,
                                    aadBuffer.baseAddress,
                                    aad.count,
                                    plaintextBuffer.baseAddress,
                                    plaintext.count,
                                    encapsulatedKeyBuffer.baseAddress,
                                    encapsulatedKeyCapacity,
                                    &encapsulatedKeyLength,
                                    ciphertextBuffer.baseAddress,
                                    ciphertextCapacity,
                                    &producedCiphertextLength
                                )
                            }
                        }
                    }
                }
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        guard encapsulatedKeyLength <= encapsulatedKey.count,
              producedCiphertextLength <= ciphertext.count
        else {
            throw ReallyMeCryptoError.providerFailure
        }
        return ReallyMeHpkeSealedMessage(
            encapsulatedKey: Array(encapsulatedKey.prefix(encapsulatedKeyLength)),
            ciphertext: Array(ciphertext.prefix(producedCiphertextLength))
        )
    }

    public func openBase(
        suite: ReallyMeHpkeSuite,
        recipientSecretKey: [UInt8],
        encapsulatedKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        ciphertext: [UInt8]
    ) throws -> [UInt8] {
        let suite = try rustSuite(for: suite)
        guard recipientSecretKey.count == suite.privateKeyLength,
              encapsulatedKey.count == suite.publicKeyLength,
              ciphertext.count >= hpkeAeadTagLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let plaintextLengthLimit = ciphertext.count.subtractingReportingOverflow(hpkeAeadTagLength)
        guard !plaintextLengthLimit.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }
        var plaintext = [UInt8](repeating: 0, count: plaintextLengthLimit.partialValue)
        var plaintextLength = 0
        let plaintextCapacity = plaintext.count
        let status = encapsulatedKey.withUnsafeBufferPointer { encapsulatedKeyBuffer in
            recipientSecretKey.withUnsafeBufferPointer { secretKeyBuffer in
                info.withUnsafeBufferPointer { infoBuffer in
                    aad.withUnsafeBufferPointer { aadBuffer in
                        ciphertext.withUnsafeBufferPointer { ciphertextBuffer in
                            plaintext.withUnsafeMutableBufferPointer { plaintextBuffer in
                                openBaseFunction(
                                    suite.ffiId,
                                    encapsulatedKeyBuffer.baseAddress,
                                    encapsulatedKey.count,
                                    secretKeyBuffer.baseAddress,
                                    recipientSecretKey.count,
                                    infoBuffer.baseAddress,
                                    info.count,
                                    aadBuffer.baseAddress,
                                    aad.count,
                                    ciphertextBuffer.baseAddress,
                                    ciphertext.count,
                                    plaintextBuffer.baseAddress,
                                    plaintextCapacity,
                                    &plaintextLength
                                )
                            }
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
        guard plaintextLength <= plaintext.count else {
            ReallyMeCryptoMemory.bestEffortClear(&plaintext)
            throw ReallyMeCryptoError.providerFailure
        }
        let output = Array(plaintext.prefix(plaintextLength))
        ReallyMeCryptoMemory.bestEffortClear(&plaintext)
        return output
    }

    private func rustSuite(for suite: ReallyMeHpkeSuite) throws -> RustCAbiHpkeSuite {
        switch suite {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
            return RustCAbiHpkeSuite(ffiId: 1, publicKeyLength: 65, privateKeyLength: 32)
        case .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
            return RustCAbiHpkeSuite(ffiId: 2, publicKeyLength: 32, privateKeyLength: 32)
        }
    }
}

public extension ReallyMeCrypto {
    static func sealHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientPublicKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        plaintext: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeHpkeSealedMessage {
        try ReallyMeRustCAbiHpke(library: rustCAbiLibrary).sealBase(
            suite: suite,
            recipientPublicKey: recipientPublicKey,
            info: info,
            aad: aad,
            plaintext: plaintext
        )
    }

    static func openHpke(
        _ suite: ReallyMeHpkeSuite,
        recipientSecretKey: [UInt8],
        encapsulatedKey: [UInt8],
        info: [UInt8],
        aad: [UInt8],
        ciphertext: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        try ReallyMeRustCAbiHpke(library: rustCAbiLibrary).openBase(
            suite: suite,
            recipientSecretKey: recipientSecretKey,
            encapsulatedKey: encapsulatedKey,
            info: info,
            aad: aad,
            ciphertext: ciphertext
        )
    }
}
