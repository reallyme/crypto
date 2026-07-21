// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiXWing768PublicKeyLength = 1_216
private let rustCAbiXWing768CiphertextLength = 1_120
private let rustCAbiXWingSecretKeyLength = 32
private let rustCAbiXWingSharedSecretLength = 32

private typealias XWingGenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias XWingDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias XWingEncapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias XWingDecapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private struct RustCAbiXWingSuite {
    let publicKeyLength: Int
    let ciphertextLength: Int
    let generateKeyPairFunction: XWingGenerateKeyPairFunction
    let deriveKeyPairFunction: XWingDeriveKeyPairFunction
    let encapsulateFunction: XWingEncapsulateFunction
    let decapsulateFunction: XWingDecapsulateFunction
}

/// X-Wing hybrid KEM operations backed by the ReallyMe Rust C ABI.
///
/// X-Wing combines X25519 with ML-KEM. The Swift package routes through the
/// Rust implementation so the combiner and serialization stay identical across
/// Rust, Swift, Kotlin, and WASM package lanes.
public struct ReallyMeRustCAbiXWing: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let xWing768GenerateKeyPairFunction: XWingGenerateKeyPairFunction
    private let xWing768DeriveKeyPairFunction: XWingDeriveKeyPairFunction
    private let xWing768EncapsulateFunction: XWingEncapsulateFunction
    private let xWing768DecapsulateFunction: XWingDecapsulateFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        xWing768GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_x_wing_768_generate_keypair",
            as: XWingGenerateKeyPairFunction.self
        )
        xWing768DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_x_wing_768_generate_keypair_derand",
            as: XWingDeriveKeyPairFunction.self
        )
        xWing768EncapsulateFunction = try library.loadFunction(
            "rm_crypto_x_wing_768_encapsulate",
            as: XWingEncapsulateFunction.self
        )
        xWing768DecapsulateFunction = try library.loadFunction(
            "rm_crypto_x_wing_768_decapsulate",
            as: XWingDecapsulateFunction.self
        )
    }

    public func generateKeyPair(_ algorithm: ReallyMeKemAlgorithm) throws -> ReallyMeKemKeyPair {
        let suite = try rustSuite(for: algorithm)
        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiXWingSecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = secretKey.count
        let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
            secretKey.withUnsafeMutableBufferPointer { secretBuffer in
                suite.generateKeyPairFunction(
                    publicBuffer.baseAddress,
                    publicKeyCapacity,
                    secretBuffer.baseAddress,
                    secretKeyCapacity
                )
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&secretKey)
            throw error
        }
        return ReallyMeKemKeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func deriveKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        secretKey: [UInt8]
    ) throws -> ReallyMeKemKeyPair {
        let suite = try rustSuite(for: algorithm)
        guard secretKey.count == rustCAbiXWingSecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        let publicKeyCapacity = publicKey.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                suite.deriveKeyPairFunction(
                    secretBuffer.baseAddress,
                    secretKey.count,
                    publicBuffer.baseAddress,
                    publicKeyCapacity
                )
            }
        }

        try ReallyMeRustCAbiStatus.throwIfError(status)
        return ReallyMeKemKeyPair(publicKey: publicKey, secretKey: secretKey)
    }

    public func encapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        publicKey: [UInt8]
    ) throws -> ReallyMeKemEncapsulation {
        let suite = try rustSuite(for: algorithm)
        guard publicKey.count == suite.publicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var ciphertext = [UInt8](repeating: 0, count: suite.ciphertextLength)
        var sharedSecret = [UInt8](repeating: 0, count: rustCAbiXWingSharedSecretLength)
        let ciphertextCapacity = ciphertext.count
        let sharedSecretCapacity = sharedSecret.count
        let status = publicKey.withUnsafeBufferPointer { publicBuffer in
            ciphertext.withUnsafeMutableBufferPointer { ciphertextBuffer in
                sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
                    suite.encapsulateFunction(
                        publicBuffer.baseAddress,
                        publicKey.count,
                        ciphertextBuffer.baseAddress,
                        ciphertextCapacity,
                        sharedSecretBuffer.baseAddress,
                        sharedSecretCapacity
                    )
                }
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&sharedSecret)
            throw error
        }
        return ReallyMeKemEncapsulation(sharedSecret: sharedSecret, ciphertext: ciphertext)
    }

    public func decapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        ciphertext: [UInt8],
        secretKey: [UInt8]
    ) throws -> [UInt8] {
        let suite = try rustSuite(for: algorithm)
        guard ciphertext.count == suite.ciphertextLength,
              secretKey.count == rustCAbiXWingSecretKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var sharedSecret = [UInt8](repeating: 0, count: rustCAbiXWingSharedSecretLength)
        let sharedSecretCapacity = sharedSecret.count
        let status = ciphertext.withUnsafeBufferPointer { ciphertextBuffer in
            secretKey.withUnsafeBufferPointer { secretBuffer in
                sharedSecret.withUnsafeMutableBufferPointer { sharedSecretBuffer in
                    suite.decapsulateFunction(
                        ciphertextBuffer.baseAddress,
                        ciphertext.count,
                        secretBuffer.baseAddress,
                        secretKey.count,
                        sharedSecretBuffer.baseAddress,
                        sharedSecretCapacity
                    )
                }
            }
        }

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&sharedSecret)
            throw error
        }
        return sharedSecret
    }

    private func rustSuite(for algorithm: ReallyMeKemAlgorithm) throws -> RustCAbiXWingSuite {
        switch algorithm {
        case .xWing768:
            return RustCAbiXWingSuite(
                publicKeyLength: rustCAbiXWing768PublicKeyLength,
                ciphertextLength: rustCAbiXWing768CiphertextLength,
                generateKeyPairFunction: xWing768GenerateKeyPairFunction,
                deriveKeyPairFunction: xWing768DeriveKeyPairFunction,
                encapsulateFunction: xWing768EncapsulateFunction,
                decapsulateFunction: xWing768DecapsulateFunction
            )
        case .mlKem512, .mlKem768, .mlKem1024:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }
}

public extension ReallyMeCrypto {
    static func generateKemKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeKemKeyPair {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024:
            return try ReallyMeRustCAbiMlKem(library: rustCAbiLibrary).generateKeyPair(algorithm)
        case .xWing768:
            return try ReallyMeRustCAbiXWing(library: rustCAbiLibrary).generateKeyPair(algorithm)
        }
    }

    static func deriveXWingKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeKemKeyPair {
        try ReallyMeRustCAbiXWing(library: rustCAbiLibrary)
            .deriveKeyPair(algorithm, secretKey: secretKey)
    }

    static func deriveMlKemKeyPair(
        _ algorithm: ReallyMeKemAlgorithm,
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeKemKeyPair {
        try ReallyMeRustCAbiMlKem(library: rustCAbiLibrary)
            .deriveKeyPair(algorithm, secretKey: secretKey)
    }

    static func encapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        publicKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> ReallyMeKemEncapsulation {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024:
            return try ReallyMeRustCAbiMlKem(library: rustCAbiLibrary)
                .encapsulate(algorithm, publicKey: publicKey)
        case .xWing768:
            return try ReallyMeRustCAbiXWing(library: rustCAbiLibrary)
                .encapsulate(algorithm, publicKey: publicKey)
        }
    }

    static func decapsulate(
        _ algorithm: ReallyMeKemAlgorithm,
        ciphertext: [UInt8],
        secretKey: [UInt8],
        rustCAbiLibrary: ReallyMeRustCAbiLibrary
    ) throws -> [UInt8] {
        switch algorithm {
        case .mlKem512, .mlKem768, .mlKem1024:
            return try ReallyMeRustCAbiMlKem(library: rustCAbiLibrary)
                .decapsulate(algorithm, ciphertext: ciphertext, secretKey: secretKey)
        case .xWing768:
            return try ReallyMeRustCAbiXWing(library: rustCAbiLibrary)
                .decapsulate(algorithm, ciphertext: ciphertext, secretKey: secretKey)
        }
    }
}
