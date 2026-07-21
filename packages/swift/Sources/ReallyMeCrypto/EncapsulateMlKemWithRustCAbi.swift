// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let rustCAbiMlKem512PublicKeyLength = 800
private let rustCAbiMlKem512CiphertextLength = 768
private let rustCAbiMlKem768PublicKeyLength = 1_184
private let rustCAbiMlKem768CiphertextLength = 1_088
private let rustCAbiMlKem1024PublicKeyLength = 1_568
private let rustCAbiMlKem1024CiphertextLength = 1_568
private let rustCAbiMlKemSecretKeyLength = 64
private let rustCAbiMlKemSharedSecretLength = 32

private typealias MlKemGenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlKemDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlKemEncapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private typealias MlKemDecapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
) -> Int32

private struct RustCAbiMlKemSuite {
    let publicKeyLength: Int
    let ciphertextLength: Int
    let generateKeyPairFunction: MlKemGenerateKeyPairFunction
    let deriveKeyPairFunction: MlKemDeriveKeyPairFunction
    let encapsulateFunction: MlKemEncapsulateFunction
    let decapsulateFunction: MlKemDecapsulateFunction
}

/// ML-KEM operations backed by the ReallyMe Rust C ABI.
///
/// The repository stores ML-KEM secret keys in the compact FIPS 203 seed form
/// used by the Rust primitives. Routing Swift package calls through this ABI
/// keeps that wire contract byte-identical across language lanes.
public struct ReallyMeRustCAbiMlKem: Sendable {
    private let library: ReallyMeRustCAbiLibrary
    private let mlKem512GenerateKeyPairFunction: MlKemGenerateKeyPairFunction
    private let mlKem512DeriveKeyPairFunction: MlKemDeriveKeyPairFunction
    private let mlKem512EncapsulateFunction: MlKemEncapsulateFunction
    private let mlKem512DecapsulateFunction: MlKemDecapsulateFunction
    private let mlKem768GenerateKeyPairFunction: MlKemGenerateKeyPairFunction
    private let mlKem768DeriveKeyPairFunction: MlKemDeriveKeyPairFunction
    private let mlKem768EncapsulateFunction: MlKemEncapsulateFunction
    private let mlKem768DecapsulateFunction: MlKemDecapsulateFunction
    private let mlKem1024GenerateKeyPairFunction: MlKemGenerateKeyPairFunction
    private let mlKem1024DeriveKeyPairFunction: MlKemDeriveKeyPairFunction
    private let mlKem1024EncapsulateFunction: MlKemEncapsulateFunction
    private let mlKem1024DecapsulateFunction: MlKemDecapsulateFunction

    public init(library: ReallyMeRustCAbiLibrary) throws {
        self.library = library
        mlKem512GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_512_generate_keypair",
            as: MlKemGenerateKeyPairFunction.self
        )
        mlKem512DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_512_generate_keypair_from_seed",
            as: MlKemDeriveKeyPairFunction.self
        )
        mlKem512EncapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_512_encapsulate",
            as: MlKemEncapsulateFunction.self
        )
        mlKem512DecapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_512_decapsulate",
            as: MlKemDecapsulateFunction.self
        )
        mlKem768GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_768_generate_keypair",
            as: MlKemGenerateKeyPairFunction.self
        )
        mlKem768DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_768_generate_keypair_from_seed",
            as: MlKemDeriveKeyPairFunction.self
        )
        mlKem768EncapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_768_encapsulate",
            as: MlKemEncapsulateFunction.self
        )
        mlKem768DecapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_768_decapsulate",
            as: MlKemDecapsulateFunction.self
        )
        mlKem1024GenerateKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_1024_generate_keypair",
            as: MlKemGenerateKeyPairFunction.self
        )
        mlKem1024DeriveKeyPairFunction = try library.loadFunction(
            "rm_crypto_ml_kem_1024_generate_keypair_from_seed",
            as: MlKemDeriveKeyPairFunction.self
        )
        mlKem1024EncapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_1024_encapsulate",
            as: MlKemEncapsulateFunction.self
        )
        mlKem1024DecapsulateFunction = try library.loadFunction(
            "rm_crypto_ml_kem_1024_decapsulate",
            as: MlKemDecapsulateFunction.self
        )
    }

    public func generateKeyPair(_ algorithm: ReallyMeKemAlgorithm) throws -> ReallyMeKemKeyPair {
        let suite = try rustSuite(for: algorithm)
        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: rustCAbiMlKemSecretKeyLength)
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

    public func deriveKeyPair(_ algorithm: ReallyMeKemAlgorithm, secretKey: [UInt8]) throws -> ReallyMeKemKeyPair {
        let suite = try rustSuite(for: algorithm)
        guard secretKey.count == rustCAbiMlKemSecretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = [UInt8](repeating: 0, count: suite.publicKeyLength)
        var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiMlKemSecretKeyLength)
        let publicKeyCapacity = publicKey.count
        let secretKeyCapacity = returnedSecretKey.count
        let status = secretKey.withUnsafeBufferPointer { secretBuffer in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer in
                returnedSecretKey.withUnsafeMutableBufferPointer { returnedSecretBuffer in
                    suite.deriveKeyPairFunction(
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

        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&returnedSecretKey)
            throw error
        }
        return ReallyMeKemKeyPair(publicKey: publicKey, secretKey: returnedSecretKey)
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
        var sharedSecret = [UInt8](repeating: 0, count: rustCAbiMlKemSharedSecretLength)
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
              secretKey.count == rustCAbiMlKemSecretKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        var sharedSecret = [UInt8](repeating: 0, count: rustCAbiMlKemSharedSecretLength)
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

    private func rustSuite(for algorithm: ReallyMeKemAlgorithm) throws -> RustCAbiMlKemSuite {
        switch algorithm {
        case .mlKem512:
            return RustCAbiMlKemSuite(
                publicKeyLength: rustCAbiMlKem512PublicKeyLength,
                ciphertextLength: rustCAbiMlKem512CiphertextLength,
                generateKeyPairFunction: mlKem512GenerateKeyPairFunction,
                deriveKeyPairFunction: mlKem512DeriveKeyPairFunction,
                encapsulateFunction: mlKem512EncapsulateFunction,
                decapsulateFunction: mlKem512DecapsulateFunction
            )
        case .mlKem768:
            return RustCAbiMlKemSuite(
                publicKeyLength: rustCAbiMlKem768PublicKeyLength,
                ciphertextLength: rustCAbiMlKem768CiphertextLength,
                generateKeyPairFunction: mlKem768GenerateKeyPairFunction,
                deriveKeyPairFunction: mlKem768DeriveKeyPairFunction,
                encapsulateFunction: mlKem768EncapsulateFunction,
                decapsulateFunction: mlKem768DecapsulateFunction
            )
        case .mlKem1024:
            return RustCAbiMlKemSuite(
                publicKeyLength: rustCAbiMlKem1024PublicKeyLength,
                ciphertextLength: rustCAbiMlKem1024CiphertextLength,
                generateKeyPairFunction: mlKem1024GenerateKeyPairFunction,
                deriveKeyPairFunction: mlKem1024DeriveKeyPairFunction,
                encapsulateFunction: mlKem1024EncapsulateFunction,
                decapsulateFunction: mlKem1024DecapsulateFunction
            )
        case .xWing768:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }
}
