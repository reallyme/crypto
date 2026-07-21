// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#if canImport(Darwin)
import Darwin
#endif
import Foundation

private typealias HashFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias AesKwFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<Int>
) -> Int32

private typealias Pbkdf2Function = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UInt32,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias KmacFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias KeypairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias DerivePublicKeyFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias SignFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias VerifyFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int
) -> Int32

private typealias EncapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias EncapsulateDerandFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

private typealias DecapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
) -> Int32

enum RustCryptoFfiError: Error {
    case repositoryRootNotFound
    case unsupportedPlatform
    case dynamicLibraryNotFound
    case dynamicLibraryLoadFailed
    case symbolNotFound
    case cargoBuildFailed
    case emptyBuffer
    case callFailed
    case invalidVerificationResult
}

final class RustCryptoFfi {
    private static let ok: Int32 = 0
    private static let sharedSecretLength = 32

    private let handle: UnsafeMutableRawPointer
    private let sha3_224: HashFunction
    private let sha3_256: HashFunction
    private let sha3_384: HashFunction
    private let sha3_512: HashFunction
    private let aes128KwWrapKey: AesKwFunction
    private let aes128KwUnwrapKey: AesKwFunction
    private let aes192KwWrapKey: AesKwFunction
    private let aes192KwUnwrapKey: AesKwFunction
    private let aes256KwWrapKey: AesKwFunction
    private let aes256KwUnwrapKey: AesKwFunction
    private let pbkdf2HmacSha256DeriveKey: Pbkdf2Function
    private let pbkdf2HmacSha512DeriveKey: Pbkdf2Function
    private let kmac256DeriveKey: KmacFunction
    private let mlDsa44GenerateKeypair: KeypairFunction
    private let mlDsa44Sign: SignFunction
    private let mlDsa44Verify: VerifyFunction
    private let mlDsa65GenerateKeypair: KeypairFunction
    private let mlDsa65Sign: SignFunction
    private let mlDsa65Verify: VerifyFunction
    private let mlDsa87GenerateKeypair: KeypairFunction
    private let mlDsa87Sign: SignFunction
    private let mlDsa87Verify: VerifyFunction
    private let mlKem512GenerateKeypair: KeypairFunction
    private let mlKem512Encapsulate: EncapsulateFunction
    private let mlKem512Decapsulate: DecapsulateFunction
    private let mlKem768GenerateKeypair: KeypairFunction
    private let mlKem768Encapsulate: EncapsulateFunction
    private let mlKem768Decapsulate: DecapsulateFunction
    private let mlKem1024GenerateKeypair: KeypairFunction
    private let mlKem1024Encapsulate: EncapsulateFunction
    private let mlKem1024Decapsulate: DecapsulateFunction
    private let xWing768DerivePublicKeyFn: DerivePublicKeyFunction
    private let xWing768EncapsulateDerandFn: EncapsulateDerandFunction
    private let xWing768DecapsulateFn: DecapsulateFunction

    init() throws {
        let repositoryRoot = try Self.repositoryRoot()
        try Self.buildLibrary(at: repositoryRoot)

        let library = try Self.libraryURL(in: repositoryRoot)
        guard FileManager.default.fileExists(atPath: library.path) else {
            throw RustCryptoFfiError.dynamicLibraryNotFound
        }
        guard let loadedHandle = dlopen(library.path, RTLD_NOW | RTLD_LOCAL) else {
            throw RustCryptoFfiError.dynamicLibraryLoadFailed
        }

        handle = loadedHandle
        sha3_224 = try Self.loadSymbol("rm_crypto_sha3_224_digest", from: loadedHandle)
        sha3_256 = try Self.loadSymbol("rm_crypto_sha3_256_digest", from: loadedHandle)
        sha3_384 = try Self.loadSymbol("rm_crypto_sha3_384_digest", from: loadedHandle)
        sha3_512 = try Self.loadSymbol("rm_crypto_sha3_512_digest", from: loadedHandle)
        aes128KwWrapKey = try Self.loadSymbol("rm_crypto_aes128_kw_wrap_key", from: loadedHandle)
        aes128KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes128_kw_unwrap_key", from: loadedHandle)
        aes192KwWrapKey = try Self.loadSymbol("rm_crypto_aes192_kw_wrap_key", from: loadedHandle)
        aes192KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes192_kw_unwrap_key", from: loadedHandle)
        aes256KwWrapKey = try Self.loadSymbol("rm_crypto_aes256_kw_wrap_key", from: loadedHandle)
        aes256KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes256_kw_unwrap_key", from: loadedHandle)
        pbkdf2HmacSha256DeriveKey = try Self.loadSymbol("rm_crypto_pbkdf2_hmac_sha256_derive_key", from: loadedHandle)
        pbkdf2HmacSha512DeriveKey = try Self.loadSymbol("rm_crypto_pbkdf2_hmac_sha512_derive_key", from: loadedHandle)
        kmac256DeriveKey = try Self.loadSymbol("rm_crypto_kmac256_derive", from: loadedHandle)
        mlDsa44GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_dsa_44_generate_keypair", from: loadedHandle)
        mlDsa44Sign = try Self.loadSymbol("rm_crypto_ml_dsa_44_sign", from: loadedHandle)
        mlDsa44Verify = try Self.loadSymbol("rm_crypto_ml_dsa_44_verify", from: loadedHandle)
        mlDsa65GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_dsa_65_generate_keypair", from: loadedHandle)
        mlDsa65Sign = try Self.loadSymbol("rm_crypto_ml_dsa_65_sign", from: loadedHandle)
        mlDsa65Verify = try Self.loadSymbol("rm_crypto_ml_dsa_65_verify", from: loadedHandle)
        mlDsa87GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_dsa_87_generate_keypair", from: loadedHandle)
        mlDsa87Sign = try Self.loadSymbol("rm_crypto_ml_dsa_87_sign", from: loadedHandle)
        mlDsa87Verify = try Self.loadSymbol("rm_crypto_ml_dsa_87_verify", from: loadedHandle)
        mlKem512GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_kem_512_generate_keypair", from: loadedHandle)
        mlKem512Encapsulate = try Self.loadSymbol("rm_crypto_ml_kem_512_encapsulate", from: loadedHandle)
        mlKem512Decapsulate = try Self.loadSymbol("rm_crypto_ml_kem_512_decapsulate", from: loadedHandle)
        mlKem768GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_kem_768_generate_keypair", from: loadedHandle)
        mlKem768Encapsulate = try Self.loadSymbol("rm_crypto_ml_kem_768_encapsulate", from: loadedHandle)
        mlKem768Decapsulate = try Self.loadSymbol("rm_crypto_ml_kem_768_decapsulate", from: loadedHandle)
        mlKem1024GenerateKeypair = try Self.loadSymbol("rm_crypto_ml_kem_1024_generate_keypair", from: loadedHandle)
        mlKem1024Encapsulate = try Self.loadSymbol("rm_crypto_ml_kem_1024_encapsulate", from: loadedHandle)
        mlKem1024Decapsulate = try Self.loadSymbol("rm_crypto_ml_kem_1024_decapsulate", from: loadedHandle)
        xWing768DerivePublicKeyFn = try Self.loadSymbol("rm_crypto_x_wing_768_generate_keypair_derand", from: loadedHandle)
        xWing768EncapsulateDerandFn = try Self.loadSymbol("rm_crypto_x_wing_768_encapsulate_derand", from: loadedHandle)
        xWing768DecapsulateFn = try Self.loadSymbol("rm_crypto_x_wing_768_decapsulate", from: loadedHandle)
    }

    deinit {
        dlclose(handle)
    }

    func sha3Digest(_ message: Data) throws -> Data {
        try callHash(sha3_256, message: message, digestLength: 32)
    }

    func sha3_224Digest(_ message: Data) throws -> Data {
        try callHash(sha3_224, message: message, digestLength: 28)
    }

    func sha3_384Digest(_ message: Data) throws -> Data {
        try callHash(sha3_384, message: message, digestLength: 48)
    }

    func sha3_512Digest(_ message: Data) throws -> Data {
        try callHash(sha3_512, message: message, digestLength: 64)
    }

    private func callHash(_ function: HashFunction, message: Data, digestLength: Int) throws -> Data {
        var digest = [UInt8](repeating: 0, count: digestLength)
        let outputLength = digest.count
        let status = try message.withUnsafeBytes { messageBytes in
            guard let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress else {
                throw RustCryptoFfiError.emptyBuffer
            }
            return try digest.withUnsafeMutableBufferPointer { digestBytes in
                let digestPointer = try Self.mutableBaseAddress(digestBytes)
                return function(
                    messagePointer,
                    message.count,
                    digestPointer,
                    outputLength
                )
            }
        }
        try Self.requireOk(status)
        return Data(digest)
    }

    func aes128KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
        try aesKwWrap(aes128KwWrapKey, kek: kek, keyData: keyData)
    }

    func aes128KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
        try aesKwUnwrap(aes128KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
    }

    func aes192KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
        try aesKwWrap(aes192KwWrapKey, kek: kek, keyData: keyData)
    }

    func aes192KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
        try aesKwUnwrap(aes192KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
    }

    func aes256KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
        try aesKwWrap(aes256KwWrapKey, kek: kek, keyData: keyData)
    }

    func aes256KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
        try aesKwUnwrap(aes256KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
    }

    private func aesKwWrap(_ function: AesKwFunction, kek: [UInt8], keyData: [UInt8]) throws -> Data {
        let outputLengthResult = keyData.count.addingReportingOverflow(8)
        guard !outputLengthResult.overflow else {
            throw RustCryptoFfiError.callFailed
        }
        let outputLength = outputLengthResult.partialValue
        return try callAesKw(function, kek: kek, input: keyData, outputLength: outputLength)
    }

    private func aesKwUnwrap(_ function: AesKwFunction, kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
        guard wrappedKey.count >= 8 else {
            throw RustCryptoFfiError.callFailed
        }
        return try callAesKw(function, kek: kek, input: wrappedKey, outputLength: wrappedKey.count - 8)
    }

    private func callAesKw(
        _ function: AesKwFunction,
        kek: [UInt8],
        input: [UInt8],
        outputLength: Int
    ) throws -> Data {
        var output = [UInt8](repeating: 0, count: outputLength)
        var writtenLength = 0
        let status = try kek.withUnsafeBufferPointer { kekBytes in
            try input.withUnsafeBufferPointer { inputBytes in
                try output.withUnsafeMutableBufferPointer { outputBytes in
                    let kekPointer = try Self.baseAddress(kekBytes)
                    let inputPointer = try Self.baseAddress(inputBytes)
                    let outputPointer = try Self.mutableBaseAddress(outputBytes)
                    return function(
                        kekPointer,
                        kek.count,
                        inputPointer,
                        input.count,
                        outputPointer,
                        outputLength,
                        &writtenLength
                    )
                }
            }
        }
        try Self.requireOk(status)
        guard writtenLength <= output.count else {
            throw RustCryptoFfiError.callFailed
        }
        return Data(output.prefix(writtenLength))
    }

    func pbkdf2HmacSha256(password: [UInt8], salt: [UInt8], iterations: UInt32, outputLength: Int) throws -> Data {
        try callPbkdf2(
            pbkdf2HmacSha256DeriveKey,
            password: password,
            salt: salt,
            iterations: iterations,
            outputLength: outputLength
        )
    }

    func pbkdf2HmacSha512(password: [UInt8], salt: [UInt8], iterations: UInt32, outputLength: Int) throws -> Data {
        try callPbkdf2(
            pbkdf2HmacSha512DeriveKey,
            password: password,
            salt: salt,
            iterations: iterations,
            outputLength: outputLength
        )
    }

    private func callPbkdf2(
        _ function: Pbkdf2Function,
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws -> Data {
        guard outputLength > 0 else {
            throw RustCryptoFfiError.callFailed
        }
        var output = [UInt8](repeating: 0, count: outputLength)
        let status = try password.withUnsafeBufferPointer { passwordBytes in
            try salt.withUnsafeBufferPointer { saltBytes in
                try output.withUnsafeMutableBufferPointer { outputBytes in
                    let passwordPointer = try Self.baseAddress(passwordBytes)
                    let saltPointer = try Self.baseAddress(saltBytes)
                    let outputPointer = try Self.mutableBaseAddress(outputBytes)
                    return function(
                        passwordPointer,
                        password.count,
                        saltPointer,
                        salt.count,
                        iterations,
                        outputPointer,
                        outputLength
                    )
                }
            }
        }
        try Self.requireOk(status)
        return Data(output)
    }

    func kmac256(key: [UInt8], context: [UInt8], customization: [UInt8], outputLength: Int) throws -> Data {
        guard outputLength > 0 else {
            throw RustCryptoFfiError.callFailed
        }
        var output = [UInt8](repeating: 0, count: outputLength)
        let status = try key.withUnsafeBufferPointer { keyBytes in
            try context.withUnsafeBufferPointer { contextBytes in
                try customization.withUnsafeBufferPointer { customizationBytes in
                    try output.withUnsafeMutableBufferPointer { outputBytes in
                        let keyPointer = try Self.baseAddress(keyBytes)
                        let contextPointer = try Self.baseAddress(contextBytes)
                        let customizationPointer = try Self.baseAddress(customizationBytes)
                        let outputPointer = try Self.mutableBaseAddress(outputBytes)
                        return kmac256DeriveKey(
                            keyPointer,
                            key.count,
                            contextPointer,
                            context.count,
                            customizationPointer,
                            customization.count,
                            outputPointer,
                            outputLength
                        )
                    }
                }
            }
        }
        try Self.requireOk(status)
        return Data(output)
    }

    func mlDsa87RoundTrip(message: Data) throws -> Bool {
        var publicKey = [UInt8](repeating: 0, count: 2_592)
        var secretSeed = [UInt8](repeating: 0, count: 32)
        try callKeypair(mlDsa87GenerateKeypair, publicKey: &publicKey, secretKey: &secretSeed)

        var signature = [UInt8](repeating: 0, count: 4_627)
        let signatureLength = signature.count
        let signStatus = try secretSeed.withUnsafeBufferPointer { secretBytes in
            try message.withUnsafeBytes { messageBytes in
                guard
                    let secretPointer = secretBytes.baseAddress,
                    let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
                else {
                    throw RustCryptoFfiError.emptyBuffer
                }
                return try signature.withUnsafeMutableBufferPointer { signatureBytes in
                    let signaturePointer = try Self.mutableBaseAddress(signatureBytes)
                    return mlDsa87Sign(
                        secretPointer,
                        secretSeed.count,
                        messagePointer,
                        message.count,
                        signaturePointer,
                        signatureLength
                    )
                }
            }
        }
        try Self.requireOk(signStatus)

        try verify(
            mlDsa87Verify,
            publicKey: publicKey,
            message: message,
            signature: signature
        )
        return true
    }

    /// Deterministically signs `message` with a committed ML-DSA seed
    /// and returns the raw signature, so the caller can compare it against
    /// the committed known-answer signature byte-for-byte.
    func mlDsa44Sign(secretSeed: [UInt8], message: Data) throws -> Data {
        try mlDsaSign(mlDsa44Sign, secretSeed: secretSeed, message: message, signatureLength: 2_420)
    }

    func mlDsa65Sign(secretSeed: [UInt8], message: Data) throws -> Data {
        try mlDsaSign(mlDsa65Sign, secretSeed: secretSeed, message: message, signatureLength: 3_309)
    }

    func mlDsa87Sign(secretSeed: [UInt8], message: Data) throws -> Data {
        try mlDsaSign(mlDsa87Sign, secretSeed: secretSeed, message: message, signatureLength: 4_627)
    }

    private func mlDsaSign(
        _ sign: SignFunction,
        secretSeed: [UInt8],
        message: Data,
        signatureLength: Int
    ) throws -> Data {
        var signature = [UInt8](repeating: 0, count: signatureLength)
        let signatureLength = signature.count
        let status = try secretSeed.withUnsafeBufferPointer { secretBytes in
            try message.withUnsafeBytes { messageBytes in
                guard
                    let secretPointer = secretBytes.baseAddress,
                    let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
                else {
                    throw RustCryptoFfiError.emptyBuffer
                }
                return try signature.withUnsafeMutableBufferPointer { signatureBytes in
                    let signaturePointer = try Self.mutableBaseAddress(signatureBytes)
                    return sign(
                        secretPointer,
                        secretSeed.count,
                        messagePointer,
                        message.count,
                        signaturePointer,
                        signatureLength
                    )
                }
            }
        }
        try Self.requireOk(status)
        return Data(signature)
    }

    /// Verifies a detached ML-DSA signature. Invalid signatures fail by status.
    func mlDsa44Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
        try verify(mlDsa44Verify, publicKey: publicKey, message: message, signature: signature)
    }

    func mlDsa65Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
        try verify(mlDsa65Verify, publicKey: publicKey, message: message, signature: signature)
    }

    func mlDsa87Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
        try verify(mlDsa87Verify, publicKey: publicKey, message: message, signature: signature)
    }

    /// Decapsulates a committed ML-KEM ciphertext with the committed
    /// secret seed and returns the resulting shared secret. Used to check
    /// both the valid known-answer secret and the implicit-rejection secret
    /// for a tampered ciphertext.
    func mlKem512Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
        try decapsulateSharedSecret(mlKem512Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
    }

    func mlKem768Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
        try decapsulateSharedSecret(mlKem768Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
    }

    /// ML-KEM-1024 counterpart of `mlKem768Decapsulate`.
    func mlKem1024Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
        try decapsulateSharedSecret(mlKem1024Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
    }

    private func decapsulateSharedSecret(
        _ decapsulate: DecapsulateFunction,
        ciphertext: [UInt8],
        secretKey: [UInt8]
    ) throws -> Data {
        var sharedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
        let sharedSecretLength = sharedSecret.count
        let status = try ciphertext.withUnsafeBufferPointer { ciphertextBytes in
            try secretKey.withUnsafeBufferPointer { secretBytes in
                try sharedSecret.withUnsafeMutableBufferPointer { sharedBytes in
                    let ciphertextPointer = try Self.baseAddress(ciphertextBytes)
                    let secretPointer = try Self.baseAddress(secretBytes)
                    let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
                    return decapsulate(
                        ciphertextPointer,
                        ciphertext.count,
                        secretPointer,
                        secretKey.count,
                        sharedPointer,
                        sharedSecretLength
                    )
                }
            }
        }
        try Self.requireOk(status)
        return Data(sharedSecret)
    }

    func mlKem512RoundTrip() throws -> Bool {
        try mlKemRoundTrip(
            generateKeypair: mlKem512GenerateKeypair,
            encapsulate: mlKem512Encapsulate,
            decapsulate: mlKem512Decapsulate,
            publicKeyLength: 800,
            secretKeyLength: 64,
            ciphertextLength: 768
        )
    }

    func mlKem768RoundTrip() throws -> Bool {
        try mlKemRoundTrip(
            generateKeypair: mlKem768GenerateKeypair,
            encapsulate: mlKem768Encapsulate,
            decapsulate: mlKem768Decapsulate,
            publicKeyLength: 1_184,
            secretKeyLength: 64,
            ciphertextLength: 1_088
        )
    }

    func mlKem1024RoundTrip() throws -> Bool {
        try mlKemRoundTrip(
            generateKeypair: mlKem1024GenerateKeypair,
            encapsulate: mlKem1024Encapsulate,
            decapsulate: mlKem1024Decapsulate,
            publicKeyLength: 1_568,
            secretKeyLength: 64,
            ciphertextLength: 1_568
        )
    }

    func xWing768PublicKey(secretKey: [UInt8]) throws -> Data {
        try derivePublicKey(xWing768DerivePublicKeyFn, secretKey: secretKey, publicKeyLength: 1_216)
    }

    func xWing768EncapsulateDerand(publicKey: [UInt8], seed: [UInt8]) throws -> (Data, Data) {
        try encapsulateDerand(
            xWing768EncapsulateDerandFn,
            publicKey: publicKey,
            seed: seed,
            ciphertextLength: 1_120
        )
    }

    func xWing768Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
        try decapsulateSharedSecret(xWing768DecapsulateFn, ciphertext: ciphertext, secretKey: secretKey)
    }

    private func derivePublicKey(
        _ function: DerivePublicKeyFunction,
        secretKey: [UInt8],
        publicKeyLength: Int
    ) throws -> Data {
        var publicKey = [UInt8](repeating: 0, count: publicKeyLength)
        let status = try secretKey.withUnsafeBufferPointer { secretBytes in
            try publicKey.withUnsafeMutableBufferPointer { publicBytes in
                let secretPointer = try Self.baseAddress(secretBytes)
                let publicPointer = try Self.mutableBaseAddress(publicBytes)
                return function(secretPointer, secretKey.count, publicPointer, publicKeyLength)
            }
        }
        try Self.requireOk(status)
        return Data(publicKey)
    }

    private func encapsulateDerand(
        _ function: EncapsulateDerandFunction,
        publicKey: [UInt8],
        seed: [UInt8],
        ciphertextLength: Int
    ) throws -> (Data, Data) {
        var ciphertext = [UInt8](repeating: 0, count: ciphertextLength)
        var sharedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
        let status = try publicKey.withUnsafeBufferPointer { publicBytes in
            try seed.withUnsafeBufferPointer { seedBytes in
                try ciphertext.withUnsafeMutableBufferPointer { ciphertextBytes in
                    try sharedSecret.withUnsafeMutableBufferPointer { sharedBytes in
                        let publicPointer = try Self.baseAddress(publicBytes)
                        let seedPointer = try Self.baseAddress(seedBytes)
                        let ciphertextPointer = try Self.mutableBaseAddress(ciphertextBytes)
                        let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
                        return function(
                            publicPointer,
                            publicKey.count,
                            seedPointer,
                            seed.count,
                            ciphertextPointer,
                            ciphertextLength,
                            sharedPointer,
                            Self.sharedSecretLength
                        )
                    }
                }
            }
        }
        try Self.requireOk(status)
        return (Data(ciphertext), Data(sharedSecret))
    }

    private func mlKemRoundTrip(
        generateKeypair: KeypairFunction,
        encapsulate: EncapsulateFunction,
        decapsulate: DecapsulateFunction,
        publicKeyLength: Int,
        secretKeyLength: Int,
        ciphertextLength: Int
    ) throws -> Bool {
        var publicKey = [UInt8](repeating: 0, count: publicKeyLength)
        var secretKey = [UInt8](repeating: 0, count: secretKeyLength)
        try callKeypair(generateKeypair, publicKey: &publicKey, secretKey: &secretKey)

        var ciphertext = [UInt8](repeating: 0, count: ciphertextLength)
        var encapsulatedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
        let encapsulatedSecretLength = encapsulatedSecret.count
        let encapsulateStatus = try publicKey.withUnsafeBufferPointer { publicBytes in
            try ciphertext.withUnsafeMutableBufferPointer { ciphertextBytes in
                try encapsulatedSecret.withUnsafeMutableBufferPointer { secretBytes in
                    let publicPointer = try Self.baseAddress(publicBytes)
                    let ciphertextPointer = try Self.mutableBaseAddress(ciphertextBytes)
                    let secretPointer = try Self.mutableBaseAddress(secretBytes)
                    return encapsulate(
                        publicPointer,
                        publicKey.count,
                        ciphertextPointer,
                        ciphertextLength,
                        secretPointer,
                        encapsulatedSecretLength
                    )
                }
            }
        }
        try Self.requireOk(encapsulateStatus)

        var decapsulatedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
        let decapsulatedSecretLength = decapsulatedSecret.count
        let decapsulateStatus = try ciphertext.withUnsafeBufferPointer { ciphertextBytes in
            try secretKey.withUnsafeBufferPointer { secretBytes in
                try decapsulatedSecret.withUnsafeMutableBufferPointer { sharedBytes in
                    let ciphertextPointer = try Self.baseAddress(ciphertextBytes)
                    let secretPointer = try Self.baseAddress(secretBytes)
                    let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
                    return decapsulate(
                        ciphertextPointer,
                        ciphertextLength,
                        secretPointer,
                        secretKeyLength,
                        sharedPointer,
                        decapsulatedSecretLength
                    )
                }
            }
        }
        try Self.requireOk(decapsulateStatus)
        return encapsulatedSecret == decapsulatedSecret
    }

    private func callKeypair(
        _ function: KeypairFunction,
        publicKey: inout [UInt8],
        secretKey: inout [UInt8]
    ) throws {
        let publicKeyLength = publicKey.count
        let secretKeyLength = secretKey.count
        let status = try publicKey.withUnsafeMutableBufferPointer { publicBytes in
            try secretKey.withUnsafeMutableBufferPointer { secretBytes in
                let publicPointer = try Self.mutableBaseAddress(publicBytes)
                let secretPointer = try Self.mutableBaseAddress(secretBytes)
                return function(
                    publicPointer,
                    publicKeyLength,
                    secretPointer,
                    secretKeyLength
                )
            }
        }
        try Self.requireOk(status)
    }

    private func verify(
        _ function: VerifyFunction,
        publicKey: [UInt8],
        message: Data,
        signature: [UInt8]
    ) throws {
        let status = try publicKey.withUnsafeBufferPointer { publicBytes in
            try message.withUnsafeBytes { messageBytes in
                try signature.withUnsafeBufferPointer { signatureBytes in
                    guard
                        let publicPointer = publicBytes.baseAddress,
                        let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress,
                        let signaturePointer = signatureBytes.baseAddress
                    else {
                        throw RustCryptoFfiError.emptyBuffer
                    }
                    return function(
                        publicPointer,
                        publicKey.count,
                        messagePointer,
                        message.count,
                        signaturePointer,
                        signature.count
                    )
                }
            }
        }
        try Self.requireOk(status)
    }

    private static func repositoryRoot() throws -> URL {
        var cursor = URL(fileURLWithPath: #filePath)
        while cursor.path != "/" {
            let manifest = cursor.appendingPathComponent("Cargo.toml")
            let ffiCrate = cursor
                .appendingPathComponent("crates")
                .appendingPathComponent("ffi")
            if FileManager.default.fileExists(atPath: manifest.path)
                && FileManager.default.fileExists(atPath: ffiCrate.path) {
                return cursor
            }
            cursor.deleteLastPathComponent()
        }
        throw RustCryptoFfiError.repositoryRootNotFound
    }

    private static func buildLibrary(at repositoryRoot: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        // The X-Wing known-answer test intentionally consumes the deterministic
        // encapsulation entry point. That symbol is excluded from production
        // artifacts and exists only in the conformance-only `test-vectors` lane.
        process.arguments = [
            "cargo", "build", "-p", "crypto-ffi", "--features", "test-vectors",
        ]
        process.currentDirectoryURL = repositoryRoot

        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw RustCryptoFfiError.cargoBuildFailed
        }
    }

    private static func libraryURL(in repositoryRoot: URL) throws -> URL {
        #if os(macOS)
        return repositoryRoot
            .appendingPathComponent("target")
            .appendingPathComponent("debug")
            .appendingPathComponent("libcrypto_ffi.dylib")
        #elseif os(Linux)
        return repositoryRoot
            .appendingPathComponent("target")
            .appendingPathComponent("debug")
            .appendingPathComponent("libcrypto_ffi.so")
        #else
        throw RustCryptoFfiError.unsupportedPlatform
        #endif
    }

    private static func loadSymbol<T>(
        _ name: String,
        from handle: UnsafeMutableRawPointer
    ) throws -> T {
        guard let symbol = dlsym(handle, name) else {
            throw RustCryptoFfiError.symbolNotFound
        }
        return unsafeBitCast(symbol, to: T.self)
    }

    private static func requireOk(_ status: Int32) throws {
        guard status == ok else {
            throw RustCryptoFfiError.callFailed
        }
    }

    private static func baseAddress(
        _ buffer: UnsafeBufferPointer<UInt8>
    ) throws -> UnsafePointer<UInt8> {
        guard let baseAddress = buffer.baseAddress else {
            throw RustCryptoFfiError.emptyBuffer
        }
        return baseAddress
    }

    private static func mutableBaseAddress(
        _ buffer: UnsafeMutableBufferPointer<UInt8>
    ) throws -> UnsafeMutablePointer<UInt8> {
        guard let baseAddress = buffer.baseAddress else {
            throw RustCryptoFfiError.emptyBuffer
        }
        return baseAddress
    }
}
