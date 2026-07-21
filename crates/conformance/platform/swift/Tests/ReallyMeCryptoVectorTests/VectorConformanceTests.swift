// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import Security
import Secp256k1ABI
import SwiftProviderProbes
import XCTest

final class VectorConformanceTests: XCTestCase {
    private static let expectedVectors = [
        "p256.json",
        "p384.json",
        "p521.json",
        "ed25519.json",
        "secp256k1.json",
        "bip340_schnorr.json",
        "rsa.json",
        "x25519.json",
        "ml_dsa_44.json",
        "ml_dsa_65.json",
        "ml_dsa_87.json",
        "slh_dsa_sha2_128s.json",
        "mlkem512.json",
        "mlkem768.json",
        "mlkem1024.json",
        "x_wing.json",
        "hpke.json",
        "aes128gcm.json",
        "aes192gcm.json",
        "aes256gcm.json",
        "aes256gcmsiv.json",
        "aes128kw.json",
        "aes192kw.json",
        "aes256kw.json",
        "argon2id.json",
        "kmac256.json",
        "chacha20poly1305.json",
        "hkdf.json",
        "hkdf_sha384.json",
        "concat_kdf.json",
        "hmac.json",
        "pbkdf2.json",
        "hashes.json",
        "operation_response.json",
        "jwk.json",
    ]

    func testManifestListsEverySharedVector() throws {
        let manifest: Manifest = try loadVector("manifest.json")
        XCTAssertEqual(manifest.vectors, Self.expectedVectors)
    }

    func testCryptoKitP256Vector() throws {
        let vector: P256Vector = try loadVector("p256.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
        let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
        let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
        let peerCompressedPublicKey = try Data(base64Url: vector.peerPublicKeyCompressed)
        let peerUncompressedPublicKey = try Data(base64Url: vector.peerPublicKeyUncompressed)
        let sharedSecret = try Data(base64Url: vector.sharedSecret)

        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: secretKey)
        let peerPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: peerSecretKey)
        let peerPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: peerCompressedPublicKey)
        let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
        XCTAssertEqual(peerPrivateKey.publicKey.compressedRepresentation, peerCompressedPublicKey)
        XCTAssertEqual(peerPrivateKey.publicKey.x963Representation, peerUncompressedPublicKey)
        XCTAssertEqual(try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey).rawBytes, sharedSecret)
        XCTAssertEqual(try peerPrivateKey.sharedSecretFromKeyAgreement(with: publicKey).rawBytes, sharedSecret)
    }

    func testCryptoKitP384Vector() throws {
        let vector: Sec1EcdsaVector = try loadVector("p384.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
        let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
        let message = try Data(base64Url: vector.message)
        let signature = try P384.Signing.ECDSASignature(
            derRepresentation: try Data(base64Url: vector.signatureDer)
        )

        let privateKey = try P384.Signing.PrivateKey(rawRepresentation: secretKey)
        let publicKey = try P384.Signing.PublicKey(compressedRepresentation: compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testCryptoKitP521Vector() throws {
        let vector: Sec1EcdsaVector = try loadVector("p521.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
        let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
        let message = try Data(base64Url: vector.message)
        let signature = try P521.Signing.ECDSASignature(
            derRepresentation: try Data(base64Url: vector.signatureDer)
        )

        let privateKey = try P521.Signing.PrivateKey(rawRepresentation: secretKey)
        let publicKey = try P521.Signing.PublicKey(compressedRepresentation: compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
        XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
    }

    func testCryptoKitEd25519Vector() throws {
        let vector: Ed25519Vector = try loadVector("ed25519.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let publicKey = try Data(base64Url: vector.publicKey)
        let message = try Data(base64Url: vector.message)
        let signature = try Data(base64Url: vector.signature)

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: secretKey)
        let verificationKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        let generatedSignature = try privateKey.signature(for: message)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey)
        XCTAssertTrue(verificationKey.isValidSignature(signature, for: message))
        XCTAssertTrue(verificationKey.isValidSignature(generatedSignature, for: message))
    }

    func testSecurityFrameworkRsaVector() throws {
        let vector: RsaVector = try loadVector("rsa.json")
        let publicKeyDer = try Data(base64Url: vector.publicKeyDer)
        let message = try Data(base64Url: vector.message)
        let pkcs1Sha1Signature = try Data(base64Url: vector.pkcs1v15Sha1Signature)
        let pkcs1Sha256Signature = try Data(base64Url: vector.pkcs1v15Sha256Signature)
        let pssSha256Signature = try Data(base64Url: vector.pssSha256Mgf1Sha256Signature)

        XCTAssertEqual(vector.keyFormat, "PKCS1-DER-RSAPublicKey")
        XCTAssertEqual(vector.pssSha256Mgf1Sha256SaltLen, 32)
        XCTAssertEqual(pkcs1Sha1Signature.count, 256)
        XCTAssertEqual(pkcs1Sha256Signature.count, 256)
        XCTAssertEqual(pssSha256Signature.count, 256)

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 2048,
        ]
        let publicKey = try XCTUnwrap(
            SecKeyCreateWithData(publicKeyDer as CFData, attributes as CFDictionary, nil)
        )

        XCTAssertTrue(
            SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePKCS1v15SHA1,
                message as CFData,
                pkcs1Sha1Signature as CFData,
                nil
            )
        )
        XCTAssertTrue(
            SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePKCS1v15SHA256,
                message as CFData,
                pkcs1Sha256Signature as CFData,
                nil
            )
        )
        XCTAssertTrue(
            SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePSSSHA256,
                message as CFData,
                pssSha256Signature as CFData,
                nil
            )
        )

        var tampered = pssSha256Signature
        tampered[0] ^= 0x01
        XCTAssertFalse(
            SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePSSSHA256,
                message as CFData,
                tampered as CFData,
                nil
            )
        )
    }

    func testCryptoKitX25519Vector() throws {
        let vector: X25519Vector = try loadVector("x25519.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let publicKey = try Data(base64Url: vector.publicKey)
        let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
        let peerPublicKey = try Data(base64Url: vector.peerPublicKey)
        let sharedSecret = try Data(base64Url: vector.sharedSecret)

        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretKey)
        let peerPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: peerSecretKey)
        let peerPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let localPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey)
        XCTAssertEqual(peerPrivateKey.publicKey.rawRepresentation, peerPublicKey)
        XCTAssertEqual(
            try privateKey.sharedSecretFromKeyAgreement(with: peerPublic).rawBytes,
            sharedSecret
        )
        XCTAssertEqual(
            try peerPrivateKey.sharedSecretFromKeyAgreement(with: localPublic).rawBytes,
            sharedSecret
        )
    }

    func testCryptoKitHpkeVector() throws {
        guard #available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *) else {
            throw XCTSkip("CryptoKit HPKE requires macOS 14 / iOS 17 or newer")
        }

        let vectors: HpkeVectors = try loadVector("hpke.json")
        try openP256HpkeCase(vectors.p256Sha256Aes256Gcm)
        try openX25519HpkeCase(vectors.x25519Sha256ChaCha20Poly1305)
    }

    func testCryptoKitAes256GcmVector() throws {
        let vector: Aes256GcmVector = try loadVector("aes256gcm.json")
        let key = SymmetricKey(data: try Data(base64Url: vector.key))
        let nonceData = try Data(base64Url: vector.nonce)
        _ = try AES.GCM.Nonce(data: nonceData)
        let aad = try Data(base64Url: vector.aad)
        let plaintext = try Data(base64Url: vector.plaintext)
        let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

        let sealedBox = try AES.GCM.SealedBox(combined: nonceData + ciphertextWithTag)
        let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        XCTAssertEqual(decrypted, plaintext)
        let generated = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: AES.GCM.Nonce(data: nonceData),
            authenticating: aad
        )
        let generatedCombined = try XCTUnwrap(generated.combined)
        XCTAssertEqual(generatedCombined.dropFirst(nonceData.count), ciphertextWithTag)
    }

    func testRustFfiAesKwVectors() throws {
        let ffi = try RustCryptoFfi()
        try assertAesKwVector(
            vectorName: "aes128kw.json",
            expectedAlgorithm: "AES-128-KW",
            wrap: ffi.aes128KwWrap,
            unwrap: ffi.aes128KwUnwrap
        )
        try assertAesKwVector(
            vectorName: "aes192kw.json",
            expectedAlgorithm: "AES-192-KW",
            wrap: ffi.aes192KwWrap,
            unwrap: ffi.aes192KwUnwrap
        )
        try assertAesKwVector(
            vectorName: "aes256kw.json",
            expectedAlgorithm: "AES-256-KW",
            wrap: ffi.aes256KwWrap,
            unwrap: ffi.aes256KwUnwrap
        )
    }

    private func assertAesKwVector(
        vectorName: String,
        expectedAlgorithm: String,
        wrap: ([UInt8], [UInt8]) throws -> Data,
        unwrap: ([UInt8], [UInt8]) throws -> Data
    ) throws {
        let vector: AesKwVector = try loadVector(vectorName)
        let kek = [UInt8](try Data(base64Url: vector.kek))
        let keyData = [UInt8](try Data(base64Url: vector.keyData))
        let wrappedKey = try Data(base64Url: vector.wrappedKey)

        XCTAssertEqual(vector.alg, expectedAlgorithm)
        XCTAssertEqual(try wrap(kek, keyData), wrappedKey)
        XCTAssertEqual(try unwrap(kek, [UInt8](wrappedKey)), Data(keyData))

        var tampered = [UInt8](wrappedKey)
        tampered[0] ^= 0x01
        XCTAssertThrowsError(try unwrap(kek, tampered))
    }

    func testRustFfiKmac256Vector() throws {
        let vector: Kmac256Vector = try loadVector("kmac256.json")
        let ffi = try RustCryptoFfi()
        let key = [UInt8](try Data(base64Url: vector.key))
        let context = [UInt8](try Data(base64Url: vector.context))
        let customization = [UInt8](try Data(base64Url: vector.customization))
        let derivedKey = try Data(base64Url: vector.derivedKey)

        XCTAssertEqual(vector.alg, "KMAC256")
        XCTAssertEqual(vector.outputLength, derivedKey.count)
        XCTAssertEqual(
            try ffi.kmac256(
                key: key,
                context: context,
                customization: customization,
                outputLength: vector.outputLength
            ),
            derivedKey
        )
    }

    func testCryptoKitChaCha20Poly1305Vector() throws {
        let vectors: ChaCha20Poly1305Vectors = try loadVector("chacha20poly1305.json")
        let vector = vectors.chacha20Poly1305
        let key = SymmetricKey(data: try Data(base64Url: vector.key))
        let nonceData = try Data(base64Url: vector.nonce)
        let aad = try Data(base64Url: vector.aad)
        let plaintext = try Data(base64Url: vector.plaintext)
        let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

        let sealedBox = try ChaChaPoly.SealedBox(combined: nonceData + ciphertextWithTag)
        let decrypted = try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
        XCTAssertEqual(decrypted, plaintext)

        let generated = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: ChaChaPoly.Nonce(data: nonceData),
            authenticating: aad
        )
        XCTAssertEqual(generated.combined.dropFirst(nonceData.count), ciphertextWithTag)
    }

    func testCryptoKitSha2Vector() throws {
        let vector: HashVector = try loadVector("hashes.json")
        let message = try Data(base64Url: vector.message)

        XCTAssertEqual(Data(SHA256.hash(data: message)), try Data(base64Url: vector.sha2_256))
        XCTAssertEqual(Data(SHA384.hash(data: message)), try Data(base64Url: vector.sha2_384))
        XCTAssertEqual(Data(SHA512.hash(data: message)), try Data(base64Url: vector.sha2_512))
    }

    func testCryptoKitHmacVector() throws {
        let vectors: HmacVectors = try loadVector("hmac.json")

        let sha256Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha256.key))
        let sha256Message = try Data(base64Url: vectors.hmacSha256.message)
        let sha256Tag = Data(HMAC<SHA256>.authenticationCode(for: sha256Message, using: sha256Key))
        XCTAssertEqual(sha256Tag, try Data(base64Url: vectors.hmacSha256.tag))

        let sha384Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha384.key))
        let sha384Message = try Data(base64Url: vectors.hmacSha384.message)
        let sha384Tag = Data(HMAC<SHA384>.authenticationCode(for: sha384Message, using: sha384Key))
        XCTAssertEqual(sha384Tag, try Data(base64Url: vectors.hmacSha384.tag))

        let sha512Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha512.key))
        let sha512Message = try Data(base64Url: vectors.hmacSha512.message)
        let sha512Tag = Data(HMAC<SHA512>.authenticationCode(for: sha512Message, using: sha512Key))
        XCTAssertEqual(sha512Tag, try Data(base64Url: vectors.hmacSha512.tag))
    }

    func testCryptoKitHkdfVectors() throws {
        try assertHkdfVector("hkdf.json", hash: SHA256.self, algorithm: "HKDF-SHA256", hashName: "SHA-256")
        try assertHkdfVector("hkdf_sha384.json", hash: SHA384.self, algorithm: "HKDF-SHA384", hashName: "SHA-384")
    }

    private func assertHkdfVector<H: HashFunction>(
        _ name: String,
        hash: H.Type,
        algorithm: String,
        hashName: String
    ) throws {
        let vector: HkdfVector = try loadVector(name)
        let ikm = SymmetricKey(data: try Data(base64Url: vector.ikm))
        let salt = try Data(base64Url: vector.salt)
        let info = try Data(base64Url: vector.info)
        let expected = try Data(base64Url: vector.okm)
        XCTAssertEqual(vector.alg, algorithm)
        XCTAssertEqual(vector.hash, hashName)
        XCTAssertEqual(vector.outputLen, expected.count)
        let derived = HKDF<H>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: vector.outputLen
        )
        XCTAssertEqual(derived.withUnsafeBytes { Data($0) }, expected)
    }

    func testRustFfiPbkdf2Vector() throws {
        let vectors: Pbkdf2Vectors = try loadVector("pbkdf2.json")
        let ffi = try RustCryptoFfi()
        try assertPbkdf2Case(vectors.pbkdf2HmacSha256, expectedLength: 32) {
            try ffi.pbkdf2HmacSha256(
                password: $0,
                salt: $1,
                iterations: $2,
                outputLength: $3
            )
        }
        try assertPbkdf2Case(vectors.pbkdf2HmacSha512, expectedLength: 64) {
            try ffi.pbkdf2HmacSha512(
                password: $0,
                salt: $1,
                iterations: $2,
                outputLength: $3
            )
        }
    }

    private func assertPbkdf2Case(
        _ vector: Pbkdf2Vector,
        expectedLength: Int,
        derive: ([UInt8], [UInt8], UInt32, Int) throws -> Data
    ) throws {
        let password = [UInt8](try Data(base64Url: vector.password))
        let salt = [UInt8](try Data(base64Url: vector.salt))
        let derivedKey = try Data(base64Url: vector.derivedKey)
        guard let iterations = UInt32(exactly: vector.iterations) else {
            throw VectorError.invalidField
        }

        XCTAssertEqual(vector.outputLen, expectedLength)
        XCTAssertEqual(derivedKey.count, expectedLength)
        XCTAssertEqual(try derive(password, salt, iterations, vector.outputLen), derivedKey)
    }

    func testRustFfiSha3Vector() throws {
        let vector: HashVector = try loadVector("hashes.json")
        let ffi = try RustCryptoFfi()
        let message = try Data(base64Url: vector.message)
        XCTAssertEqual(
            try ffi.sha3_224Digest(message),
            try Data(base64Url: vector.sha3_224)
        )
        XCTAssertEqual(
            try ffi.sha3Digest(message),
            try Data(base64Url: vector.sha3_256)
        )
        XCTAssertEqual(
            try ffi.sha3_384Digest(message),
            try Data(base64Url: vector.sha3_384)
        )
        XCTAssertEqual(
            try ffi.sha3_512Digest(message),
            try Data(base64Url: vector.sha3_512)
        )
    }

    func testLibsecp256k1AbiRoundTrip() throws {
        var publicKey = [UInt8](repeating: 0, count: 33)
        var secretKey = [UInt8](repeating: 0, count: 32)
        XCTAssertEqual(secp256k1_generate_keypair(&publicKey, &secretKey), 0)

        let message = Data("reallyme swift secp256k1 conformance".utf8)
        var signature = [UInt8](repeating: 0, count: 64)
        let signStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
            try message.withUnsafeBytes { messageBytes in
                guard
                    let secretPointer = secretBytes.baseAddress,
                    let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
                else {
                    throw VectorError.emptyBuffer
                }
                return secp256k1_sign(
                    secretPointer,
                    messagePointer,
                    message.count,
                    &signature
                )
            }
        }
        XCTAssertEqual(signStatus, 0)

        var valid: Int32 = 0
        let verifyStatus = try signature.withUnsafeBufferPointer { signatureBytes in
            try message.withUnsafeBytes { messageBytes in
                try publicKey.withUnsafeBufferPointer { publicBytes in
                    guard
                        let signaturePointer = signatureBytes.baseAddress,
                        let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress,
                        let publicPointer = publicBytes.baseAddress
                    else {
                        throw VectorError.emptyBuffer
                    }
                    return secp256k1_verify(
                        signaturePointer,
                        messagePointer,
                        message.count,
                        publicPointer,
                        &valid
                    )
                }
            }
        }
        XCTAssertEqual(verifyStatus, 0)
        XCTAssertEqual(valid, 1)
    }

    func testLibsecp256k1Bip340Vector() throws {
        let vector: Bip340SchnorrVector = try loadVector("bip340_schnorr.json")
        let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
        let publicKey = [UInt8](try Data(base64Url: vector.publicKeyXonly))
        let message = [UInt8](try Data(base64Url: vector.message))
        let auxRand = [UInt8](try Data(base64Url: vector.auxRand))
        let expectedSignature = [UInt8](try Data(base64Url: vector.signature))

        var derivedPublicKey = [UInt8](repeating: 0, count: 32)
        let deriveStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
            guard let secretPointer = secretBytes.baseAddress else {
                throw VectorError.emptyBuffer
            }
            return bip340_schnorr_derive_public_key(secretPointer, &derivedPublicKey)
        }
        XCTAssertEqual(deriveStatus, 0)
        XCTAssertEqual(derivedPublicKey, publicKey)

        var signature = [UInt8](repeating: 0, count: 64)
        let signStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
            try message.withUnsafeBufferPointer { messageBytes in
                try auxRand.withUnsafeBufferPointer { auxBytes in
                    guard
                        let secretPointer = secretBytes.baseAddress,
                        let messagePointer = messageBytes.baseAddress,
                        let auxPointer = auxBytes.baseAddress
                    else {
                        throw VectorError.emptyBuffer
                    }
                    return bip340_schnorr_sign(
                        secretPointer,
                        messagePointer,
                        auxPointer,
                        &signature
                    )
                }
            }
        }
        XCTAssertEqual(signStatus, 0)
        XCTAssertEqual(signature, expectedSignature)

        var valid: Int32 = 0
        let verifyStatus = try expectedSignature.withUnsafeBufferPointer { signatureBytes in
            try message.withUnsafeBufferPointer { messageBytes in
                try publicKey.withUnsafeBufferPointer { publicKeyBytes in
                    guard
                        let signaturePointer = signatureBytes.baseAddress,
                        let messagePointer = messageBytes.baseAddress,
                        let publicKeyPointer = publicKeyBytes.baseAddress
                    else {
                        throw VectorError.emptyBuffer
                    }
                    return bip340_schnorr_verify(
                        signaturePointer,
                        messagePointer,
                        publicKeyPointer,
                        &valid
                    )
                }
            }
        }
        XCTAssertEqual(verifyStatus, 0)
        XCTAssertEqual(valid, 1)

        var tampered = expectedSignature
        tampered[0] ^= 0x01
        let tamperStatus = try tampered.withUnsafeBufferPointer { signatureBytes in
            try message.withUnsafeBufferPointer { messageBytes in
                try publicKey.withUnsafeBufferPointer { publicKeyBytes in
                    guard
                        let signaturePointer = signatureBytes.baseAddress,
                        let messagePointer = messageBytes.baseAddress,
                        let publicKeyPointer = publicKeyBytes.baseAddress
                    else {
                        throw VectorError.emptyBuffer
                    }
                    return bip340_schnorr_verify(
                        signaturePointer,
                        messagePointer,
                        publicKeyPointer,
                        &valid
                    )
                }
            }
        }
        XCTAssertEqual(tamperStatus, 0)
        XCTAssertEqual(valid, 0)
    }

    func testRustFfiMlDsaKnownAnswers() throws {
        // Cross-implementation KAT through the compiled native library that
        // iOS links: deterministic signing must reproduce the committed
        // signature, the committed signature must verify, and a tampered
        // signature must be rejected.
        let ffi = try RustCryptoFfi()
        try assertMlDsaKnownAnswer(
            ffi: ffi,
            vectorName: "ml_dsa_44.json",
            sign: ffi.mlDsa44Sign,
            verify: ffi.mlDsa44Verify
        )
        try assertMlDsaKnownAnswer(
            ffi: ffi,
            vectorName: "ml_dsa_65.json",
            sign: ffi.mlDsa65Sign,
            verify: ffi.mlDsa65Verify
        )
        try assertMlDsaKnownAnswer(
            ffi: ffi,
            vectorName: "ml_dsa_87.json",
            sign: ffi.mlDsa87Sign,
            verify: ffi.mlDsa87Verify
        )
    }

    private func assertMlDsaKnownAnswer(
        ffi _: RustCryptoFfi,
        vectorName: String,
        sign: ([UInt8], Data) throws -> Data,
        verify: ([UInt8], Data, [UInt8]) throws -> Void
    ) throws {
        let vector: MlDsaVector = try loadVector(vectorName)
        let secretSeed = [UInt8](try Data(base64Url: vector.secretKey))
        let publicKey = [UInt8](try Data(base64Url: vector.publicKey))
        let message = try Data(base64Url: vector.message)
        let expectedSignature = try Data(base64Url: vector.signature)

        let signature = try sign(secretSeed, message)
        XCTAssertEqual(signature, expectedSignature, "\(vectorName): signature must match the committed KAT")

        try verify(publicKey, message, [UInt8](expectedSignature))

        var tampered = [UInt8](expectedSignature)
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try verify(publicKey, message, tampered),
            "\(vectorName): tampered signature must be rejected"
        )
    }

    func testRustFfiMlKemKnownAnswer() throws {
        let ffi = try RustCryptoFfi()
        try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem512.json") {
            try ffi.mlKem512Decapsulate(ciphertext: $0, secretKey: $1)
        }
        try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem768.json") {
            try ffi.mlKem768Decapsulate(ciphertext: $0, secretKey: $1)
        }
        try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem1024.json") {
            try ffi.mlKem1024Decapsulate(ciphertext: $0, secretKey: $1)
        }
    }

    func testRustFfiXWingKnownAnswer() throws {
        let ffi = try RustCryptoFfi()
        let vectors: XWingVectors = try loadVector("x_wing.json")
        try assertXWingKnownAnswer(
            vector: vectors.xWing768,
            publicKeyLength: 1_216,
            ciphertextLength: 1_120,
            derivePublicKey: ffi.xWing768PublicKey,
            encapsulateDerand: ffi.xWing768EncapsulateDerand,
            decapsulate: ffi.xWing768Decapsulate
        )
    }

    private func assertXWingKnownAnswer(
        vector: XWingVector,
        publicKeyLength: Int,
        ciphertextLength: Int,
        derivePublicKey: ([UInt8]) throws -> Data,
        encapsulateDerand: ([UInt8], [UInt8]) throws -> (Data, Data),
        decapsulate: ([UInt8], [UInt8]) throws -> Data
    ) throws {
        let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
        let publicKey = [UInt8](try Data(base64Url: vector.publicKey))
        let encapsSeed = [UInt8](try Data(base64Url: vector.encapsSeed))
        let ciphertext = [UInt8](try Data(base64Url: vector.ciphertext))
        let sharedSecret = try Data(base64Url: vector.sharedSecret)

        XCTAssertEqual(vector.secretKeyFormat, "x-wing-seed")
        XCTAssertEqual(publicKey.count, publicKeyLength)
        XCTAssertEqual(ciphertext.count, ciphertextLength)
        XCTAssertEqual(encapsSeed.count, 64)
        XCTAssertEqual(sharedSecret.count, 32)
        XCTAssertEqual(try derivePublicKey(secretKey), Data(publicKey))

        let (derivedCiphertext, derivedSharedSecret) = try encapsulateDerand(publicKey, encapsSeed)
        XCTAssertEqual(derivedCiphertext, Data(ciphertext))
        XCTAssertEqual(derivedSharedSecret, sharedSecret)
        XCTAssertEqual(try decapsulate(ciphertext, secretKey), sharedSecret)
    }

    /// Decapsulates the committed ciphertext to the committed shared secret,
    /// and the tampered ciphertext to the committed implicit-rejection
    /// secret — the same FIPS 203 behavior the Rust and noble oracles show —
    /// exercised through the native library iOS links.
    private func assertMlKemKnownAnswer(
        ffi: RustCryptoFfi,
        vectorName: String,
        decapsulate: ([UInt8], [UInt8]) throws -> Data
    ) throws {
        let vector: MlKemVector = try loadVector(vectorName)
        let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
        let ciphertext = [UInt8](try Data(base64Url: vector.ciphertext))
        let sharedSecret = try Data(base64Url: vector.sharedSecret)
        let tamperedCiphertext = [UInt8](try Data(base64Url: vector.tamperedCiphertext))
        let tamperedSharedSecret = try Data(base64Url: vector.tamperedSharedSecret)

        XCTAssertEqual(
            try decapsulate(ciphertext, secretKey),
            sharedSecret,
            "\(vectorName): decapsulation must reproduce the committed shared secret"
        )

        let rejected = try decapsulate(tamperedCiphertext, secretKey)
        XCTAssertEqual(
            rejected,
            tamperedSharedSecret,
            "\(vectorName): implicit rejection must reproduce the committed pseudorandom secret"
        )
        XCTAssertNotEqual(
            rejected,
            sharedSecret,
            "\(vectorName): implicit rejection must not reveal the real shared secret"
        )
    }

    func testLatestSwiftProviderPackagesCompile() {
        XCTAssertEqual(
            SwiftProviderProbe.compiledProviderNames,
            ["SwiftKyber", "SwiftDilithium", "BigInt", "Digest"]
        )
    }

    func testAllVectorShapesAreLoadedAndValidated() throws {
        try validateP256Shape()
        try validateSec1EcdsaShape("p384.json", secretKeyLength: 48, compressedLength: 49, uncompressedLength: 97)
        try validateSec1EcdsaShape("p521.json", secretKeyLength: 66, compressedLength: 67, uncompressedLength: 133)
        try validateEd25519Shape()
        try validateSecp256k1Shape()
        try validateBip340SchnorrShape()
        try validateRsaShape()
        try validateX25519Shape()
        try validateMlDsaShape("ml_dsa_44.json", publicKeyLength: 1_312, signatureLength: 2_420)
        try validateMlDsaShape("ml_dsa_65.json", publicKeyLength: 1_952, signatureLength: 3_309)
        try validateMlDsaShape("ml_dsa_87.json", publicKeyLength: 2_592, signatureLength: 4_627)
        try validateSlhDsaShape()
        try validateMlKemShape("mlkem512.json", publicKeyLength: 800, secretKeyLength: 64)
        try validateMlKemShape("mlkem768.json", publicKeyLength: 1_184, secretKeyLength: 64)
        try validateMlKemShape("mlkem1024.json", publicKeyLength: 1_568, secretKeyLength: 64)
        try validateXWingShape()
        try validateHpkeShape()
        try validateAes256GcmShape()
        try validateAesKwShape(
            "aes128kw.json",
            expectedAlgorithm: "AES-128-KW",
            kekLength: 16,
            keyDataLength: 16
        )
        try validateAesKwShape(
            "aes192kw.json",
            expectedAlgorithm: "AES-192-KW",
            kekLength: 24,
            keyDataLength: 16
        )
        try validateAesKwShape(
            "aes256kw.json",
            expectedAlgorithm: "AES-256-KW",
            kekLength: 32,
            keyDataLength: 32
        )
        try validateChaCha20Poly1305Shape()
        try validateHmacShape()
        try validatePbkdf2Shape()
        try validateKmac256Shape()
        try validateHashShape()
        try validateJwkShape()
    }

    func testSwiftNativeLaneDeclaresExecutableCoverage() throws {
        let manifest: Manifest = try loadVector("manifest.json")
        let swiftLane = try XCTUnwrap(manifest.runtimeLanes.first { $0.name == "swift-native" })

        XCTAssertEqual(swiftLane.status, "executable")
        XCTAssertEqual(
            swiftLane.algorithms,
            [
                "P-256",
                "P-384",
                "P-521",
                "Ed25519",
                "secp256k1",
                "BIP-340-Schnorr",
                "RSA",
                "X25519",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "SLH-DSA-SHA2-128s",
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024",
                "X-Wing-768",
                "HPKE-P256-SHA256-AES256GCM",
                "HPKE-X25519-SHA256-CHACHA20POLY1305",
                "AES-128-GCM",
                "AES-192-GCM",
                "AES-256-GCM",
                "AES-128-KW",
                "AES-192-KW",
                "AES-256-KW",
                "ChaCha20-Poly1305",
                "HMAC-SHA-256",
                "HMAC-SHA-384",
                "HMAC-SHA-512",
                "HKDF-SHA256",
                "HKDF-SHA384",
                "JWA-CONCAT-KDF-SHA256",
                "KMAC256",
                "PBKDF2-HMAC-SHA-256",
                "PBKDF2-HMAC-SHA-512",
                "SHA2-256",
                "SHA2-384",
                "SHA2-512",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
                "JWK",
                "JWK-Multikey",
            ]
        )
        XCTAssertTrue(swiftLane.notes.contains { $0.contains("CryptoKit") })
        XCTAssertTrue(swiftLane.notes.contains { $0.contains("libsecp256k1") })
        XCTAssertTrue(swiftLane.notes.contains { $0.contains("SwiftKyber 3.5.0") })
        XCTAssertTrue(swiftLane.notes.contains { $0.contains("SwiftDilithium 3.6.0") })
        XCTAssertTrue(swiftLane.notes.contains { $0.contains("ReallyMe Rust C ABI") })
    }

    private func validateP256Shape() throws {
        let vector: P256Vector = try loadVector("p256.json")
        let secretKey = try Data(base64Url: vector.secretKey)
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
        let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
        let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
        let peerCompressedPublicKey = try Data(base64Url: vector.peerPublicKeyCompressed)
        let peerUncompressedPublicKey = try Data(base64Url: vector.peerPublicKeyUncompressed)
        let sharedSecret = try Data(base64Url: vector.sharedSecret)

        XCTAssertEqual(secretKey.count, 32)
        XCTAssertEqual(compressedPublicKey.count, 33)
        XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
        XCTAssertEqual(uncompressedPublicKey.count, 65)
        XCTAssertEqual(uncompressedPublicKey.first, 0x04)
        XCTAssertEqual(peerSecretKey.count, 32)
        XCTAssertEqual(peerCompressedPublicKey.count, 33)
        XCTAssertTrue(peerCompressedPublicKey.first == 0x02 || peerCompressedPublicKey.first == 0x03)
        XCTAssertEqual(peerUncompressedPublicKey.count, 65)
        XCTAssertEqual(peerUncompressedPublicKey.first, 0x04)
        XCTAssertEqual(sharedSecret.count, 32)
    }

    private func validateSec1EcdsaShape(
        _ vectorName: String,
        secretKeyLength: Int,
        compressedLength: Int,
        uncompressedLength: Int
    ) throws {
        let vector: Sec1EcdsaVector = try loadVector(vectorName)
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
        let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)

        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, secretKeyLength)
        XCTAssertEqual(compressedPublicKey.count, compressedLength)
        XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
        XCTAssertEqual(uncompressedPublicKey.count, uncompressedLength)
        XCTAssertEqual(uncompressedPublicKey.first, 0x04)
        XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
        XCTAssertFalse(try Data(base64Url: vector.signatureDer).isEmpty)
    }

    private func validateEd25519Shape() throws {
        let vector: Ed25519Vector = try loadVector("ed25519.json")
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
        XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.signature).count, 64)
    }

    private func validateSecp256k1Shape() throws {
        let vector: Secp256k1Vector = try loadVector("secp256k1.json")
        let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)

        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(compressedPublicKey.count, 33)
        XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
    }

    private func validateBip340SchnorrShape() throws {
        let vector: Bip340SchnorrVector = try loadVector("bip340_schnorr.json")

        XCTAssertEqual(vector.publicKeyFormat, "x-only")
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.publicKeyXonly).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.message).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.auxRand).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.signature).count, 64)
    }

    private func validateRsaShape() throws {
        let vector: RsaVector = try loadVector("rsa.json")

        XCTAssertEqual(vector.keyFormat, "PKCS1-DER-RSAPublicKey")
        XCTAssertEqual(try Data(base64Url: vector.publicKeyDer).first, 0x30)
        XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.pkcs1v15Sha1Signature).count, 256)
        XCTAssertEqual(try Data(base64Url: vector.pkcs1v15Sha256Signature).count, 256)
        XCTAssertEqual(vector.pssSha256Mgf1Sha256SaltLen, 32)
        XCTAssertEqual(try Data(base64Url: vector.pssSha256Mgf1Sha256Signature).count, 256)
    }

    private func validateX25519Shape() throws {
        let vector: X25519Vector = try loadVector("x25519.json")
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.peerSecretKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.peerPublicKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.sharedSecret).count, 32)
    }

    private func validateMlDsaShape(
        _ vectorName: String,
        publicKeyLength: Int,
        signatureLength: Int
    ) throws {
        let vector: MlDsaVector = try loadVector(vectorName)
        let publicKey = try Data(base64Url: vector.publicKey)

        XCTAssertEqual(vector.secretKeyFormat, "fips-204-seed")
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(publicKey.count, publicKeyLength)
        XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
        XCTAssertEqual(try Data(base64Url: vector.signature).count, signatureLength)
    }

    private func validateSlhDsaShape() throws {
        let vector: SlhDsaVector = try loadVector("slh_dsa_sha2_128s.json")

        XCTAssertEqual(vector.secretKeyFormat, "fips-205-serialized-secret-key")
        XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 64)
        XCTAssertEqual(try Data(base64Url: vector.keygenSkSeed).count, 16)
        XCTAssertEqual(try Data(base64Url: vector.keygenSkPrf).count, 16)
        XCTAssertEqual(try Data(base64Url: vector.keygenPkSeed).count, 16)
        XCTAssertEqual(try Data(base64Url: vector.signature).count, 7_856)
        XCTAssertEqual(vector.publicKeyLength, 32)
        XCTAssertEqual(vector.secretKeyLength, 64)
        XCTAssertEqual(vector.signatureLength, 7_856)
    }

    private func validateMlKemShape(
        _ vectorName: String,
        publicKeyLength: Int,
        secretKeyLength: Int
    ) throws {
        let vector: MlKemVector = try loadVector(vectorName)

        XCTAssertEqual(vector.secretKeyFormat, "fips-203-seed")
        XCTAssertEqual(try Data(base64Url: vector.publicKey).count, publicKeyLength)
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, secretKeyLength)
        XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
    }

    private func validateXWingShape() throws {
        let vectors: XWingVectors = try loadVector("x_wing.json")
        try validateXWingCase(vectors.xWing768, publicKeyLength: 1_216, ciphertextLength: 1_120)
    }

    private func validateXWingCase(
        _ vector: XWingVector,
        publicKeyLength: Int,
        ciphertextLength: Int
    ) throws {
        XCTAssertEqual(vector.secretKeyFormat, "x-wing-seed")
        XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.publicKey).count, publicKeyLength)
        XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
        XCTAssertEqual(try Data(base64Url: vector.encapsSeed).count, 64)
        XCTAssertEqual(try Data(base64Url: vector.ciphertext).count, ciphertextLength)
        XCTAssertEqual(vector.ciphertextLength, ciphertextLength)
        XCTAssertEqual(try Data(base64Url: vector.sharedSecret).count, 32)
    }

    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    private func openP256HpkeCase(_ vector: HpkeVector) throws {
        let privateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: try Data(base64Url: vector.recipientSecretKey)
        )
        let publicKey = try P256.KeyAgreement.PublicKey(
            try Data(base64Url: vector.recipientPublicKey),
            kem: .P256_HKDF_SHA256
        )
        XCTAssertEqual(privateKey.publicKey.x963Representation, try Data(base64Url: vector.recipientPublicKey))
        XCTAssertEqual(try publicKey.hpkeRepresentation(kem: .P256_HKDF_SHA256), try Data(base64Url: vector.recipientPublicKey))

        try openHpkeCase(
            vector,
            privateKey: privateKey,
            ciphersuite: .P256_SHA256_AES_GCM_256
        )
    }

    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    private func openX25519HpkeCase(_ vector: HpkeVector) throws {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: try Data(base64Url: vector.recipientSecretKey)
        )
        let publicKey = try Curve25519.KeyAgreement.PublicKey(
            try Data(base64Url: vector.recipientPublicKey),
            kem: .Curve25519_HKDF_SHA256
        )
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, try Data(base64Url: vector.recipientPublicKey))
        XCTAssertEqual(try publicKey.hpkeRepresentation(kem: .Curve25519_HKDF_SHA256), try Data(base64Url: vector.recipientPublicKey))

        try openHpkeCase(
            vector,
            privateKey: privateKey,
            ciphersuite: .Curve25519_SHA256_ChachaPoly
        )
    }

    @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
    private func openHpkeCase<PrivateKey: HPKEDiffieHellmanPrivateKey>(
        _ vector: HpkeVector,
        privateKey: PrivateKey,
        ciphersuite: HPKE.Ciphersuite
    ) throws {
        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: ciphersuite,
            info: try Data(base64Url: vector.info),
            encapsulatedKey: try Data(base64Url: vector.encapsulatedKey)
        )
        let opened = try recipient.open(
            try Data(base64Url: vector.ciphertext),
            authenticating: try Data(base64Url: vector.aad)
        )
        XCTAssertEqual(opened, try Data(base64Url: vector.plaintext))

        var tamperedRecipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: ciphersuite,
            info: try Data(base64Url: vector.info),
            encapsulatedKey: try Data(base64Url: vector.encapsulatedKey)
        )
        XCTAssertThrowsError(
            try tamperedRecipient.open(
                try Data(base64Url: vector.tamperedCiphertext),
                authenticating: try Data(base64Url: vector.aad)
            )
        )
    }

    private func validateHpkeShape() throws {
        let vectors: HpkeVectors = try loadVector("hpke.json")
        try validateHpkeCase(
            vectors.p256Sha256Aes256Gcm,
            kemId: 0x0010,
            kdfId: 0x0001,
            aeadId: 0x0002,
            secretKeyLength: 32,
            publicKeyLength: 65,
            encapsulatedKeyLength: 65
        )
        try validateHpkeCase(
            vectors.x25519Sha256ChaCha20Poly1305,
            kemId: 0x0020,
            kdfId: 0x0001,
            aeadId: 0x0003,
            secretKeyLength: 32,
            publicKeyLength: 32,
            encapsulatedKeyLength: 32
        )
    }

    private func validateHpkeCase(
        _ vector: HpkeVector,
        kemId: Int,
        kdfId: Int,
        aeadId: Int,
        secretKeyLength: Int,
        publicKeyLength: Int,
        encapsulatedKeyLength: Int
    ) throws {
        let plaintext = try Data(base64Url: vector.plaintext)
        let ciphertext = try Data(base64Url: vector.ciphertext)

        XCTAssertEqual(vector.mode, "base")
        XCTAssertEqual(vector.kemId, kemId)
        XCTAssertEqual(vector.kdfId, kdfId)
        XCTAssertEqual(vector.aeadId, aeadId)
        XCTAssertEqual(try Data(base64Url: vector.recipientSecretKey).count, secretKeyLength)
        XCTAssertEqual(try Data(base64Url: vector.recipientPublicKey).count, publicKeyLength)
        XCTAssertEqual(try Data(base64Url: vector.encapsSeed).count, 32)
        XCTAssertFalse(try Data(base64Url: vector.info).isEmpty)
        XCTAssertFalse(try Data(base64Url: vector.aad).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.encapsulatedKey).count, encapsulatedKeyLength)
        XCTAssertEqual(ciphertext.count, plaintext.count + 16)
        XCTAssertEqual(try Data(base64Url: vector.tamperedCiphertext).count, ciphertext.count)
    }

    private func validateAes256GcmShape() throws {
        let vector: Aes256GcmVector = try loadVector("aes256gcm.json")
        let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

        XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.nonce).count, 12)
        XCTAssertGreaterThanOrEqual(ciphertextWithTag.count, 16)
    }

    private func validateAesKwShape(
        _ vectorName: String,
        expectedAlgorithm: String,
        kekLength: Int,
        keyDataLength: Int
    ) throws {
        let vector: AesKwVector = try loadVector(vectorName)

        XCTAssertEqual(vector.alg, expectedAlgorithm)
        XCTAssertEqual(try Data(base64Url: vector.kek).count, kekLength)
        XCTAssertEqual(try Data(base64Url: vector.keyData).count, keyDataLength)
        XCTAssertEqual(try Data(base64Url: vector.wrappedKey).count, keyDataLength + 8)
    }

    private func validateKmac256Shape() throws {
        let vector: Kmac256Vector = try loadVector("kmac256.json")

        XCTAssertEqual(vector.alg, "KMAC256")
        XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
        XCTAssertFalse(try Data(base64Url: vector.context).isEmpty)
        XCTAssertFalse(try Data(base64Url: vector.customization).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.derivedKey).count, vector.outputLength)
    }

    private func validateChaCha20Poly1305Shape() throws {
        let vectors: ChaCha20Poly1305Vectors = try loadVector("chacha20poly1305.json")
        try validateChaCha20Poly1305Case(vectors.chacha20Poly1305, nonceLength: 12)
        try validateChaCha20Poly1305Case(vectors.xChaCha20Poly1305, nonceLength: 24)
    }

    private func validateChaCha20Poly1305Case(
        _ vector: ChaCha20Poly1305Vector,
        nonceLength: Int
    ) throws {
        let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

        XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.nonce).count, nonceLength)
        XCTAssertGreaterThanOrEqual(ciphertextWithTag.count, 16)
    }

    private func validateHashShape() throws {
        let vector: HashVector = try loadVector("hashes.json")
        XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.sha2_256).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.sha2_384).count, 48)
        XCTAssertEqual(try Data(base64Url: vector.sha2_512).count, 64)
        XCTAssertEqual(try Data(base64Url: vector.sha3_224).count, 28)
        XCTAssertEqual(try Data(base64Url: vector.sha3_256).count, 32)
        XCTAssertEqual(try Data(base64Url: vector.sha3_384).count, 48)
        XCTAssertEqual(try Data(base64Url: vector.sha3_512).count, 64)
    }

    private func validateHmacShape() throws {
        let vectors: HmacVectors = try loadVector("hmac.json")
        try validateHmacCase(vectors.hmacSha256, tagLength: 32)
        try validateHmacCase(vectors.hmacSha384, tagLength: 48)
        try validateHmacCase(vectors.hmacSha512, tagLength: 64)
    }

    private func validateHmacCase(_ vector: HmacVector, tagLength: Int) throws {
        XCTAssertFalse(try Data(base64Url: vector.key).isEmpty)
        XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
        XCTAssertEqual(try Data(base64Url: vector.tag).count, tagLength)
    }

    private func validatePbkdf2Shape() throws {
        let vectors: Pbkdf2Vectors = try loadVector("pbkdf2.json")
        try validatePbkdf2Case(vectors.pbkdf2HmacSha256, alg: "PBKDF2-HMAC-SHA-256", outputLength: 32)
        try validatePbkdf2Case(vectors.pbkdf2HmacSha512, alg: "PBKDF2-HMAC-SHA-512", outputLength: 64)
    }

    private func validatePbkdf2Case(_ vector: Pbkdf2Vector, alg: String, outputLength: Int) throws {
        XCTAssertEqual(vector.alg, alg)
        XCTAssertFalse(try Data(base64Url: vector.password).isEmpty)
        XCTAssertFalse(try Data(base64Url: vector.salt).isEmpty)
        XCTAssertGreaterThanOrEqual(vector.iterations, 1)
        XCTAssertEqual(vector.outputLen, outputLength)
        XCTAssertEqual(try Data(base64Url: vector.derivedKey).count, outputLength)
    }

    func testNativeJwkVectors() throws {
        let vectors: JwkVectors = try loadVector("jwk.json")
        for vector in vectors.vectors {
            let publicKey = try Data(base64Url: vector.publicKey)
            XCTAssertEqual(publicKey.count, vector.publicKeyLength)
            XCTAssertEqual(try SwiftJwk.toJcs(alg: vector.alg, publicKey: publicKey), vector.jwkJcs)
            let parsed = try SwiftJwk.fromJcs(vector.jwkJcs)
            XCTAssertEqual(parsed.alg, vector.alg)
            XCTAssertEqual(parsed.publicKey, publicKey)
            if vector.multikeyStatus == "supported" {
                XCTAssertNotNil(vector.multikey)
                XCTAssertTrue(try XCTUnwrap(vector.multikey).hasPrefix("z"))
            } else {
                XCTAssertEqual(vector.multikeyStatus, "multicodec-missing")
                XCTAssertNil(vector.multikey)
            }
        }
    }

    private func validateJwkShape() throws {
        let vectors: JwkVectors = try loadVector("jwk.json")
        let expectedAlgorithms: Set<String> = [
            "Ed25519", "X25519", "P-256", "secp256k1",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "SLH-DSA-SHA2-128s", "X-Wing-768",
        ]
        XCTAssertEqual(Set(vectors.vectors.map(\.alg)), expectedAlgorithms)
        XCTAssertEqual(vectors.vectors.count, expectedAlgorithms.count)
        for vector in vectors.vectors {
            let publicKey = try Data(base64Url: vector.publicKey)
            XCTAssertEqual(publicKey.count, vector.publicKeyLength)
            XCTAssertFalse(vector.jwkJcs.isEmpty)
        }
    }
}

private struct Manifest: Decodable {
    let vectors: [String]
    let runtimeLanes: [RuntimeLane]

    enum CodingKeys: String, CodingKey {
        case vectors
        case runtimeLanes = "runtime_lanes"
    }
}

private struct RuntimeLane: Decodable {
    let name: String
    let status: String
    let algorithms: [String]
    let notes: [String]
}

private struct P256Vector: Decodable {
    let secretKey: String
    let publicKeyCompressed: String
    let publicKeyUncompressed: String
    let peerSecretKey: String
    let peerPublicKeyCompressed: String
    let peerPublicKeyUncompressed: String
    let sharedSecret: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyCompressed = "public_key_compressed"
        case publicKeyUncompressed = "public_key_uncompressed"
        case peerSecretKey = "peer_secret_key"
        case peerPublicKeyCompressed = "peer_public_key_compressed"
        case peerPublicKeyUncompressed = "peer_public_key_uncompressed"
        case sharedSecret = "shared_secret"
    }
}

private struct Sec1EcdsaVector: Decodable {
    let secretKey: String
    let publicKeyCompressed: String
    let publicKeyUncompressed: String
    let message: String
    let signatureDer: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyCompressed = "public_key_compressed"
        case publicKeyUncompressed = "public_key_uncompressed"
        case message
        case signatureDer = "signature_der"
    }
}

private struct Ed25519Vector: Decodable {
    let secretKey: String
    let publicKey: String
    let message: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case message
        case signature
    }
}

private struct X25519Vector: Decodable {
    let secretKey: String
    let publicKey: String
    let peerSecretKey: String
    let peerPublicKey: String
    let sharedSecret: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case peerSecretKey = "peer_secret_key"
        case peerPublicKey = "peer_public_key"
        case sharedSecret = "shared_secret"
    }
}

private struct Secp256k1Vector: Decodable {
    let secretKey: String
    let publicKeyCompressed: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyCompressed = "public_key_compressed"
    }
}

private struct Bip340SchnorrVector: Decodable {
    let secretKey: String
    let publicKeyXonly: String
    let publicKeyFormat: String
    let message: String
    let auxRand: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyXonly = "public_key_xonly"
        case publicKeyFormat = "public_key_format"
        case message
        case auxRand = "aux_rand"
        case signature
    }
}

private struct RsaVector: Decodable {
    let keyFormat: String
    let publicKeyDer: String
    let message: String
    let pkcs1v15Sha1Signature: String
    let pkcs1v15Sha256Signature: String
    let pssSha256Mgf1Sha256SaltLen: Int
    let pssSha256Mgf1Sha256Signature: String

    enum CodingKeys: String, CodingKey {
        case keyFormat = "key_format"
        case publicKeyDer = "public_key_der"
        case message
        case pkcs1v15Sha1Signature = "pkcs1v15_sha1_signature"
        case pkcs1v15Sha256Signature = "pkcs1v15_sha256_signature"
        case pssSha256Mgf1Sha256SaltLen = "pss_sha256_mgf1_sha256_salt_len"
        case pssSha256Mgf1Sha256Signature = "pss_sha256_mgf1_sha256_signature"
    }
}

private struct MlDsaVector: Decodable {
    let secretKeyFormat: String
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let message: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case secretKeyFormat = "secret_key_format"
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case message
        case signature
    }
}

private struct SlhDsaVector: Decodable {
    let secretKeyFormat: String
    let keygenSkSeed: String
    let keygenSkPrf: String
    let keygenPkSeed: String
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let secretKeyLength: Int
    let message: String
    let signature: String
    let signatureLength: Int

    enum CodingKeys: String, CodingKey {
        case secretKeyFormat = "secret_key_format"
        case keygenSkSeed = "keygen_sk_seed"
        case keygenSkPrf = "keygen_sk_prf"
        case keygenPkSeed = "keygen_pk_seed"
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case secretKeyLength = "secret_key_length"
        case message
        case signature
        case signatureLength = "signature_length"
    }
}

private struct MlKemVector: Decodable {
    let secretKeyFormat: String
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let ciphertext: String
    let sharedSecret: String
    let tamperedCiphertext: String
    let tamperedSharedSecret: String

    enum CodingKeys: String, CodingKey {
        case secretKeyFormat = "secret_key_format"
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case ciphertext
        case sharedSecret = "shared_secret"
        case tamperedCiphertext = "tampered_ciphertext"
        case tamperedSharedSecret = "tampered_shared_secret"
    }
}

private struct XWingVectors: Decodable {
    let xWing768: XWingVector

    enum CodingKeys: String, CodingKey {
        case xWing768 = "x_wing_768"
    }
}

private struct XWingVector: Decodable {
    let secretKeyFormat: String
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let encapsSeed: String
    let ciphertext: String
    let ciphertextLength: Int
    let sharedSecret: String

    enum CodingKeys: String, CodingKey {
        case secretKeyFormat = "secret_key_format"
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case encapsSeed = "encaps_seed"
        case ciphertext
        case ciphertextLength = "ciphertext_length"
        case sharedSecret = "shared_secret"
    }
}

private struct HpkeVectors: Decodable {
    let p256Sha256Aes256Gcm: HpkeVector
    let x25519Sha256ChaCha20Poly1305: HpkeVector

    enum CodingKeys: String, CodingKey {
        case p256Sha256Aes256Gcm = "p256_sha256_aes256gcm"
        case x25519Sha256ChaCha20Poly1305 = "x25519_sha256_chacha20poly1305"
    }
}

private struct HpkeVector: Decodable {
    let alg: String
    let mode: String
    let kemId: Int
    let kdfId: Int
    let aeadId: Int
    let recipientSecretKey: String
    let recipientPublicKey: String
    let encapsSeed: String
    let info: String
    let aad: String
    let plaintext: String
    let encapsulatedKey: String
    let ciphertext: String
    let tamperedCiphertext: String

    enum CodingKeys: String, CodingKey {
        case alg
        case mode
        case kemId = "kem_id"
        case kdfId = "kdf_id"
        case aeadId = "aead_id"
        case recipientSecretKey = "recipient_secret_key"
        case recipientPublicKey = "recipient_public_key"
        case encapsSeed = "encaps_seed"
        case info
        case aad
        case plaintext
        case encapsulatedKey = "encapsulated_key"
        case ciphertext
        case tamperedCiphertext = "tampered_ciphertext"
    }
}

private struct Aes256GcmVector: Decodable {
    let key: String
    let nonce: String
    let aad: String
    let plaintext: String
    let ciphertextWithTag: String

    enum CodingKeys: String, CodingKey {
        case key
        case nonce
        case aad
        case plaintext
        case ciphertextWithTag = "ciphertext_with_tag"
    }
}

private struct AesKwVector: Decodable {
    let alg: String
    let kek: String
    let keyData: String
    let wrappedKey: String

    enum CodingKeys: String, CodingKey {
        case alg
        case kek
        case keyData = "key_data"
        case wrappedKey = "wrapped_key"
    }
}

private struct Kmac256Vector: Decodable {
    let alg: String
    let key: String
    let context: String
    let customization: String
    let outputLength: Int
    let derivedKey: String

    enum CodingKeys: String, CodingKey {
        case alg
        case key
        case context
        case customization
        case outputLength = "output_length"
        case derivedKey = "derived_key"
    }
}

private struct ChaCha20Poly1305Vectors: Decodable {
    let chacha20Poly1305: ChaCha20Poly1305Vector
    let xChaCha20Poly1305: ChaCha20Poly1305Vector

    enum CodingKeys: String, CodingKey {
        case chacha20Poly1305 = "chacha20_poly1305"
        case xChaCha20Poly1305 = "xchacha20_poly1305"
    }
}

private struct ChaCha20Poly1305Vector: Decodable {
    let key: String
    let nonce: String
    let aad: String
    let plaintext: String
    let ciphertextWithTag: String

    enum CodingKeys: String, CodingKey {
        case key
        case nonce
        case aad
        case plaintext
        case ciphertextWithTag = "ciphertext_with_tag"
    }
}

private struct HashVector: Decodable {
    let message: String
    let sha2_256: String
    let sha2_384: String
    let sha2_512: String
    let sha3_224: String
    let sha3_256: String
    let sha3_384: String
    let sha3_512: String
}

private struct HmacVectors: Decodable {
    let hmacSha256: HmacVector
    let hmacSha384: HmacVector
    let hmacSha512: HmacVector

    enum CodingKeys: String, CodingKey {
        case hmacSha256 = "hmac_sha256"
        case hmacSha384 = "hmac_sha384"
        case hmacSha512 = "hmac_sha512"
    }
}

private struct HkdfVector: Decodable {
    let alg: String
    let hash: String
    let ikm: String
    let salt: String
    let info: String
    let outputLen: Int
    let okm: String

    enum CodingKeys: String, CodingKey {
        case alg
        case hash
        case ikm
        case salt
        case info
        case outputLen = "output_len"
        case okm
    }
}

private struct HmacVector: Decodable {
    let key: String
    let message: String
    let tag: String
}

private struct Pbkdf2Vectors: Decodable {
    let pbkdf2HmacSha256: Pbkdf2Vector
    let pbkdf2HmacSha512: Pbkdf2Vector

    enum CodingKeys: String, CodingKey {
        case pbkdf2HmacSha256 = "pbkdf2_hmac_sha256"
        case pbkdf2HmacSha512 = "pbkdf2_hmac_sha512"
    }
}

private struct Pbkdf2Vector: Decodable {
    let alg: String
    let password: String
    let salt: String
    let iterations: Int
    let outputLen: Int
    let derivedKey: String

    enum CodingKeys: String, CodingKey {
        case alg
        case password
        case salt
        case iterations
        case outputLen = "output_len"
        case derivedKey = "derived_key"
    }
}

private struct JwkVectors: Decodable {
    let vectors: [JwkVector]
}

private struct JwkVector: Decodable {
    let alg: String
    let publicKey: String
    let publicKeyLength: Int
    let jwkJcs: String
    let multikey: String?
    let multikeyStatus: String

    enum CodingKeys: String, CodingKey {
        case alg
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case jwkJcs = "jwk_jcs"
        case multikey
        case multikeyStatus = "multikey_status"
    }
}

private struct SwiftJwkSpec {
    let alg: String
    let crv: String
    let kty: String
    let keyUse: String
    let publicKeyLength: Int
}

private struct ParsedJwk {
    let alg: String
    let publicKey: Data
}

private enum SwiftJwk {
    static func toJcs(alg: String, publicKey: Data) throws -> String {
        let spec = try spec(for: alg)
        guard publicKey.count == spec.publicKeyLength else {
            throw VectorError.invalidField
        }

        if spec.kty == "EC" {
            let uncompressed = try decompressEcPublicKey(alg: alg, publicKey: publicKey)
            let x = uncompressed.subdata(in: 1..<33).base64UrlEncodedString()
            let y = uncompressed.subdata(in: 33..<65).base64UrlEncodedString()
            return try #"{"alg":\#(jsonString(spec.alg)),"crv":\#(jsonString(spec.crv)),"kty":"EC","use":"sig","x":\#(jsonString(x)),"y":\#(jsonString(y))}"#
        }

        let encodedPublicKey = publicKey.base64UrlEncodedString()
        if spec.kty == "AKP" {
            return try #"{"alg":\#(jsonString(spec.alg)),"kty":"AKP","pub":\#(jsonString(encodedPublicKey)),"use":\#(jsonString(spec.keyUse))}"#
        }
        return try #"{"alg":\#(jsonString(spec.alg)),"crv":\#(jsonString(spec.crv)),"kty":"OKP","use":\#(jsonString(spec.keyUse)),"x":\#(jsonString(encodedPublicKey))}"#
    }

    static func fromJcs(_ value: String) throws -> ParsedJwk {
        guard let data = value.data(using: .utf8) else {
            throw VectorError.invalidField
        }
        let object = try JSONSerialization.jsonObject(with: data)
        guard
            let jwk = object as? [String: Any],
            let kty = jwk["kty"] as? String
        else {
            throw VectorError.invalidField
        }
        let keyIdentifier: String
        let publicKeyMember: String
        if kty == "AKP" {
            guard
                let alg = jwk["alg"] as? String,
                let encodedPublicKey = jwk["pub"] as? String
            else {
                throw VectorError.invalidField
            }
            keyIdentifier = alg
            publicKeyMember = encodedPublicKey
        } else {
            guard
                let crv = jwk["crv"] as? String,
                let encodedPublicKey = jwk["x"] as? String
            else {
                throw VectorError.invalidField
            }
            keyIdentifier = crv
            publicKeyMember = encodedPublicKey
        }
        let spec = try spec(for: keyIdentifier)
        guard
            kty == spec.kty,
            (jwk["alg"] as? String) == spec.alg,
            (jwk["use"] as? String) == spec.keyUse
        else {
            throw VectorError.invalidField
        }

        if spec.kty == "EC" {
            guard let y = jwk["y"] as? String else {
                throw VectorError.invalidField
            }
            let compressed = try compressEcPublicKey(
                alg: keyIdentifier,
                x: Data(base64Url: publicKeyMember),
                y: Data(base64Url: y)
            )
            return ParsedJwk(alg: keyIdentifier, publicKey: compressed)
        }

        let publicKey = try Data(base64Url: publicKeyMember)
        guard publicKey.count == spec.publicKeyLength else {
            throw VectorError.invalidField
        }
        return ParsedJwk(alg: keyIdentifier, publicKey: publicKey)
    }

    private static func spec(for alg: String) throws -> SwiftJwkSpec {
        switch alg {
        case "Ed25519":
            return SwiftJwkSpec(alg: "EdDSA", crv: "Ed25519", kty: "OKP", keyUse: "sig", publicKeyLength: 32)
        case "X25519":
            return SwiftJwkSpec(alg: "ECDH-ES", crv: "X25519", kty: "OKP", keyUse: "enc", publicKeyLength: 32)
        case "P-256":
            return SwiftJwkSpec(alg: "ES256", crv: "P-256", kty: "EC", keyUse: "sig", publicKeyLength: 33)
        case "secp256k1":
            return SwiftJwkSpec(alg: "ES256K", crv: "secp256k1", kty: "EC", keyUse: "sig", publicKeyLength: 33)
        case "ML-DSA-44":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 1_312)
        case "ML-DSA-65":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 1_952)
        case "ML-DSA-87":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 2_592)
        case "ML-KEM-512":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 800)
        case "ML-KEM-768":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_184)
        case "ML-KEM-1024":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_568)
        case "SLH-DSA-SHA2-128s":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 32)
        case "X-Wing-768":
            return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_216)
        default:
            throw VectorError.invalidField
        }
    }

    private static func decompressEcPublicKey(alg: String, publicKey: Data) throws -> Data {
        if alg == "P-256" {
            return try P256.Signing.PublicKey(compressedRepresentation: publicKey).x963Representation
        }

        guard alg == "secp256k1" else {
            throw VectorError.invalidField
        }

        var x = [UInt8](repeating: 0, count: 32)
        var y = [UInt8](repeating: 0, count: 32)
        let compressed = [UInt8](publicKey)
        let status = compressed.withUnsafeBytes { publicBytes in
            guard let publicPointer = publicBytes.bindMemory(to: UInt8.self).baseAddress else {
                return Int32(-128)
            }
            return secp256k1_decompress_public_key(publicPointer, &x, &y)
        }
        guard status == 0 else {
            throw VectorError.invalidField
        }

        var uncompressed = Data([0x04])
        uncompressed.append(contentsOf: x)
        uncompressed.append(contentsOf: y)
        return uncompressed
    }

    private static func compressEcPublicKey(alg: String, x: Data, y: Data) throws -> Data {
        guard x.count == 32, y.count == 32 else {
            throw VectorError.invalidField
        }
        var uncompressed = Data([0x04])
        uncompressed.append(x)
        uncompressed.append(y)

        if alg == "P-256" {
            return try P256.Signing.PublicKey(x963Representation: uncompressed).compressedRepresentation
        }

        guard alg == "secp256k1" else {
            throw VectorError.invalidField
        }

        let yLast = try XCTUnwrap(y.last)
        var compressed = Data([yLast & 1 == 0 ? 0x02 : 0x03])
        compressed.append(x)
        let roundTrip = try decompressEcPublicKey(alg: alg, publicKey: compressed)
        guard roundTrip == uncompressed else {
            throw VectorError.invalidField
        }
        return compressed
    }

    private static func jsonString(_ value: String) throws -> String {
        let data = try JSONEncoder().encode(value)
        guard let encoded = String(data: data, encoding: .utf8) else {
            throw VectorError.invalidField
        }
        return encoded
    }
}

private enum VectorError: Error {
    case repositoryRootNotFound
    case invalidBase64Url
    case emptyBuffer
    case invalidField
}

private func loadVector<T: Decodable>(_ name: String) throws -> T {
    let data = try Data(contentsOf: vectorsDirectory().appendingPathComponent(name))
    return try JSONDecoder().decode(T.self, from: data)
}

private func vectorsDirectory() throws -> URL {
    if let override = ProcessInfo.processInfo.environment["REALLYME_CRYPTO_VECTORS_DIR"] {
        return URL(fileURLWithPath: override, isDirectory: true)
    }

    var cursor = URL(fileURLWithPath: #filePath)
    while cursor.path != "/" {
        let candidate = cursor
            .appendingPathComponent("vectors", isDirectory: true)
            .appendingPathComponent("manifest.json")
        if FileManager.default.fileExists(atPath: candidate.path) {
            return candidate.deletingLastPathComponent()
        }
        cursor.deleteLastPathComponent()
    }

    throw VectorError.repositoryRootNotFound
}

private extension Data {
    init(base64Url: String) throws {
        var value = base64Url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder != 0 {
            value.append(String(repeating: "=", count: 4 - remainder))
        }

        guard let data = Data(base64Encoded: value) else {
            throw VectorError.invalidBase64Url
        }
        self = data
    }

    func base64UrlEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

private extension SharedSecret {
    var rawBytes: Data {
        withUnsafeBytes { bytes in
            Data(bytes)
        }
    }
}
