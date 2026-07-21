// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

private struct AesGcmVector: Decodable {
    let alg: String
    let key: String
    let nonce: String
    let aad: String
    let plaintext: String
    let ciphertextWithTag: String

    private enum CodingKeys: String, CodingKey {
        case alg
        case key
        case nonce
        case aad
        case plaintext
        case ciphertextWithTag = "ciphertext_with_tag"
    }
}

private struct ConcatKdfVector: Decodable {
    let sharedSecret: String
    let algorithmId: String
    let partyUInfo: String
    let partyVInfo: String
    let outputLen: Int
    let derivedKey: String

    private enum CodingKeys: String, CodingKey {
        case sharedSecret = "shared_secret"
        case algorithmId = "algorithm_id"
        case partyUInfo = "party_u_info"
        case partyVInfo = "party_v_info"
        case outputLen = "output_len"
        case derivedKey = "derived_key"
    }
}

extension ReallyMeCryptoTests {
    func testProviderCatalogIsExplicit() {
        XCTAssertEqual(
            ReallyMeCryptoProviderCatalog.compiledProviders,
            [
                .cryptoKit,
                .secureEnclaveKeychain,
                .cSecp256k1,
                .digest,
                .rustCAbi,
            ]
        )
    }

    func testDefaultProviderReportsBundledRustCAbiState() {
        let providers = ReallyMeCryptoProviders.default

        if ReallyMeRustCAbiLibrary.isBundledProviderAvailable {
            XCTAssertNotNil(providers.rustCAbiLibrary)
            XCTAssertNil(providers.rustCAbiDiagnostic)
        } else {
            XCTAssertNil(providers.rustCAbiLibrary)
            XCTAssertEqual(providers.rustCAbiDiagnostic, .bundledProviderNotLinked)
        }
    }

    func testExplicitProviderContextFailsClosedWithoutRustProvider() {
        let crypto = ReallyMeCrypto(providers: ReallyMeCryptoProviders())
        let empty = [UInt8]()

        XCTAssertThrowsError(
            try crypto.seal(.aes256GcmSiv, key: empty, nonce: empty, aad: empty, plaintext: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.wrapKey(.aes256Kw, wrappingKey: empty, keyToWrap: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.deriveKey(.argon2id, password: empty, salt: empty, iterations: 1, outputLength: 32)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try crypto.deriveArgon2idKey(kdfVersion: 1, secret: empty, salt: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.verify(
                .rsaPkcs1v15Sha256,
                signature: empty,
                message: empty,
                publicKeyDer: empty,
                publicKeyEncoding: .pkcs1
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.sign(.bip340SchnorrSecp256k1Sha256, message: empty, secretKey: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try crypto.sign(
                .bip340SchnorrSecp256k1Sha256,
                message32: empty,
                secretKey: empty,
                auxRand32: empty
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.deriveKeyPair(.ed25519, secretKey: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
        XCTAssertThrowsError(
            try crypto.deriveXWingKeyPair(.xWing768, secretKey: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
    }

    func testConfiguredProviderContextPreservesAppleNativeSemantics() throws {
        let crypto = ReallyMeCrypto()
        let key = try Self.base64UrlBytes(Self.aes256GcmKeyBase64Url)
        let nonce = try Self.base64UrlBytes(Self.aes256GcmNonceBase64Url)
        let aad = try Self.base64UrlBytes(Self.aes256GcmAadBase64Url)
        let plaintext = try Self.base64UrlBytes(Self.aes256GcmPlaintextBase64Url)
        let ciphertext = try Self.base64UrlBytes(Self.aes256GcmCiphertextWithTagBase64Url)

        XCTAssertEqual(
            try crypto.seal(.aes256Gcm, key: key, nonce: nonce, aad: aad, plaintext: plaintext),
            try ReallyMeCrypto.seal(.aes256Gcm, key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        )
        XCTAssertEqual(
            try crypto.open(.aes256Gcm, key: key, nonce: nonce, aad: aad, ciphertextWithTag: ciphertext),
            plaintext
        )

        XCTAssertThrowsError(
            try crypto.seal(.aes256Gcm, key: [0x00], nonce: nonce, aad: aad, plaintext: plaintext)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try crypto.open(.aes256Gcm, key: key, nonce: nonce, aad: aad, ciphertextWithTag: tampered)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
    }

    func testConfiguredProviderContextRoutesRustBackedAlgorithmsWhenConfigured() throws {
        let library = try ReallyMeCryptoRustCAbiTests.configuredRustCAbiLibrary()
        let crypto = ReallyMeCrypto(providers: ReallyMeCryptoProviders(rustCAbiLibrary: library))
        let key = try Self.base64UrlBytes("MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8")
        let nonce = try Self.base64UrlBytes("0NHS09TV1tfY2drb")
        let aad = try Self.base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWdjbS1zaXYtdmVjdG9yLWFhZA")
        let plaintext = try Self.base64UrlBytes("UmVhbGx5TWUgQUVTLTI1Ni1HQ00tU0lWIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        let ciphertext = try Self.base64UrlBytes(
            "830aIA-5lFFihlRNK2QIUHoFRAQXaaBqX2nDndhvyVq-EcnpsGqtqHVZC1bTdM8kugkvV_o3Ve9HQq4"
        )

        XCTAssertEqual(
            try crypto.seal(.aes256GcmSiv, key: key, nonce: nonce, aad: aad, plaintext: plaintext),
            ciphertext
        )
        XCTAssertEqual(
            try crypto.seal(.aes256GcmSiv, key: key, nonce: nonce, aad: aad, plaintext: plaintext),
            try ReallyMeCrypto.seal(
                .aes256GcmSiv,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext,
                rustCAbiLibrary: library
            )
        )
        XCTAssertEqual(
            try crypto.open(.aes256GcmSiv, key: key, nonce: nonce, aad: aad, ciphertextWithTag: ciphertext),
            plaintext
        )
        XCTAssertThrowsError(
            try crypto.seal(.aes256GcmSiv, key: Array(key.dropLast()), nonce: nonce, aad: aad, plaintext: plaintext)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try crypto.open(.aes256GcmSiv, key: key, nonce: nonce, aad: aad, ciphertextWithTag: tampered)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertEqual(
            try crypto.deriveArgon2idKey(
                kdfVersion: 1,
                secret: Array("password".utf8),
                salt: Array("somesaltvalue1234".utf8)
            ),
            Self.bytes("53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757")
        )

        let rsaPublicKeyDer = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.rsaPublicKeyDerBase64Url)
        let rsaMessage = try Self.base64UrlBytes("UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        let rsaSignature = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.rsaPkcs1Sha256SignatureBase64Url)
        try crypto.verify(
            .rsaPkcs1v15Sha256,
            signature: rsaSignature,
            message: rsaMessage,
            publicKeyDer: rsaPublicKeyDer,
            publicKeyEncoding: .pkcs1
        )
        var tamperedRsaSignature = rsaSignature
        tamperedRsaSignature[0] ^= 0x01
        XCTAssertThrowsError(
            try crypto.verify(
                .rsaPkcs1v15Sha256,
                signature: tamperedRsaSignature,
                message: rsaMessage,
                publicKeyDer: rsaPublicKeyDer,
                publicKeyEncoding: .pkcs1
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        let bip340SecretKey = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.bip340SecretKeyBase64Url)
        let bip340PublicKey = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.bip340PublicKeyBase64Url)
        let bip340Message = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.bip340MessageBase64Url)
        let bip340AuxRand = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.bip340AuxRandBase64Url)
        let bip340Signature = try Self.base64UrlBytes(ReallyMeCryptoRustCAbiTests.bip340SignatureBase64Url)
        XCTAssertEqual(try crypto.deriveBip340SchnorrPublicKey(secretKey: bip340SecretKey), bip340PublicKey)
        XCTAssertEqual(
            try crypto.sign(
                .bip340SchnorrSecp256k1Sha256,
                message32: bip340Message,
                secretKey: bip340SecretKey,
                auxRand32: bip340AuxRand
            ),
            bip340Signature
        )
        try crypto.verify(
            .bip340SchnorrSecp256k1Sha256,
            signature: bip340Signature,
            message: bip340Message,
            publicKey: bip340PublicKey
        )

        let ed25519SecretKey = Self.bytes(
            "9b712355c46a089f4182701852cdef4322116da07e394abcd85f132692a1be77"
        )
        let ed25519PublicKey = Self.bytes(
            "6ddffbec369caae216a5fb99080a6ce013799d8bea00d39804d7a90d73502d82"
        )
        let ed25519KeyPair = try crypto.deriveKeyPair(.ed25519, secretKey: ed25519SecretKey)
        XCTAssertEqual(ed25519KeyPair.publicKey, ed25519PublicKey)
        XCTAssertEqual(ed25519KeyPair.secretKey, ed25519SecretKey)

        let p384Vector = try ReallyMeCryptoRustCAbiTests.loadEcdsaCurveVector("p384.json")
        let p521Vector = try ReallyMeCryptoRustCAbiTests.loadEcdsaCurveVector("p521.json")
        let ecdsaCases: [(ReallyMeSignatureAlgorithm, [UInt8], [UInt8], [UInt8], [UInt8], Int, Int)] = [
            (
                .ecdsaP256Sha256,
                ReallyMeCryptoRustCAbiTests.p256EcdsaSecretKey,
                ReallyMeCryptoRustCAbiTests.p256EcdsaPublicKey,
                ReallyMeCryptoRustCAbiTests.p256EcdsaMessage,
                ReallyMeCryptoRustCAbiTests.p256EcdsaSignatureDer,
                33,
                32
            ),
            (
                .ecdsaP384Sha384,
                try Self.base64UrlBytes(p384Vector.secretKey),
                try Self.base64UrlBytes(p384Vector.publicKeyCompressed),
                try Self.base64UrlBytes(p384Vector.message),
                try Self.base64UrlBytes(p384Vector.signatureDer),
                49,
                48
            ),
            (
                .ecdsaP521Sha512,
                try Self.base64UrlBytes(p521Vector.secretKey),
                try Self.base64UrlBytes(p521Vector.publicKeyCompressed),
                try Self.base64UrlBytes(p521Vector.message),
                try Self.base64UrlBytes(p521Vector.signatureDer),
                67,
                66
            ),
        ]

        for ecdsaCase in ecdsaCases {
            let (algorithm, secretKey, publicKey, message, expectedSignature, publicKeyLength, secretKeyLength) =
                ecdsaCase
            let derivedKeyPair = try crypto.deriveKeyPair(algorithm, secretKey: secretKey)
            XCTAssertEqual(derivedKeyPair.publicKey, publicKey, algorithm.rawValue)
            XCTAssertEqual(derivedKeyPair.secretKey, secretKey, algorithm.rawValue)
            let signature = try crypto.sign(algorithm, message: message, secretKey: secretKey)
            XCTAssertEqual(signature, expectedSignature, algorithm.rawValue)
            XCTAssertEqual(signature.first, UInt8(0x30), algorithm.rawValue)
            try crypto.verify(algorithm, signature: signature, message: message, publicKey: publicKey)

            let generatedKeyPair = try crypto.generateKeyPair(algorithm)
            XCTAssertEqual(generatedKeyPair.publicKey.count, publicKeyLength, algorithm.rawValue)
            XCTAssertEqual(generatedKeyPair.secretKey.count, secretKeyLength, algorithm.rawValue)
            let generatedSignature = try crypto.sign(
                algorithm,
                message: message,
                secretKey: generatedKeyPair.secretKey
            )
            XCTAssertEqual(generatedSignature.first, UInt8(0x30), algorithm.rawValue)
            try crypto.verify(
                algorithm,
                signature: generatedSignature,
                message: message,
                publicKey: generatedKeyPair.publicKey
            )
        }

        let xWingVector = try ReallyMeCryptoRustCAbiTests.loadXWingVectors().xWing768
        let xWingSecretKey = try Self.base64UrlBytes(xWingVector.secretKey)
        let xWingPublicKey = try Self.base64UrlBytes(xWingVector.publicKey)
        let xWingCiphertext = try Self.base64UrlBytes(xWingVector.ciphertext)
        let xWingSharedSecret = try Self.base64UrlBytes(xWingVector.sharedSecret)
        let xWingKeyPair = try crypto.deriveXWingKeyPair(.xWing768, secretKey: xWingSecretKey)
        XCTAssertEqual(xWingKeyPair.publicKey, xWingPublicKey)
        XCTAssertEqual(xWingKeyPair.secretKey, xWingSecretKey)

        XCTAssertEqual(
            try crypto.decapsulate(
                .xWing768,
                ciphertext: xWingCiphertext,
                secretKey: xWingSecretKey
            ),
            xWingSharedSecret
        )
        let xWingEncapsulation = try crypto.encapsulate(.xWing768, publicKey: xWingPublicKey)
        XCTAssertEqual(
            try crypto.decapsulate(
                .xWing768,
                ciphertext: xWingEncapsulation.ciphertext,
                secretKey: xWingSecretKey
            ),
            xWingEncapsulation.sharedSecret
        )
    }

    func testSha256KnownAnswer() {
        let digest = ReallyMeDigest.sha256(Array("abc".utf8))
        XCTAssertEqual(
            digest.map { String(format: "%02x", $0) }.joined(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testGenericFacadeHashesSupportedSha2() throws {
        let bytes = Array("abc".utf8)

        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha2_256, bytes),
            ReallyMeDigest.sha256(bytes)
        )
        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha2_384, bytes),
            ReallyMeDigest.sha384(bytes)
        )
        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha2_512, bytes),
            ReallyMeDigest.sha512(bytes)
        )
    }

    func testGenericFacadeHashesSupportedSha3KnownAnswers() throws {
        let bytes = Array("abc".utf8)

        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha3_224, bytes).map { String(format: "%02x", $0) }.joined(),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        )
        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha3_256, bytes).map { String(format: "%02x", $0) }.joined(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha3_384, bytes).map { String(format: "%02x", $0) }.joined(),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
                + "98d88cea927ac7f539f1edf228376d25"
        )
        XCTAssertEqual(
            try ReallyMeCrypto.hash(.sha3_512, bytes).map { String(format: "%02x", $0) }.joined(),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
    }

    // HMAC key/message/tags are vectors/hmac.json (RFC 4231 test case 1) —
    // the same KAT the conformance lanes prove.
    func testGenericFacadeHmacKnownAnswers() throws {
        let key = Self.bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let message = Self.bytes("4869205468657265")
        let sha256Tag = try ReallyMeCrypto.authenticate(
            .hmacSha256,
            key: key,
            message: message
        )
        let sha384Tag = try ReallyMeCrypto.authenticate(
            .hmacSha384,
            key: key,
            message: message
        )
        let sha512Tag = try ReallyMeCrypto.authenticate(
            .hmacSha512,
            key: key,
            message: message
        )

        XCTAssertEqual(
            sha384Tag,
            Self.bytes(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                    + "faea9ea9076ede7f4af152e8b2fa9cb6"
            )
        )
        XCTAssertEqual(
            sha256Tag,
            Self.bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        )
        XCTAssertEqual(
            sha512Tag,
            Self.bytes(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd"
                    + "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            )
        )
        XCTAssertTrue(
            try ReallyMeCrypto.verifyMac(.hmacSha384, tag: sha384Tag, key: key, message: message)
        )
        XCTAssertTrue(
            try ReallyMeCrypto.verifyMac(.hmacSha256, tag: sha256Tag, key: key, message: message)
        )
        XCTAssertTrue(
            try ReallyMeCrypto.verifyMac(.hmacSha512, tag: sha512Tag, key: key, message: message)
        )
    }

    func testGenericFacadeHmacRejectsInvalidInputAndTampering() throws {
        let key = Self.bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let message = Self.bytes("4869205468657265")
        var tag = try ReallyMeCrypto.authenticate(.hmacSha256, key: key, message: message)
        tag[0] ^= 0x01

        XCTAssertFalse(
            try ReallyMeCrypto.verifyMac(.hmacSha256, tag: tag, key: key, message: message)
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.authenticate(.hmacSha256, key: [], message: message)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verifyMac(.hmacSha256, tag: [0x00], key: key, message: message)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testGenericFacadeAes256GcmKnownAnswerAndTampering() throws {
        let key = try Self.base64UrlBytes(Self.aes256GcmKeyBase64Url)
        let nonce = try Self.base64UrlBytes(Self.aes256GcmNonceBase64Url)
        let aad = try Self.base64UrlBytes(Self.aes256GcmAadBase64Url)
        let plaintext = try Self.base64UrlBytes(Self.aes256GcmPlaintextBase64Url)
        let ciphertext = try Self.base64UrlBytes(Self.aes256GcmCiphertextWithTagBase64Url)

        XCTAssertEqual(
            try ReallyMeCrypto.seal(
                .aes256Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            ),
            ciphertext
        )
        XCTAssertEqual(
            try ReallyMeCrypto.open(
                .aes256Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertext
            ),
            plaintext
        )

        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .aes256Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: tampered
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.seal(
                .aes256Gcm,
                key: [0x00],
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testGenericFacadeAes128GcmKnownAnswerAndTampering() throws {
        let data = try Data(contentsOf: reallyMeVectorURL("aes128gcm.json"))
        let vector = try JSONDecoder().decode(AesGcmVector.self, from: data)
        XCTAssertEqual(vector.alg, "AES-128-GCM")

        let key = try Self.base64UrlBytes(vector.key)
        let nonce = try Self.base64UrlBytes(vector.nonce)
        let aad = try Self.base64UrlBytes(vector.aad)
        let plaintext = try Self.base64UrlBytes(vector.plaintext)
        let ciphertext = try Self.base64UrlBytes(vector.ciphertextWithTag)

        XCTAssertEqual(
            try ReallyMeCrypto.seal(
                .aes128Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            ),
            ciphertext
        )
        XCTAssertEqual(
            try ReallyMeCrypto.open(
                .aes128Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertext
            ),
            plaintext
        )

        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .aes128Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: tampered
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.seal(
                .aes128Gcm,
                key: [UInt8](repeating: 0, count: ReallyMeAesGcm.aes256KeyLength),
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testGenericFacadeAes192GcmKnownAnswerAndTampering() throws {
        let data = try Data(contentsOf: reallyMeVectorURL("aes192gcm.json"))
        let vector = try JSONDecoder().decode(AesGcmVector.self, from: data)
        XCTAssertEqual(vector.alg, "AES-192-GCM")

        let key = try Self.base64UrlBytes(vector.key)
        let nonce = try Self.base64UrlBytes(vector.nonce)
        let aad = try Self.base64UrlBytes(vector.aad)
        let plaintext = try Self.base64UrlBytes(vector.plaintext)
        let ciphertext = try Self.base64UrlBytes(vector.ciphertextWithTag)

        XCTAssertEqual(
            try ReallyMeCrypto.seal(
                .aes192Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            ),
            ciphertext
        )
        XCTAssertEqual(
            try ReallyMeCrypto.open(
                .aes192Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertext
            ),
            plaintext
        )

        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .aes192Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: tampered
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .aes192Gcm,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: [UInt8](repeating: 0, count: ReallyMeAesGcm.tagLength - 1)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.seal(
                .aes192Gcm,
                key: [UInt8](repeating: 0, count: ReallyMeAesGcm.aes128KeyLength),
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testGenericFacadeChaCha20Poly1305KnownAnswerAndTampering() throws {
        let key = try Self.base64UrlBytes(Self.chacha20Poly1305KeyBase64Url)
        let nonce = try Self.base64UrlBytes(Self.chacha20Poly1305NonceBase64Url)
        let aad = try Self.base64UrlBytes(Self.chacha20Poly1305AadBase64Url)
        let plaintext = try Self.base64UrlBytes(Self.chacha20Poly1305PlaintextBase64Url)
        let ciphertext = try Self.base64UrlBytes(Self.chacha20Poly1305CiphertextWithTagBase64Url)

        XCTAssertEqual(
            try ReallyMeCrypto.seal(
                .chacha20Poly1305,
                key: key,
                nonce: nonce,
                aad: aad,
                plaintext: plaintext
            ),
            ciphertext
        )
        XCTAssertEqual(
            try ReallyMeCrypto.open(
                .chacha20Poly1305,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: ciphertext
            ),
            plaintext
        )

        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .chacha20Poly1305,
                key: key,
                nonce: nonce,
                aad: aad,
                ciphertextWithTag: tampered
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.open(
                .chacha20Poly1305,
                key: key,
                nonce: [0x00],
                aad: aad,
                ciphertextWithTag: ciphertext
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testGenericFacadePbkdf2KnownAnswers() throws {
        let password = Array("password".utf8)
        let salt = Array("salt".utf8)

        XCTAssertEqual(
            try ReallyMeCrypto.deriveKey(
                .pbkdf2HmacSha256,
                password: password,
                salt: salt,
                iterations: 100_000,
                outputLength: 32
            ),
            Self.bytes("0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5")
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveKey(
                .pbkdf2HmacSha512,
                password: password,
                salt: salt,
                iterations: 100_000,
                outputLength: 64
            ),
            Self.bytes(
                "f5d17022c96af46c0a1dc49a58bbe654a28e98104883e4af4de974cda2c74122"
                    + "dd082f4105a93fc80692ca4eb1a784cfeda81bfaa33f5192cc9143d818bd7581"
            )
        )
    }

    func testGenericFacadePbkdf2RejectsInvalidInputsAndUnsupportedKdf() {
        let salt = Array("salt".utf8)
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKey(
                .pbkdf2HmacSha256,
                password: [],
                salt: salt,
                iterations: 100_000,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKey(
                .pbkdf2HmacSha256,
                password: Array("password".utf8),
                salt: [],
                iterations: 100_000,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKey(
                .pbkdf2HmacSha256,
                password: Array("password".utf8),
                salt: salt,
                iterations: 0,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKey(
                .hkdfSha256,
                password: Array("password".utf8),
                salt: salt,
                iterations: 1,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testGenericFacadeHkdfKnownAnswer() throws {
        let inputKeyMaterial = Self.bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = Self.bytes("000102030405060708090a0b0c")
        let info = Self.bytes("f0f1f2f3f4f5f6f7f8f9")

        XCTAssertEqual(
            try ReallyMeCrypto.deriveHkdf(
                .hkdfSha256,
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                info: info,
                outputLength: 42
            ),
            Self.bytes(
                "3cb25f25faacd57a90434f64d0362f2a"
                    + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    + "34007208d5b887185865"
            )
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveHkdf(
                .hkdfSha384,
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                info: info,
                outputLength: 42
            ),
            Self.bytes(
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7"
                    + "48b6457763e4f0204fc5"
            )
        )
    }

    func testGenericFacadeHkdfRejectsInvalidInputsAndUnsupportedKdf() {
        let salt = Self.bytes("000102030405060708090a0b0c")
        let info = Self.bytes("f0f1f2f3f4f5f6f7f8f9")

        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveHkdf(
                .hkdfSha256,
                inputKeyMaterial: [],
                salt: salt,
                info: info,
                outputLength: 42
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveHkdf(
                .hkdfSha256,
                inputKeyMaterial: Self.bytes("0b"),
                salt: salt,
                info: info,
                outputLength: 0
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveHkdf(
                .pbkdf2HmacSha256,
                inputKeyMaterial: Self.bytes("0b"),
                salt: salt,
                info: info,
                outputLength: 42
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testGenericFacadeJwaConcatKdfMatchesSharedVector() throws {
        let data = try Data(contentsOf: reallyMeVectorURL("concat_kdf.json"))
        let vector = try JSONDecoder().decode(ConcatKdfVector.self, from: data)
        let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)
        let algorithmId = try Self.base64UrlBytes(vector.algorithmId)
        let partyUInfo = try Self.base64UrlBytes(vector.partyUInfo)
        let partyVInfo = try Self.base64UrlBytes(vector.partyVInfo)
        let derivedKey = try Self.base64UrlBytes(vector.derivedKey)

        XCTAssertEqual(
            try ReallyMeJwaConcatKdf.deriveSha256(
                sharedSecret: sharedSecret,
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: vector.outputLen
            ),
            derivedKey
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                .jwaConcatKdfSha256,
                sharedSecret: sharedSecret,
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: vector.outputLen
            ),
            derivedKey
        )
    }

    func testGenericFacadeJwaConcatKdfRejectsInvalidInputsAndUnsupportedKdf() throws {
        let data = try Data(contentsOf: reallyMeVectorURL("concat_kdf.json"))
        let vector = try JSONDecoder().decode(ConcatKdfVector.self, from: data)
        let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)
        let algorithmId = try Self.base64UrlBytes(vector.algorithmId)
        let partyUInfo = try Self.base64UrlBytes(vector.partyUInfo)
        let partyVInfo = try Self.base64UrlBytes(vector.partyVInfo)

        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                .jwaConcatKdfSha256,
                sharedSecret: [],
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: vector.outputLen
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                .jwaConcatKdfSha256,
                sharedSecret: sharedSecret,
                algorithmId: [],
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: vector.outputLen
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                .jwaConcatKdfSha256,
                sharedSecret: sharedSecret,
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: 0
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                .hkdfSha256,
                sharedSecret: sharedSecret,
                algorithmId: algorithmId,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                outputLength: vector.outputLen
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testGenericFacadeRemainingFamiliesReturnTypedUnsupportedAlgorithm() {
        let empty = [UInt8]()

        XCTAssertThrowsError(
            try ReallyMeCrypto.seal(.aes256GcmSiv, key: empty, nonce: empty, aad: empty, plaintext: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.wrapKey(.aes256Kw, wrappingKey: empty, keyToWrap: empty)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(try ReallyMeCrypto.generateKemKeyPair(.mlKem768)) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sealHpke(
                .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
                recipientPublicKey: empty,
                info: empty,
                aad: empty,
                plaintext: empty
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testGenericFacadeSupportedAlgorithmSetsAreExplicit() {
        XCTAssertEqual(
            Set(ReallyMeHashAlgorithm.allCases),
            [.sha2_256, .sha2_384, .sha2_512, .sha3_224, .sha3_256, .sha3_384, .sha3_512]
        )
        XCTAssertEqual(
            Set(ReallyMeMacAlgorithm.allCases),
            [.hmacSha256, .hmacSha384, .hmacSha512]
        )
        XCTAssertEqual(
            Set(ReallyMeKeyAgreementAlgorithm.allCases),
            [.x25519, .p256Ecdh, .p384Ecdh, .p521Ecdh]
        )
    }

    func testGenericFacadeUnsupportedSignaturesAreExhaustive() {
        let empty = [UInt8]()
        let supported: Set<ReallyMeSignatureAlgorithm> = [.ecdsaSecp256k1Sha256]

        for algorithm in ReallyMeSignatureAlgorithm.allCases where !supported.contains(algorithm) {
            XCTAssertThrowsError(try ReallyMeCrypto.generateKeyPair(algorithm), algorithm.rawValue) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.sign(algorithm, message: empty, secretKey: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.verify(algorithm, signature: empty, message: empty, publicKey: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }
    }

    func testGenericFacadeUnsupportedReservedFamiliesAreExhaustive() {
        let empty = [UInt8]()
        let unsupportedAeadAlgorithms: Set<ReallyMeAeadAlgorithm> = [
            .aes256GcmSiv,
            .xchacha20Poly1305,
        ]

        for algorithm in ReallyMeAeadAlgorithm.allCases where unsupportedAeadAlgorithms.contains(algorithm) {
            XCTAssertThrowsError(
                try ReallyMeCrypto.seal(algorithm, key: empty, nonce: empty, aad: empty, plaintext: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.open(algorithm, key: empty, nonce: empty, aad: empty, ciphertextWithTag: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }

        for algorithm in ReallyMeKemAlgorithm.allCases {
            XCTAssertThrowsError(try ReallyMeCrypto.generateKemKeyPair(algorithm), algorithm.rawValue) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(try ReallyMeCrypto.encapsulate(algorithm, publicKey: empty), algorithm.rawValue) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.decapsulate(algorithm, ciphertext: empty, secretKey: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }

        for algorithm in ReallyMeKeyWrapAlgorithm.allCases {
            XCTAssertThrowsError(
                try ReallyMeCrypto.wrapKey(algorithm, wrappingKey: empty, keyToWrap: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.unwrapKey(algorithm, wrappingKey: empty, wrappedKey: empty),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }

        for suite in ReallyMeHpkeSuite.allCases {
            XCTAssertThrowsError(
                try ReallyMeCrypto.sealHpke(
                    suite,
                    recipientPublicKey: empty,
                    info: empty,
                    aad: empty,
                    plaintext: empty
                ),
                suite.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
            XCTAssertThrowsError(
                try ReallyMeCrypto.openHpke(
                    suite,
                    recipientSecretKey: empty,
                    encapsulatedKey: empty,
                    info: empty,
                    aad: empty,
                    ciphertext: empty
                ),
                suite.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }
    }

    func testGenericFacadeUnsupportedKdfRoutesAreExhaustive() {
        let empty = [UInt8]()
        let deriveKeySupported: Set<ReallyMeKdfAlgorithm> = [.pbkdf2HmacSha256, .pbkdf2HmacSha512]
        let deriveHkdfSupported: Set<ReallyMeKdfAlgorithm> = [.hkdfSha256, .hkdfSha384]
        let deriveJwaConcatSupported: Set<ReallyMeKdfAlgorithm> = [.jwaConcatKdfSha256]

        for algorithm in ReallyMeKdfAlgorithm.allCases where !deriveKeySupported.contains(algorithm) {
            XCTAssertThrowsError(
                try ReallyMeCrypto.deriveKey(
                    algorithm,
                    password: empty,
                    salt: empty,
                    iterations: 1,
                    outputLength: 1
                ),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }

        for algorithm in ReallyMeKdfAlgorithm.allCases where !deriveHkdfSupported.contains(algorithm) {
            XCTAssertThrowsError(
                try ReallyMeCrypto.deriveHkdf(
                    algorithm,
                    inputKeyMaterial: empty,
                    salt: empty,
                    info: empty,
                    outputLength: 1
                ),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }

        for algorithm in ReallyMeKdfAlgorithm.allCases where !deriveJwaConcatSupported.contains(algorithm) {
            XCTAssertThrowsError(
                try ReallyMeCrypto.deriveJwaConcatKdfSha256(
                    algorithm,
                    sharedSecret: empty,
                    algorithmId: empty,
                    partyUInfo: empty,
                    partyVInfo: empty,
                    outputLength: 1
                ),
                algorithm.rawValue
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
            }
        }
    }

    func testMissingRustAbiLibraryReturnsTypedError() {
        XCTAssertThrowsError(try ReallyMeRustCAbiLibrary(path: "/tmp/reallyme-crypto-missing.dylib")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .dynamicLibraryNotFound)
        }
    }

    func testRustAbiLibraryRejectsRelativePath() {
        XCTAssertThrowsError(try ReallyMeRustCAbiLibrary(path: "libcrypto_ffi.dylib")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }
}
