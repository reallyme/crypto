// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoRustCAbiTests {
    func testRustCAbiStatusMappingIsTyped() {
        XCTAssertNoThrow(try ReallyMeRustCAbiStatus.throwIfError(ReallyMeRustCAbiStatus.ok))
        XCTAssertThrowsError(
            try ReallyMeRustCAbiStatus.throwIfError(ReallyMeRustCAbiStatus.invalidArgument)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeRustCAbiStatus.throwIfError(ReallyMeRustCAbiStatus.authenticationFailed)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
        XCTAssertThrowsError(
            try ReallyMeRustCAbiStatus.throwIfError(ReallyMeRustCAbiStatus.internalError)
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }
    }

    func testRustCAbiAesKwKnownAnswerWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let vectors: [(ReallyMeKeyWrapAlgorithm, String, String)] = [
            (
                .aes128Kw,
                "aes128kw.json",
                "AES-128-KW"
            ),
            (
                .aes192Kw,
                "aes192kw.json",
                "AES-192-KW"
            ),
            (
                .aes256Kw,
                "aes256kw.json",
                "AES-256-KW"
            ),
        ]

        for (algorithm, vectorName, expectedAlgorithm) in vectors {
            let vector = try Self.loadAesKwVector(vectorName)
            let kek = try Self.base64UrlBytes(vector.kek)
            let keyData = try Self.base64UrlBytes(vector.keyData)
            let expectedWrapped = try Self.base64UrlBytes(vector.wrappedKey)

            XCTAssertEqual(vector.alg, expectedAlgorithm)
            let wrapped = try ReallyMeCrypto.wrapKey(
                algorithm,
                wrappingKey: kek,
                keyToWrap: keyData,
                rustCAbiLibrary: library
            )
            XCTAssertEqual(wrapped.count, keyData.count + 8)
            XCTAssertEqual(wrapped, expectedWrapped)
            let unwrapped = try ReallyMeCrypto.unwrapKey(
                algorithm,
                wrappingKey: kek,
                wrappedKey: wrapped,
                rustCAbiLibrary: library
            )
            XCTAssertEqual(unwrapped.count, wrapped.count - 8)
            XCTAssertEqual(unwrapped, keyData)

            var tampered = wrapped
            tampered[0] ^= 0x01
            XCTAssertThrowsError(
                try ReallyMeCrypto.unwrapKey(
                    algorithm,
                    wrappingKey: kek,
                    wrappedKey: tampered,
                    rustCAbiLibrary: library
                )
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
            }
        }

    }

    func testRustCAbiKmac256KnownAnswerWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let vector = try Self.loadKmac256Vector()
        let key = try Self.base64UrlBytes(vector.key)
        let context = try Self.base64UrlBytes(vector.context)
        let customization = try Self.base64UrlBytes(vector.customization)
        let expected = try Self.base64UrlBytes(vector.derivedKey)

        XCTAssertEqual(vector.alg, "KMAC256")
        XCTAssertEqual(
            try ReallyMeCrypto.deriveKmac256(
                .kmac256,
                key: key,
                context: context,
                customization: customization,
                outputLength: vector.outputLength,
                rustCAbiLibrary: library
            ),
            expected
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKmac256(
                .kmac256,
                key: Array(key.dropLast()),
                context: context,
                customization: customization,
                outputLength: vector.outputLength,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKmac256(
                .kmac256,
                key: key,
                context: [UInt8](repeating: 0, count: 65_537),
                customization: customization,
                outputLength: vector.outputLength,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testRustCAbiAeadKnownAnswersWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        try assertRustCAbiAeadRoundTrip(
            algorithm: .aes256GcmSiv,
            library: library,
            key: Self.base64UrlBytes("MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8"),
            nonce: Self.base64UrlBytes("0NHS09TV1tfY2drb"),
            aad: Self.base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWdjbS1zaXYtdmVjdG9yLWFhZA"),
            plaintext: Self.base64UrlBytes("UmVhbGx5TWUgQUVTLTI1Ni1HQ00tU0lWIGNvbmZvcm1hbmNlIHZlY3Rvcg"),
            ciphertext: Self.base64UrlBytes(
                "830aIA-5lFFihlRNK2QIUHoFRAQXaaBqX2nDndhvyVq-EcnpsGqtqHVZC1bTdM8kugkvV_o3Ve9HQq4"
            )
        )
        try assertRustCAbiAeadRoundTrip(
            algorithm: .xchacha20Poly1305,
            library: library,
            key: Self.base64UrlBytes("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"),
            nonce: Self.base64UrlBytes("sLGys7S1tre4ubq7vL2-v8DBwsPExcbH"),
            aad: Self.base64UrlBytes("cmVhbGx5bWUtY3J5cHRvLWNoYWNoYS12ZWN0b3ItYWFk"),
            plaintext: Self.base64UrlBytes("UmVhbGx5TWUgQ2hhQ2hhMjAtUG9seTEzMDUgY29uZm9ybWFuY2UgdmVjdG9y"),
            ciphertext: Self.base64UrlBytes(
                "PaGz1pCJhIoCzTRgbz_xBf2PIGFhWUpptCP_BgisAl_zRTk565yv62NWfuEFOpomXSETJ68qwZAH1Zjoxg"
            )
        )
    }

    func testRustCAbiArgon2idVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let secret = Array("password".utf8)
        let salt = Array("somesaltvalue1234".utf8)

        XCTAssertEqual(
            try ReallyMeCrypto.deriveArgon2idKey(
                kdfVersion: 1,
                secret: secret,
                salt: salt,
                rustCAbiLibrary: library
            ),
            Self.bytes("53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757")
        )
        // Shared conformance vector (vectors/argon2id.json), V1 profile.
        XCTAssertEqual(
            try ReallyMeCrypto.deriveArgon2idKey(
                kdfVersion: 1,
                secret: Array("ReallyMe Argon2id conformance secret".utf8),
                salt: Self.bytes("e0e1e2e3e4e5e6e7e8e9eaebecedeeef"),
                rustCAbiLibrary: library
            ),
            Self.bytes("abc73241d7488428a41b4bf94510cc41327de1f67c0d7547be9f1c4cb400c2b0")
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveArgon2idKey(
                kdfVersion: 1,
                secret: [],
                salt: salt,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveArgon2idKey(
                kdfVersion: 1,
                secret: secret,
                salt: Array(salt.prefix(15)),
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveArgon2idKey(
                kdfVersion: 99,
                secret: secret,
                salt: salt,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testRustCAbiEd25519KnownAnswerWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let secretKey = Self.bytes(
            "9b712355c46a089f4182701852cdef4322116da07e394abcd85f132692a1be77"
        )
        let publicKey = Self.bytes(
            "6ddffbec369caae216a5fb99080a6ce013799d8bea00d39804d7a90d73502d82"
        )
        let message = Self.bytes(
            "5265616c6c794d65207369676e617475726520636f6e666f726d616e636520766563746f72"
        )
        let expectedSignature = Self.bytes(
            "69d360b839583ce3632021e8ca6b382533f68e8c53f4996cd84dfda548273659"
                + "3646588752e7d8d22a84cdccdc4cb84e6b8c781e672745aca5ace2443cccde03"
        )

        let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
            .ed25519,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, publicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        let signature = try ReallyMeCrypto.sign(
            .ed25519,
            message: message,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            .ed25519,
            signature: signature,
            message: message,
            publicKey: publicKey,
            rustCAbiLibrary: library
        )

        var tampered = signature
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ed25519,
                signature: tampered,
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        let keyPair = try ReallyMeCrypto.generateKeyPair(.ed25519, rustCAbiLibrary: library)
        XCTAssertEqual(keyPair.publicKey.count, 32)
        XCTAssertEqual(keyPair.secretKey.count, 32)
        let freshSignature = try ReallyMeCrypto.sign(
            .ed25519,
            message: message,
            secretKey: keyPair.secretKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ed25519,
            signature: freshSignature,
            message: message,
            publicKey: keyPair.publicKey,
            rustCAbiLibrary: library
        )
    }

    func testRustCAbiBip340SchnorrVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let secretKey = try Self.base64UrlBytes(Self.bip340SecretKeyBase64Url)
        let publicKey = try Self.base64UrlBytes(Self.bip340PublicKeyBase64Url)
        let message = try Self.base64UrlBytes(Self.bip340MessageBase64Url)
        let auxRand = try Self.base64UrlBytes(Self.bip340AuxRandBase64Url)
        let expectedSignature = try Self.base64UrlBytes(Self.bip340SignatureBase64Url)

        XCTAssertEqual(
            try ReallyMeCrypto.deriveBip340SchnorrPublicKey(
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            publicKey
        )
        let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
            .bip340SchnorrSecp256k1Sha256,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, publicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        let signature = try ReallyMeCrypto.sign(
            .bip340SchnorrSecp256k1Sha256,
            message32: message,
            secretKey: secretKey,
            auxRand32: auxRand,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            .bip340SchnorrSecp256k1Sha256,
            signature: signature,
            message: message,
            publicKey: publicKey,
            rustCAbiLibrary: library
        )

        var tampered = signature
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .bip340SchnorrSecp256k1Sha256,
                signature: tampered,
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                .bip340SchnorrSecp256k1Sha256,
                message32: message,
                secretKey: secretKey,
                auxRand32: [0x00],
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testRustCAbiRsaVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let publicKeyDer = try Self.base64UrlBytes(Self.rsaPublicKeyDerBase64Url)
        let message = try Self.base64UrlBytes("UmVhbGx5TWUgc2lnbmF0dXJlIGNvbmZvcm1hbmNlIHZlY3Rvcg")
        let pkcs1Sha1Signature = try Self.base64UrlBytes(Self.rsaPkcs1Sha1SignatureBase64Url)
        let pkcs1Sha256Signature = try Self.base64UrlBytes(Self.rsaPkcs1Sha256SignatureBase64Url)
        let pssSha256Signature = try Self.base64UrlBytes(Self.rsaPssSha256SignatureBase64Url)

        try ReallyMeCrypto.verify(
            .rsaPkcs1v15Sha1,
            signature: pkcs1Sha1Signature,
            message: message,
            publicKeyDer: publicKeyDer,
            publicKeyEncoding: .pkcs1,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .rsaPkcs1v15Sha256,
            signature: pkcs1Sha256Signature,
            message: message,
            publicKeyDer: publicKeyDer,
            publicKeyEncoding: .pkcs1,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .rsaPssSha256Mgf1Sha256,
            signature: pssSha256Signature,
            message: message,
            publicKeyDer: publicKeyDer,
            publicKeyEncoding: .pkcs1,
            rustCAbiLibrary: library
        )

        // Remaining committed RSA digests from vectors/rsa.json. Each must
        // verify through the ABI and reject a one-bit tamper.
        let additionalCases: [(ReallyMeSignatureAlgorithm, [UInt8])] = [
            (.rsaPkcs1v15Sha384, try Self.base64UrlBytes(Self.rsaPkcs1Sha384SignatureBase64Url)),
            (.rsaPkcs1v15Sha512, try Self.base64UrlBytes(Self.rsaPkcs1Sha512SignatureBase64Url)),
            (.rsaPssSha1Mgf1Sha1, try Self.base64UrlBytes(Self.rsaPssSha1SignatureBase64Url)),
            (.rsaPssSha384Mgf1Sha384, try Self.base64UrlBytes(Self.rsaPssSha384SignatureBase64Url)),
            (.rsaPssSha512Mgf1Sha512, try Self.base64UrlBytes(Self.rsaPssSha512SignatureBase64Url)),
        ]
        for (algorithm, signature) in additionalCases {
            try ReallyMeCrypto.verify(
                algorithm,
                signature: signature,
                message: message,
                publicKeyDer: publicKeyDer,
                publicKeyEncoding: .pkcs1,
                rustCAbiLibrary: library
            )
            var tamperedCase = signature
            tamperedCase[0] ^= 0x01
            XCTAssertThrowsError(
                try ReallyMeCrypto.verify(
                    algorithm,
                    signature: tamperedCase,
                    message: message,
                    publicKeyDer: publicKeyDer,
                    publicKeyEncoding: .pkcs1,
                    rustCAbiLibrary: library
                ),
                String(describing: algorithm)
            ) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
            }
        }

        var tampered = pkcs1Sha256Signature
        tampered[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .rsaPkcs1v15Sha256,
                signature: tampered,
                message: message,
                publicKeyDer: publicKeyDer,
                publicKeyEncoding: .pkcs1,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
    }

    func testRustCAbiHpkeVectorsWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        try Self.assertHpkeOpenVector(
            suite: .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
            recipientSecretKey: Self.hpkeP256RecipientSecretKeyBase64Url,
            recipientPublicKey: Self.hpkeP256RecipientPublicKeyBase64Url,
            encapsulatedKey: Self.hpkeP256EncapsulatedKeyBase64Url,
            ciphertext: Self.hpkeP256CiphertextBase64Url,
            tamperedCiphertext: Self.hpkeP256TamperedCiphertextBase64Url,
            library: library
        )
        try Self.assertHpkeOpenVector(
            suite: .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipientSecretKey: Self.hpkeX25519RecipientSecretKeyBase64Url,
            recipientPublicKey: Self.hpkeX25519RecipientPublicKeyBase64Url,
            encapsulatedKey: Self.hpkeX25519EncapsulatedKeyBase64Url,
            ciphertext: Self.hpkeX25519CiphertextBase64Url,
            tamperedCiphertext: Self.hpkeX25519TamperedCiphertextBase64Url,
            library: library
        )
    }
}

private func assertRustCAbiAeadRoundTrip(
    algorithm: ReallyMeAeadAlgorithm,
    library: ReallyMeRustCAbiLibrary,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8],
    plaintext: [UInt8],
    ciphertext: [UInt8]
) throws {
    XCTAssertEqual(
        try ReallyMeCrypto.seal(
            algorithm,
            key: key,
            nonce: nonce,
            aad: aad,
            plaintext: plaintext,
            rustCAbiLibrary: library
        ),
        ciphertext
    )
    XCTAssertEqual(
        try ReallyMeCrypto.open(
            algorithm,
            key: key,
            nonce: nonce,
            aad: aad,
            ciphertextWithTag: ciphertext,
            rustCAbiLibrary: library
        ),
        plaintext
    )

    var tampered = ciphertext
    tampered[0] ^= 0x01
    XCTAssertThrowsError(
        try ReallyMeCrypto.open(
            algorithm,
            key: key,
            nonce: nonce,
            aad: aad,
            ciphertextWithTag: tampered,
            rustCAbiLibrary: library
        )
    ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
    }
}
