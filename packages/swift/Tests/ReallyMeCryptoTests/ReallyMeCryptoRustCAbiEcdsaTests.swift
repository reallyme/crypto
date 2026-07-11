// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoRustCAbiTests {
    func testRustCAbiP256EcdsaVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()

        let signature = try ReallyMeCrypto.sign(
            .ecdsaP256Sha256,
            message: Self.p256EcdsaMessage,
            secretKey: Self.p256EcdsaSecretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, Self.p256EcdsaSignatureDer)
        let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
            .ecdsaP256Sha256,
            secretKey: Self.p256EcdsaSecretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, Self.p256EcdsaPublicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, Self.p256EcdsaSecretKey)
        try ReallyMeCrypto.verify(
            .ecdsaP256Sha256,
            signature: signature,
            message: Self.p256EcdsaMessage,
            publicKey: Self.p256EcdsaPublicKey,
            rustCAbiLibrary: library
        )

        var tampered = signature
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP256Sha256,
                signature: tampered,
                message: Self.p256EcdsaMessage,
                publicKey: Self.p256EcdsaPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                .ecdsaP256Sha256,
                message: Self.p256EcdsaMessage,
                secretKey: [0x01, 0x02],
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP256Sha256,
                signature: [0x30, 0x01],
                message: Self.p256EcdsaMessage,
                publicKey: Self.p256EcdsaPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP256Sha256, rustCAbiLibrary: library)
        XCTAssertEqual(keyPair.publicKey.count, 33)
        XCTAssertEqual(keyPair.secretKey.count, 32)
        let freshSignature = try ReallyMeCrypto.sign(
            .ecdsaP256Sha256,
            message: Self.p256EcdsaMessage,
            secretKey: keyPair.secretKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ecdsaP256Sha256,
            signature: freshSignature,
            message: Self.p256EcdsaMessage,
            publicKey: keyPair.publicKey,
            rustCAbiLibrary: library
        )
    }

    func testRustCAbiP384EcdsaVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let vector = try Self.loadEcdsaCurveVector("p384.json")
        let secretKey = try Self.base64UrlBytes(vector.secretKey)
        let compressedPublicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
        let uncompressedPublicKey = try Self.base64UrlBytes(vector.publicKeyUncompressed)
        let message = try Self.base64UrlBytes(vector.message)
        let expectedSignature = try Self.base64UrlBytes(vector.signatureDer)

        XCTAssertEqual(secretKey.count, 48)
        XCTAssertEqual(compressedPublicKey.count, 49)
        XCTAssertEqual(uncompressedPublicKey.count, 97)

        let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
            .ecdsaP384Sha384,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, compressedPublicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        let signature = try ReallyMeCrypto.sign(
            .ecdsaP384Sha384,
            message: message,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            .ecdsaP384Sha384,
            signature: signature,
            message: message,
            publicKey: compressedPublicKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ecdsaP384Sha384,
            signature: signature,
            message: message,
            publicKey: uncompressedPublicKey,
            rustCAbiLibrary: library
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP384Sha384,
                signature: signature,
                message: message + [0x00],
                publicKey: compressedPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                .ecdsaP384Sha384,
                message: message,
                secretKey: [0x01, 0x02],
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP384Sha384,
                signature: [0x30, 0x01],
                message: message,
                publicKey: compressedPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP384Sha384, rustCAbiLibrary: library)
        XCTAssertEqual(keyPair.publicKey.count, 49)
        XCTAssertEqual(keyPair.secretKey.count, 48)
        let freshSignature = try ReallyMeCrypto.sign(
            .ecdsaP384Sha384,
            message: message,
            secretKey: keyPair.secretKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ecdsaP384Sha384,
            signature: freshSignature,
            message: message,
            publicKey: keyPair.publicKey,
            rustCAbiLibrary: library
        )
    }

    func testRustCAbiP521EcdsaVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let vector = try Self.loadEcdsaCurveVector("p521.json")
        let secretKey = try Self.base64UrlBytes(vector.secretKey)
        let compressedPublicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
        let uncompressedPublicKey = try Self.base64UrlBytes(vector.publicKeyUncompressed)
        let message = try Self.base64UrlBytes(vector.message)
        let expectedSignature = try Self.base64UrlBytes(vector.signatureDer)

        XCTAssertEqual(secretKey.count, 66)
        XCTAssertEqual(compressedPublicKey.count, 67)
        XCTAssertEqual(uncompressedPublicKey.count, 133)

        let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
            .ecdsaP521Sha512,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, compressedPublicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        let signature = try ReallyMeCrypto.sign(
            .ecdsaP521Sha512,
            message: message,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            .ecdsaP521Sha512,
            signature: signature,
            message: message,
            publicKey: compressedPublicKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ecdsaP521Sha512,
            signature: signature,
            message: message,
            publicKey: uncompressedPublicKey,
            rustCAbiLibrary: library
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP521Sha512,
                signature: signature,
                message: message + [0x00],
                publicKey: compressedPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                .ecdsaP521Sha512,
                message: message,
                secretKey: [0x01, 0x02],
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .ecdsaP521Sha512,
                signature: [0x30, 0x01],
                message: message,
                publicKey: compressedPublicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP521Sha512, rustCAbiLibrary: library)
        XCTAssertEqual(keyPair.publicKey.count, 67)
        XCTAssertEqual(keyPair.secretKey.count, 66)
        let freshSignature = try ReallyMeCrypto.sign(
            .ecdsaP521Sha512,
            message: message,
            secretKey: keyPair.secretKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            .ecdsaP521Sha512,
            signature: freshSignature,
            message: message,
            publicKey: keyPair.publicKey,
            rustCAbiLibrary: library
        )
    }
}
