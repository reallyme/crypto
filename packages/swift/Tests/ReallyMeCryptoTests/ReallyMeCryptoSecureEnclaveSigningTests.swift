// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
    func testP256SecureEnclaveSigningHandleEncodingAndValidation() throws {
        XCTAssertEqual(ReallyMeP256SecureEnclaveEcdsa.signatureDerMaxLength, 72)
        let tag = Array("me.really.crypto.tests.p256.signing".utf8)
        let handle = try ReallyMeP256SecureEnclaveEcdsa.encodePrivateKeyHandle(tag: tag)

        XCTAssertEqual(try ReallyMeP256SecureEnclaveEcdsa.decodePrivateKeyHandle(handle), tag)
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdsa.encodePrivateKeyHandle(tag: [])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdsa.encodePrivateKeyHandle(
                tag: [UInt8](repeating: 0x41, count: ReallyMeP256SecureEnclaveEcdsa.maxTagLength + 1)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdsa.decodePrivateKeyHandle(Array("SE:not-signing".utf8))
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.signWithPrivateKeyHandle(
                .ecdsaP384Sha384,
                message: [],
                privateKeyHandle: handle
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testP256SecureEnclaveVerifierAcceptsDerSignatureVector() throws {
        try ReallyMeP256SecureEnclaveEcdsa.verify(
            signature: ReallyMeCryptoRustCAbiTests.p256EcdsaSignatureDer,
            message: ReallyMeCryptoRustCAbiTests.p256EcdsaMessage,
            publicKey: ReallyMeCryptoRustCAbiTests.p256EcdsaPublicKey
        )
        try ReallyMeCrypto.verifySecureEnclaveSignature(
            .ecdsaP256Sha256,
            signature: ReallyMeCryptoRustCAbiTests.p256EcdsaSignatureDer,
            message: ReallyMeCryptoRustCAbiTests.p256EcdsaMessage,
            publicKey: ReallyMeCryptoRustCAbiTests.p256EcdsaPublicKey
        )

        var tamperedSignature = ReallyMeCryptoRustCAbiTests.p256EcdsaSignatureDer
        tamperedSignature[tamperedSignature.count - 1] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdsa.verify(
                signature: tamperedSignature,
                message: ReallyMeCryptoRustCAbiTests.p256EcdsaMessage,
                publicKey: ReallyMeCryptoRustCAbiTests.p256EcdsaPublicKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verifySecureEnclaveSignature(
                .ecdsaP384Sha384,
                signature: [],
                message: [],
                publicKey: []
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testP256SecureEnclaveSigningRoundTripWhenAvailable() throws {
        let tag = Array("me.really.crypto.tests.p256.signing.\(UUID().uuidString)".utf8)
        let keyPair: ReallyMeSignatureHandleKeyPair
        do {
            keyPair = try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
                .ecdsaP256Sha256,
                tag: tag,
                accessControl: .privateKeyUsage,
                overwriteExisting: true
            )
        } catch ReallyMeCryptoError.unsupportedPlatform {
            throw XCTSkip("Secure Enclave signing is not available on this test platform")
        } catch ReallyMeCryptoError.providerFailure {
            throw XCTSkip("Secure Enclave signing is not available to this test process")
        }
        defer {
            try? ReallyMeCrypto.deleteSecureEnclaveSigningKey(
                .ecdsaP256Sha256,
                privateKeyHandle: keyPair.privateKeyHandle
            )
        }

        let message = Array("ReallyMe Secure Enclave signing test".utf8)
        XCTAssertEqual(
            try ReallyMeCrypto.deriveSecureEnclaveSigningPublicKey(
                .ecdsaP256Sha256,
                privateKeyHandle: keyPair.privateKeyHandle
            ),
            keyPair.publicKey
        )

        let signature = try ReallyMeCrypto.signWithPrivateKeyHandle(
            .ecdsaP256Sha256,
            message: message,
            privateKeyHandle: keyPair.privateKeyHandle
        )
        XCTAssertEqual(keyPair.publicKey.count, ReallyMeP256SecureEnclaveEcdsa.compressedPublicKeyLength)
        XCTAssertEqual(signature.first, UInt8(0x30))
        try ReallyMeCrypto.verifySecureEnclaveSignature(
            .ecdsaP256Sha256,
            signature: signature,
            message: message,
            publicKey: keyPair.publicKey
        )
    }

    func testP256SecureEnclaveSigningRejectsDuplicateTagWhenAvailable() throws {
        let tag = Array("me.really.crypto.tests.p256.signing.duplicate.\(UUID().uuidString)".utf8)
        let keyPair: ReallyMeSignatureHandleKeyPair
        do {
            keyPair = try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
                .ecdsaP256Sha256,
                tag: tag,
                accessControl: .privateKeyUsage,
                overwriteExisting: true
            )
        } catch ReallyMeCryptoError.unsupportedPlatform {
            throw XCTSkip("Secure Enclave signing is not available on this test platform")
        } catch ReallyMeCryptoError.providerFailure {
            throw XCTSkip("Secure Enclave signing is not available to this test process")
        }
        defer {
            try? ReallyMeCrypto.deleteSecureEnclaveSigningKey(
                .ecdsaP256Sha256,
                privateKeyHandle: keyPair.privateKeyHandle
            )
        }

        XCTAssertThrowsError(
            try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
                .ecdsaP256Sha256,
                tag: tag,
                accessControl: .privateKeyUsage,
                overwriteExisting: false
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        let replacement = try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
            .ecdsaP256Sha256,
            tag: tag,
            accessControl: .privateKeyUsage,
            overwriteExisting: true
        )
        XCTAssertEqual(
            replacement.publicKey.count,
            ReallyMeP256SecureEnclaveEcdsa.compressedPublicKeyLength
        )
        XCTAssertEqual(try ReallyMeP256SecureEnclaveEcdsa.decodePrivateKeyHandle(
            replacement.privateKeyHandle
        ), tag)
    }

    func testP256SecureEnclaveSigningAndEcdhTagsArePurposeSeparatedWhenAvailable() throws {
        let tag = Array("me.really.crypto.tests.p256.shared-tag.\(UUID().uuidString)".utf8)
        let agreementKeyPair: ReallyMeKeyAgreementHandleKeyPair
        do {
            agreementKeyPair = try ReallyMeCrypto.generateSecureEnclaveKeyAgreementKeyPair(
                .p256Ecdh,
                tag: tag,
                overwriteExisting: false
            )
        } catch ReallyMeCryptoError.unsupportedPlatform {
            throw XCTSkip("Secure Enclave is not available on this test platform")
        } catch ReallyMeCryptoError.providerFailure {
            throw XCTSkip("Secure Enclave is not available to this test process")
        }
        defer {
            try? ReallyMeCrypto.deleteSecureEnclaveKeyAgreementKey(
                .p256Ecdh,
                privateKeyHandle: agreementKeyPair.privateKeyHandle
            )
        }

        let signingKeyPair = try ReallyMeCrypto.generateSecureEnclaveSigningKeyPair(
            .ecdsaP256Sha256,
            tag: tag,
            accessControl: .privateKeyUsage,
            overwriteExisting: false
        )
        defer {
            try? ReallyMeCrypto.deleteSecureEnclaveSigningKey(
                .ecdsaP256Sha256,
                privateKeyHandle: signingKeyPair.privateKeyHandle
            )
        }

        XCTAssertNotEqual(agreementKeyPair.publicKey, signingKeyPair.publicKey)
        let message = Array("ReallyMe Secure Enclave purpose separation".utf8)
        let signature = try ReallyMeCrypto.signWithPrivateKeyHandle(
            .ecdsaP256Sha256,
            message: message,
            privateKeyHandle: signingKeyPair.privateKeyHandle
        )
        try ReallyMeCrypto.verifySecureEnclaveSignature(
            .ecdsaP256Sha256,
            signature: signature,
            message: message,
            publicKey: signingKeyPair.publicKey
        )

        let peer = try ReallyMeP256Ecdh.generateKeyPair()
        let enclaveSecret = try ReallyMeCrypto.deriveSharedSecretWithPrivateKeyHandle(
            .p256Ecdh,
            publicKey: peer.publicKey,
            privateKeyHandle: agreementKeyPair.privateKeyHandle
        )
        let peerSecret = try ReallyMeP256Ecdh.deriveSharedSecret(
            publicKey: agreementKeyPair.publicKey,
            secretKey: peer.secretKey
        )
        XCTAssertEqual(enclaveSecret, peerSecret)
    }
}
