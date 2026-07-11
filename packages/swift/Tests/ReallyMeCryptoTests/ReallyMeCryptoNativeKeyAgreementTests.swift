// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
    // MARK: - X25519 (CryptoKit)

    func testX25519DerivePublicKeyKnownAnswer() throws {
        XCTAssertEqual(
            try ReallyMeX25519.derivePublicKey(secretKey: Self.x25519SecretKey),
            Self.x25519PublicKey
        )
        XCTAssertEqual(
            try ReallyMeX25519.derivePublicKey(secretKey: Self.x25519PeerSecretKey),
            Self.x25519PeerPublicKey
        )
        let keyPair = try ReallyMeCrypto.deriveKeyAgreementKeyPair(
            .x25519,
            secretKey: Self.x25519SecretKey
        )
        XCTAssertEqual(keyPair.publicKey, Self.x25519PublicKey)
        XCTAssertEqual(keyPair.secretKey, Self.x25519SecretKey)
    }

    func testX25519DeriveSharedSecretKnownAnswer() throws {
        XCTAssertEqual(
            try ReallyMeX25519.deriveSharedSecret(
                publicKey: Self.x25519PeerPublicKey,
                secretKey: Self.x25519SecretKey
            ),
            Self.x25519SharedSecret
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveSharedSecret(
                .x25519,
                publicKey: Self.x25519PublicKey,
                secretKey: Self.x25519PeerSecretKey
            ),
            Self.x25519SharedSecret
        )
    }

    func testX25519RejectsMalformedInputs() {
        XCTAssertThrowsError(
            try ReallyMeX25519.derivePublicKey(secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveKeyAgreementKeyPair(.x25519, secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        XCTAssertThrowsError(
            try ReallyMeX25519.deriveSharedSecret(
                publicKey: [UInt8](repeating: 0, count: ReallyMeX25519.publicKeyLength - 1),
                secretKey: Self.x25519SecretKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        XCTAssertThrowsError(
            try ReallyMeX25519.deriveSharedSecret(
                publicKey: [UInt8](repeating: 0, count: ReallyMeX25519.publicKeyLength),
                secretKey: Self.x25519SecretKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testX25519GenerateKeyPairRoundTrip() throws {
        let alice = try ReallyMeX25519.generateKeyPair()
        let bob = try ReallyMeX25519.generateKeyPair()
        let aliceSecret = try ReallyMeCrypto.deriveSharedSecret(
            .x25519,
            publicKey: bob.publicKey,
            secretKey: alice.secretKey
        )
        let bobSecret = try ReallyMeCrypto.deriveSharedSecret(
            .x25519,
            publicKey: alice.publicKey,
            secretKey: bob.secretKey
        )

        XCTAssertEqual(alice.publicKey.count, ReallyMeX25519.publicKeyLength)
        XCTAssertEqual(alice.secretKey.count, ReallyMeX25519.secretKeyLength)
        XCTAssertEqual(aliceSecret.count, ReallyMeX25519.sharedSecretLength)
        XCTAssertEqual(aliceSecret, bobSecret)
    }

    // MARK: - P-256 ECDH (CryptoKit)

    func testP256EcdhKnownAnswer() throws {
        XCTAssertEqual(
            try ReallyMeP256Ecdh.derivePublicKey(secretKey: Self.p256EcdhSecretKey),
            Self.p256EcdhPublicKey
        )
        let keyPair = try ReallyMeCrypto.deriveKeyAgreementKeyPair(
            .p256Ecdh,
            secretKey: Self.p256EcdhSecretKey
        )
        XCTAssertEqual(keyPair.publicKey, Self.p256EcdhPublicKey)
        XCTAssertEqual(keyPair.secretKey, Self.p256EcdhSecretKey)
        XCTAssertEqual(
            try ReallyMeP256Ecdh.deriveSharedSecret(
                publicKey: Self.p256EcdhPeerPublicKey,
                secretKey: Self.p256EcdhSecretKey
            ),
            Self.p256EcdhSharedSecret
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveSharedSecret(
                .p256Ecdh,
                publicKey: Self.p256EcdhPublicKey,
                secretKey: Self.p256EcdhPeerSecretKey
            ),
            Self.p256EcdhSharedSecret
        )
    }

    func testP256EcdhRejectsMalformedInputs() {
        XCTAssertThrowsError(
            try ReallyMeP256Ecdh.derivePublicKey(secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP256Ecdh.deriveSharedSecret(
                publicKey: [UInt8](repeating: 0, count: ReallyMeP256Ecdh.compressedPublicKeyLength),
                secretKey: Self.p256EcdhSecretKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testP256EcdhGenerateKeyPairRoundTrip() throws {
        let alice = try ReallyMeP256Ecdh.generateKeyPair()
        let bob = try ReallyMeP256Ecdh.generateKeyPair()
        let aliceSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p256Ecdh,
            publicKey: bob.publicKey,
            secretKey: alice.secretKey
        )
        let bobSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p256Ecdh,
            publicKey: alice.publicKey,
            secretKey: bob.secretKey
        )

        XCTAssertEqual(aliceSecret.count, ReallyMeP256Ecdh.sharedSecretLength)
        XCTAssertEqual(aliceSecret, bobSecret)
    }
}
