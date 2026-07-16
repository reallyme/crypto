// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

private struct Sec1KeyAgreementVector: Decodable {
    let secretKey: String
    let publicKeyCompressed: String
    let peerSecretKey: String
    let peerPublicKeyCompressed: String
    let sharedSecret: String

    private enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyCompressed = "public_key_compressed"
        case peerSecretKey = "peer_secret_key"
        case peerPublicKeyCompressed = "peer_public_key_compressed"
        case sharedSecret = "shared_secret"
    }
}

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

    func testP256SecureEnclaveHandleEncodingAndValidation() throws {
        let tag = Array("me.really.crypto.tests.p256".utf8)
        let handle = try ReallyMeP256SecureEnclaveEcdh.encodePrivateKeyHandle(tag: tag)

        XCTAssertEqual(try ReallyMeP256SecureEnclaveEcdh.decodePrivateKeyHandle(handle), tag)
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdh.encodePrivateKeyHandle(tag: [])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP256SecureEnclaveEcdh.decodePrivateKeyHandle(Array("not-a-handle".utf8))
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveSharedSecretWithPrivateKeyHandle(
                .x25519,
                publicKey: [],
                privateKeyHandle: handle
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testP256SecureEnclaveEcdhRoundTripWhenAvailable() throws {
        let tag = Array("me.really.crypto.tests.p256.\(UUID().uuidString)".utf8)
        let enclaveKeyPair: ReallyMeKeyAgreementHandleKeyPair
        do {
            enclaveKeyPair = try ReallyMeCrypto.generateSecureEnclaveKeyAgreementKeyPair(
                .p256Ecdh,
                tag: tag,
                overwriteExisting: true
            )
        } catch ReallyMeCryptoError.unsupportedPlatform {
            throw XCTSkip("Secure Enclave is not available on this test platform")
        } catch ReallyMeCryptoError.providerFailure {
            throw XCTSkip("Secure Enclave is not available to this test process")
        }
        defer {
            try? ReallyMeCrypto.deleteSecureEnclaveKeyAgreementKey(
                .p256Ecdh,
                privateKeyHandle: enclaveKeyPair.privateKeyHandle
            )
        }

        let peer = try ReallyMeP256Ecdh.generateKeyPair()
        XCTAssertEqual(
            try ReallyMeP256SecureEnclaveEcdh.derivePublicKey(
                privateKeyHandle: enclaveKeyPair.privateKeyHandle
            ),
            enclaveKeyPair.publicKey
        )

        let enclaveSecret = try ReallyMeCrypto.deriveSharedSecretWithPrivateKeyHandle(
            .p256Ecdh,
            publicKey: peer.publicKey,
            privateKeyHandle: enclaveKeyPair.privateKeyHandle
        )
        let peerSecret = try ReallyMeP256Ecdh.deriveSharedSecret(
            publicKey: enclaveKeyPair.publicKey,
            secretKey: peer.secretKey
        )

        XCTAssertEqual(enclaveKeyPair.publicKey.count, ReallyMeP256Ecdh.compressedPublicKeyLength)
        XCTAssertEqual(enclaveSecret.count, ReallyMeP256Ecdh.sharedSecretLength)
        XCTAssertEqual(enclaveSecret, peerSecret)
    }

    // MARK: - P-384 ECDH (CryptoKit)

    func testP384EcdhKnownAnswer() throws {
        let vector = try Self.sec1KeyAgreementVector("p384.json")
        let secretKey = try Self.base64UrlBytes(vector.secretKey)
        let publicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
        let peerSecretKey = try Self.base64UrlBytes(vector.peerSecretKey)
        let peerPublicKey = try Self.base64UrlBytes(vector.peerPublicKeyCompressed)
        let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)

        XCTAssertEqual(try ReallyMeP384Ecdh.derivePublicKey(secretKey: secretKey), publicKey)
        let keyPair = try ReallyMeCrypto.deriveKeyAgreementKeyPair(
            .p384Ecdh,
            secretKey: secretKey
        )
        XCTAssertEqual(keyPair.publicKey, publicKey)
        XCTAssertEqual(keyPair.secretKey, secretKey)
        XCTAssertEqual(
            try ReallyMeP384Ecdh.deriveSharedSecret(
                publicKey: peerPublicKey,
                secretKey: secretKey
            ),
            sharedSecret
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveSharedSecret(
                .p384Ecdh,
                publicKey: publicKey,
                secretKey: peerSecretKey
            ),
            sharedSecret
        )
    }

    func testP384EcdhRejectsMalformedInputs() {
        XCTAssertThrowsError(
            try ReallyMeP384Ecdh.derivePublicKey(secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP384Ecdh.deriveSharedSecret(
                publicKey: [UInt8](repeating: 0, count: ReallyMeP384Ecdh.compressedPublicKeyLength),
                secretKey: [UInt8](repeating: 1, count: ReallyMeP384Ecdh.secretKeyLength)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testP384EcdhGenerateKeyPairRoundTrip() throws {
        let alice = try ReallyMeP384Ecdh.generateKeyPair()
        let bob = try ReallyMeP384Ecdh.generateKeyPair()
        let aliceSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p384Ecdh,
            publicKey: bob.publicKey,
            secretKey: alice.secretKey
        )
        let bobSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p384Ecdh,
            publicKey: alice.publicKey,
            secretKey: bob.secretKey
        )

        XCTAssertEqual(aliceSecret.count, ReallyMeP384Ecdh.sharedSecretLength)
        XCTAssertEqual(aliceSecret, bobSecret)
    }

    // MARK: - P-521 ECDH (CryptoKit)

    func testP521EcdhKnownAnswer() throws {
        let vector = try Self.sec1KeyAgreementVector("p521.json")
        let secretKey = try Self.base64UrlBytes(vector.secretKey)
        let publicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
        let peerSecretKey = try Self.base64UrlBytes(vector.peerSecretKey)
        let peerPublicKey = try Self.base64UrlBytes(vector.peerPublicKeyCompressed)
        let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)

        XCTAssertEqual(try ReallyMeP521Ecdh.derivePublicKey(secretKey: secretKey), publicKey)
        let keyPair = try ReallyMeCrypto.deriveKeyAgreementKeyPair(
            .p521Ecdh,
            secretKey: secretKey
        )
        XCTAssertEqual(keyPair.publicKey, publicKey)
        XCTAssertEqual(keyPair.secretKey, secretKey)
        XCTAssertEqual(
            try ReallyMeP521Ecdh.deriveSharedSecret(
                publicKey: peerPublicKey,
                secretKey: secretKey
            ),
            sharedSecret
        )
        XCTAssertEqual(
            try ReallyMeCrypto.deriveSharedSecret(
                .p521Ecdh,
                publicKey: publicKey,
                secretKey: peerSecretKey
            ),
            sharedSecret
        )
    }

    func testP521EcdhRejectsMalformedInputs() {
        XCTAssertThrowsError(
            try ReallyMeP521Ecdh.derivePublicKey(secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeP521Ecdh.deriveSharedSecret(
                publicKey: [UInt8](repeating: 0, count: ReallyMeP521Ecdh.compressedPublicKeyLength),
                secretKey: [UInt8](repeating: 1, count: ReallyMeP521Ecdh.secretKeyLength)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testP521EcdhGenerateKeyPairRoundTrip() throws {
        let alice = try ReallyMeP521Ecdh.generateKeyPair()
        let bob = try ReallyMeP521Ecdh.generateKeyPair()
        let aliceSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p521Ecdh,
            publicKey: bob.publicKey,
            secretKey: alice.secretKey
        )
        let bobSecret = try ReallyMeCrypto.deriveSharedSecret(
            .p521Ecdh,
            publicKey: alice.publicKey,
            secretKey: bob.secretKey
        )

        XCTAssertEqual(aliceSecret.count, ReallyMeP521Ecdh.sharedSecretLength)
        XCTAssertEqual(aliceSecret, bobSecret)
    }

    private static func sec1KeyAgreementVector(_ name: String) throws -> Sec1KeyAgreementVector {
        let data = try Data(contentsOf: reallyMeVectorURL(name))
        return try JSONDecoder().decode(Sec1KeyAgreementVector.self, from: data)
    }
}
