// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
    // MARK: - secp256k1 (Bitcoin Core libsecp256k1 via reallyme/CSecp256k1)

    func testSecp256k1DerivePublicKeyKnownAnswer() throws {
        let publicKey = try ReallyMeSecp256k1.derivePublicKey(secretKey: Self.vectorSecretKey)
        XCTAssertEqual(publicKey, Self.vectorPublicKey)
        let keyPair = try ReallyMeSecp256k1.deriveKeyPair(secretKey: Self.vectorSecretKey)
        XCTAssertEqual(keyPair.publicKey, Self.vectorPublicKey)
        XCTAssertEqual(keyPair.secretKey, Self.vectorSecretKey)
    }

    func testSecp256k1SignIsDeterministicAndVerifies() throws {
        let message = Array("reallyme secp256k1 contract".utf8)

        let first = try ReallyMeSecp256k1.sign(message: message, secretKey: Self.vectorSecretKey)
        let second = try ReallyMeSecp256k1.sign(message: message, secretKey: Self.vectorSecretKey)
        XCTAssertEqual(first, second, "RFC 6979 signatures must be deterministic")
        XCTAssertEqual(first.count, ReallyMeSecp256k1.signatureLength)

        // Cross-lane KAT: the same bytes @noble/curves 2.2.0 (TS lane oracle)
        // and BouncyCastle (Kotlin lane) produce for this message and key.
        XCTAssertEqual(
            first,
            Self.bytes(
                "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d"
                    + "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee"
            )
        )

        try ReallyMeSecp256k1.verify(
            signature: first, message: message, publicKey: Self.vectorPublicKey
        )
    }

    func testGenericFacadeSecp256k1KnownAnswer() throws {
        let message = Array("reallyme secp256k1 contract".utf8)
        let signature = try ReallyMeCrypto.sign(
            .ecdsaSecp256k1Sha256,
            message: message,
            secretKey: Self.vectorSecretKey
        )

        XCTAssertEqual(
            signature,
            Self.bytes(
                "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d"
                    + "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee"
            )
        )
        try ReallyMeCrypto.verify(
            .ecdsaSecp256k1Sha256,
            signature: signature,
            message: message,
            publicKey: Self.vectorPublicKey
        )
    }

    func testSecp256k1SignatureIsLowS() throws {
        // s must be <= n/2 (BIP 0062). n/2 for secp256k1:
        let halfOrder = Self.bytes(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
        )
        let message = Array("low-s check".utf8)
        let signature = try ReallyMeSecp256k1.sign(message: message, secretKey: Self.vectorSecretKey)
        let s = Array(signature[32...])
        XCTAssertFalse(
            Self.lexicographicallyGreater(s, halfOrder),
            "signature s component must be low-S normalized"
        )
    }

    func testSecp256k1RejectsTamperedSignatureAndMessage() throws {
        let message = Array("tamper check".utf8)
        var signature = try ReallyMeSecp256k1.sign(message: message, secretKey: Self.vectorSecretKey)

        XCTAssertThrowsError(
            try ReallyMeSecp256k1.verify(
                signature: signature, message: message + [0x00], publicKey: Self.vectorPublicKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }

        signature[10] ^= 0xff
        XCTAssertThrowsError(
            try ReallyMeSecp256k1.verify(
                signature: signature, message: message, publicKey: Self.vectorPublicKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
    }

    func testSecp256k1RejectsMalformedInputs() {
        let message = Array("shape check".utf8)

        XCTAssertThrowsError(
            try ReallyMeSecp256k1.sign(message: message, secretKey: [0x01, 0x02])
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        XCTAssertThrowsError(
            try ReallyMeSecp256k1.derivePublicKey(
                secretKey: [UInt8](repeating: 0, count: ReallyMeSecp256k1.secretKeyLength)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        XCTAssertThrowsError(
            try ReallyMeSecp256k1.verify(
                signature: [UInt8](repeating: 0, count: 63),
                message: message,
                publicKey: Self.vectorPublicKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        var invalidKey = Self.vectorPublicKey
        invalidKey[0] = 0x07 // not a valid SEC1 compressed prefix
        XCTAssertThrowsError(
            try ReallyMeSecp256k1.verify(
                signature: [UInt8](repeating: 0, count: ReallyMeSecp256k1.signatureLength),
                message: message,
                publicKey: invalidKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testSecp256k1RejectsHighSMalleatedTwin() throws {
        let curveOrder = Self.bytes(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        )
        let message = Array("malleability check".utf8)
        let signature = try ReallyMeSecp256k1.sign(message: message, secretKey: Self.vectorSecretKey)
        try ReallyMeSecp256k1.verify(
            signature: signature, message: message, publicKey: Self.vectorPublicKey
        )

        // (r, n - s) verifies under raw ECDSA but must be rejected (BIP 0062).
        // libsecp256k1 refuses high-S natively, so this must fail closed.
        let highS = Self.subtractBigEndian(curveOrder, Array(signature[32...]))
        let malleated = Array(signature[..<32]) + highS
        XCTAssertThrowsError(
            try ReallyMeSecp256k1.verify(
                signature: malleated, message: message, publicKey: Self.vectorPublicKey
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
    }

    func testSecp256k1GenerateKeyPairRoundTrip() throws {
        let keyPair = try ReallyMeSecp256k1.generateKeyPair()
        XCTAssertEqual(keyPair.secretKey.count, ReallyMeSecp256k1.secretKeyLength)
        XCTAssertEqual(keyPair.publicKey.count, ReallyMeSecp256k1.compressedPublicKeyLength)

        let message = Array("fresh keypair".utf8)
        let signature = try ReallyMeSecp256k1.sign(message: message, secretKey: keyPair.secretKey)
        try ReallyMeSecp256k1.verify(
            signature: signature, message: message, publicKey: keyPair.publicKey
        )
    }

    /// Big-endian byte-wise subtraction (lhs - rhs), assuming lhs >= rhs.
    private static func subtractBigEndian(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: lhs.count)
        var borrow = 0
        for index in stride(from: lhs.count - 1, through: 0, by: -1) {
            let difference = Int(lhs[index]) - Int(rhs[index]) - borrow
            out[index] = UInt8((difference + 256) % 256)
            borrow = difference < 0 ? 1 : 0
        }
        return out
    }

    private static func lexicographicallyGreater(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for (left, right) in zip(lhs, rhs) where left != right {
            return left > right
        }
        return false
    }


}
