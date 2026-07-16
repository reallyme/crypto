// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
    func testMultikeyVectorRoundTrips() throws {
        try installReallyMeCodecProviderForTest()
        let vector = try Self.loadSupportedJwkMultikeyVector(algorithm: "Ed25519")
        let multikey = try XCTUnwrap(vector.multikey)
        let parsed = try ReallyMeMultikey.parse(multikey)

        XCTAssertEqual(parsed.algorithm, .ed25519PublicKey)
        XCTAssertEqual(parsed.algorithmName, vector.alg)
        XCTAssertEqual(parsed.expectedPublicKeyLength, vector.publicKeyLength)
        XCTAssertEqual(parsed.publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(
            try ReallyMeMultikey.encode(parsed.algorithm, publicKey: parsed.publicKey),
            multikey
        )
    }

    func testMultikeyRejectsMalformedInputs() throws {
        try installReallyMeCodecProviderForTest()
        XCTAssertThrowsError(try ReallyMeMultikey.parse("")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(try ReallyMeMultikey.parse("uAAAA")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(try ReallyMeMultikey.parse("z0")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(try ReallyMeMultikey.parse("z2")) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeMultikey.encode(.ed25519PublicKey, publicKey: [UInt8](repeating: 0, count: 31))
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(try ReallyMeMultikey.encode(.rsaPublicKey, publicKey: [])) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    static func loadSupportedJwkMultikeyVector(algorithm: String) throws -> JwkMultikeyVector {
        let vectorUrl = try reallyMeVectorURL("jwk.json")
        let data = try Data(contentsOf: vectorUrl)
        let vectors = try JSONDecoder().decode(JwkMultikeyVectors.self, from: data)
        return try XCTUnwrap(vectors.vectors.first { vector in
            vector.alg == algorithm && vector.multikeyStatus == "supported"
        })
    }
}

struct JwkMultikeyVectors: Decodable {
    let vectors: [JwkMultikeyVector]
}

struct JwkMultikeyVector: Decodable {
    let alg: String
    let publicKeyLength: Int
    let multikey: String?
    let multikeyStatus: String

    private enum CodingKeys: String, CodingKey {
        case alg
        case publicKeyLength = "public_key_length"
        case multikey
        case multikeyStatus = "multikey_status"
    }
}
