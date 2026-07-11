// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
    func testMulticodecPrefixVectorsMatchSharedContract() throws {
        let vector = try Self.loadCodecVector()

        for entry in vector.multicodecPrefixes {
            guard let algorithm = ReallyMeMulticodecKeyAlgorithm(rawValue: entry.name) else {
                continue
            }

            XCTAssertEqual(ReallyMeMulticodec.algorithmName(for: algorithm), entry.alg)
            XCTAssertEqual(
                ReallyMeMulticodec.prefix(for: algorithm),
                try Self.base64UrlBytes(entry.prefix),
                entry.name
            )
        }
    }

    func testMultikeyVectorRoundTrips() throws {
        let vector = try Self.loadCodecVector()
        let parsed = try ReallyMeMultikey.parse(vector.multikey)

        XCTAssertEqual(parsed.algorithm, .ed25519PublicKey)
        XCTAssertEqual(parsed.algorithmName, "Ed25519")
        XCTAssertEqual(parsed.expectedPublicKeyLength, 32)
        XCTAssertEqual(parsed.publicKey.count, 32)
        XCTAssertEqual(
            try ReallyMeMultikey.encode(parsed.algorithm, publicKey: parsed.publicKey),
            vector.multikey
        )
    }

    func testMultikeyRejectsMalformedInputs() {
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

    static func loadCodecVector() throws -> CodecVector {
        let vectorUrl = try reallyMeVectorURL("codecs.json")
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(CodecVector.self, from: data)
    }
}

struct CodecVector: Decodable {
    let multicodecPrefixes: [CodecPrefixVector]
    let multikey: String

    private enum CodingKeys: String, CodingKey {
        case multicodecPrefixes = "multicodec_prefixes"
        case multikey
    }
}

struct CodecPrefixVector: Decodable {
    let name: String
    let alg: String
    let prefix: String
}
