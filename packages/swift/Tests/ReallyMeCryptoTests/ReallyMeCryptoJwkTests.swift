// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

final class ReallyMeCryptoJwkTests: XCTestCase {
    func testJwkVectorsMatchPackageFacade() throws {
        try installReallyMeCodecProviderForTest()
        let data = try Data(contentsOf: reallyMeVectorURL("jwk.json"))
        let vectors = try JSONDecoder().decode(JwkVectorFile.self, from: data)

        for vector in vectors.vectors {
            guard let algorithm = ReallyMeJwkAlgorithm(rawValue: vector.alg) else {
                XCTFail("unsupported JWK vector algorithm")
                continue
            }
            let publicKey = try Self.base64UrlBytes(vector.publicKey)
            XCTAssertEqual(publicKey.count, vector.publicKeyLength)

            let jwk = try ReallyMeJwk.toJwk(algorithm: algorithm, publicKey: publicKey)
            XCTAssertEqual(try ReallyMeJwk.toJcs(jwk), vector.jwkJcs)

            let parsed = try ReallyMeJwk.fromJwkJson(Data(vector.jwkJcs.utf8))
            XCTAssertEqual(parsed.algorithm, algorithm)
            XCTAssertEqual(parsed.publicKey, publicKey)
            XCTAssertEqual(try ReallyMeJwk.toJcs(parsed.jwk), vector.jwkJcs)
        }
    }

    func testJwkParserRejectsPrivateKeyMembers() throws {
        try installReallyMeCodecProviderForTest()
        let publicX = String(repeating: "A", count: 43)
        for name in ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "privateKey", "secretKey"] {
            let json = #"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"\#(publicX)","\#(name)":"redacted-test-value"}"#
            XCTAssertThrowsError(try ReallyMeJwk.fromJwkJson(Data(json.utf8))) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
            }
        }
    }

    func testJwkParserRejectsDuplicateUnknownAndMixedShapeMembers() throws {
        try installReallyMeCodecProviderForTest()
        let publicX = String(repeating: "A", count: 43)
        let valid = #"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"\#(publicX)"}"#
        let malformed = [
            #"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","kty":"OKP","use":"sig","x":"\#(publicX)"}"#,
            #"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"\#(publicX)","unknown":"value"}"#,
            #"{"alg":"EdDSA","crv":"Ed25519","kty":"OKP","use":"sig","x":"\#(publicX)","y":"\#(publicX)"}"#,
        ]
        for json in malformed {
            XCTAssertThrowsError(try ReallyMeJwk.fromJwkJson(Data(json.utf8))) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
            }
        }
        let jwksWithUnknownMember = #"{"keys":[\#(valid)],"unknown":"value"}"#
        XCTAssertThrowsError(try ReallyMeJwk.fromJwksJson(Data(jwksWithUnknownMember.utf8))) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testJwkParserRejectsMismatchedEcCoordinates() throws {
        try installReallyMeCodecProviderForTest()
        let data = try Data(contentsOf: reallyMeVectorURL("jwk.json"))
        let vectors = try JSONDecoder().decode(JwkVectorFile.self, from: data)

        for algorithm in ["P-256", "secp256k1"] {
            let vector = try XCTUnwrap(vectors.vectors.first { $0.alg == algorithm })
            for mutation in [YMutation.sameParity, .oppositeParity] {
                let json = try Self.mutatedEcJwkJson(vector.jwkJcs, mutation: mutation)
                XCTAssertThrowsError(try ReallyMeJwk.fromJwkJson(Data(json.utf8)), algorithm) { error in
                    XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
                }
            }
        }
    }

    func testOkpMetadataIsOptionalButConflictsAreRejected() throws {
        try installReallyMeCodecProviderForTest()
        let publicX = String(repeating: "A", count: 43)
        let omitted = #"{"crv":"Ed25519","kty":"OKP","x":"\#(publicX)"}"#
        XCTAssertEqual(
            try ReallyMeJwk.fromJwkJson(Data(omitted.utf8)).algorithm,
            .ed25519
        )

        for metadata in [#""alg":"ECDH-ES","#, #""use":"enc","#] {
            let conflicting = #"{\#(metadata)"crv":"Ed25519","kty":"OKP","x":"\#(publicX)"}"#
            XCTAssertThrowsError(try ReallyMeJwk.fromJwkJson(Data(conflicting.utf8))) { error in
                XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
            }
        }
    }

    private static func base64UrlBytes(_ encoded: String) throws -> [UInt8] {
        let paddingLength = (4 - (encoded.count % 4)) % 4
        let padded = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: paddingLength)
        guard let data = Data(base64Encoded: padded) else {
            throw ReallyMeCryptoError.invalidInput
        }
        return Array(data)
    }

    private static func base64UrlString(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func mutatedEcJwkJson(_ json: String, mutation: YMutation) throws -> String {
        let decoded = try JSONSerialization.jsonObject(with: Data(json.utf8))
        guard var object = decoded as? [String: Any], let encodedY = object["y"] as? String else {
            throw ReallyMeCryptoError.invalidInput
        }
        var y = try base64UrlBytes(encodedY)
        switch mutation {
        case .sameParity:
            y[0] ^= 0x02
        case .oppositeParity:
            y[31] ^= 0x01
        }
        object["y"] = base64UrlString(y)
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard let output = String(data: data, encoding: .utf8) else {
            throw ReallyMeCryptoError.invalidInput
        }
        return output
    }
}

private enum YMutation {
    case sameParity
    case oppositeParity
}

private struct JwkVectorFile: Decodable {
    let vectors: [JwkVector]
}

private struct JwkVector: Decodable {
    let alg: String
    let publicKey: String
    let publicKeyLength: Int
    let jwkJcs: String

    enum CodingKeys: String, CodingKey {
        case alg
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case jwkJcs = "jwk_jcs"
    }
}
