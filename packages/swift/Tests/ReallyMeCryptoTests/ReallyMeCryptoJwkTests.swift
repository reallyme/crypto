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
