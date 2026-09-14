// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Security
import Secp256k1ABI
import SwiftProviderProbes
import XCTest

extension VectorConformanceTests {
  func testNativeJwkVectors() throws {
    let vectors: JwkVectors = try loadVector("jwk.json")
    for vector in vectors.vectors {
      let publicKey = try Data(base64Url: vector.publicKey)
      XCTAssertEqual(publicKey.count, vector.publicKeyLength)
      XCTAssertEqual(try SwiftJwk.toJcs(alg: vector.alg, publicKey: publicKey), vector.jwkJcs)
      let parsed = try SwiftJwk.fromJcs(vector.jwkJcs)
      XCTAssertEqual(parsed.alg, vector.alg)
      XCTAssertEqual(parsed.publicKey, publicKey)
      if vector.multikeyStatus == "supported" {
        XCTAssertNotNil(vector.multikey)
        XCTAssertTrue(try XCTUnwrap(vector.multikey).hasPrefix("z"))
      } else {
        XCTAssertEqual(vector.multikeyStatus, "multicodec-missing")
        XCTAssertNil(vector.multikey)
      }
    }
  }

  func validateJwkShape() throws {
    let vectors: JwkVectors = try loadVector("jwk.json")
    let expectedAlgorithms: Set<String> = [
      "Ed25519", "X25519", "P-256", "secp256k1",
      "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
      "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
      "SLH-DSA-SHA2-128s", "X-Wing-768",
    ]
    XCTAssertEqual(Set(vectors.vectors.map(\.alg)), expectedAlgorithms)
    XCTAssertEqual(vectors.vectors.count, expectedAlgorithms.count)
    for vector in vectors.vectors {
      let publicKey = try Data(base64Url: vector.publicKey)
      XCTAssertEqual(publicKey.count, vector.publicKeyLength)
      XCTAssertFalse(vector.jwkJcs.isEmpty)
    }
  }
}
