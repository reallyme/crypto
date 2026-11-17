// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

private struct Bip340ErrorVector: Decodable {
  let signature: String
  let message: String
  let publicKeyXonly: String
  let invalidOffCurvePublicKeyXonly: String
  let invalidOutOfRangePublicKeyXonly: String
}

extension ReallyMeCryptoRustCAbiTests {
  func testSharedBip340InvalidPublicKeysHaveInputErrors() throws {
    let library = try Self.configuredRustCAbiLibrary()
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let vector = try decoder.decode(
      Bip340ErrorVector.self, from: Data(contentsOf: reallyMeVectorURL("bip340_schnorr.json")))
    let signature = try Self.base64UrlBytes(vector.signature)
    let message = try Self.base64UrlBytes(vector.message)
    let publicKey = try Self.base64UrlBytes(vector.publicKeyXonly)
    try ReallyMeCrypto.verify(
      .bip340SchnorrSecp256k1Sha256, signature: signature, message: message,
      publicKey: publicKey, rustCAbiLibrary: library)
    for encoded in [vector.invalidOffCurvePublicKeyXonly, vector.invalidOutOfRangePublicKeyXonly] {
      let invalidKey = try Self.base64UrlBytes(encoded)
      XCTAssertThrowsError(
        try ReallyMeCrypto.verify(
          .bip340SchnorrSecp256k1Sha256, signature: signature, message: message,
          publicKey: invalidKey, rustCAbiLibrary: library)
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
      }
    }
    var tampered = signature
    tampered[0] ^= 1
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .bip340SchnorrSecp256k1Sha256, signature: tampered, message: message,
        publicKey: publicKey, rustCAbiLibrary: library)
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }
  }
}
