// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

private struct EcdsaEncodingVector: Decodable {
  let message: String?
  let ecdsaMessage: String?
  let signatureDer: String?
  let ecdsaSignatureDer: String?
  let publicKeyCompressed: String
  let publicKeyUncompressed: String
  let signatureDerNonminimalSequenceLength: String
  let signatureDerIndefiniteSequenceLength: String
  let signatureDerNonminimalIntegerLength: String
  let publicKeyHybridEven: String
  let publicKeyHybridOdd: String
}

extension ReallyMeCryptoRustCAbiTests {
  func testSharedEcdsaEncodingVectorsRejectBerAndHybridKeys() throws {
    let library = try Self.configuredRustCAbiLibrary()
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    let cases: [(String, ReallyMeSignatureAlgorithm)] = [
      ("p256.json", .ecdsaP256Sha256),
      ("p384.json", .ecdsaP384Sha384),
      ("p521.json", .ecdsaP521Sha512),
    ]
    for (name, algorithm) in cases {
      let data = try Data(contentsOf: reallyMeVectorURL(name))
      let vector = try decoder.decode(EcdsaEncodingVector.self, from: data)
      let encodedMessage = try XCTUnwrap(vector.message ?? vector.ecdsaMessage)
      let encodedSignature = try XCTUnwrap(vector.signatureDer ?? vector.ecdsaSignatureDer)
      let message = try Self.base64UrlBytes(encodedMessage)
      let signature = try Self.base64UrlBytes(encodedSignature)
      let publicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
      // Verify both canonical key representations before rejecting aliases of
      // the same coordinates. This distinguishes encoding policy from invalid
      // points or invalid signatures in the negative cases.
      for encoded in [vector.publicKeyCompressed, vector.publicKeyUncompressed] {
        try ReallyMeCrypto.verify(
          algorithm, signature: signature, message: message,
          publicKey: Self.base64UrlBytes(encoded), rustCAbiLibrary: library)
      }
      for encoded in [
        vector.signatureDerNonminimalSequenceLength,
        vector.signatureDerIndefiniteSequenceLength,
        vector.signatureDerNonminimalIntegerLength,
      ] {
        let malformed = try Self.base64UrlBytes(encoded)
        XCTAssertThrowsError(
          try ReallyMeCrypto.verify(
            algorithm, signature: malformed, message: message,
            publicKey: publicKey, rustCAbiLibrary: library)
        ) { error in
          XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature, name)
        }
      }
      for encoded in [vector.publicKeyHybridEven, vector.publicKeyHybridOdd] {
        let malformed = try Self.base64UrlBytes(encoded)
        XCTAssertThrowsError(
          try ReallyMeCrypto.verify(
            algorithm, signature: signature, message: message,
            publicKey: malformed, rustCAbiLibrary: library)
        ) { error in
          XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput, name)
        }
      }
    }
  }
}
