// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
  func testP256SecureEnclaveReferenceRejectsInvalidApplicationTags() {
    XCTAssertThrowsError(
      try ReallyMeP256SecureEnclaveEcdhKeyReference(applicationTag: [])
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeP256SecureEnclaveEcdhKeyReference(
        applicationTag: [UInt8](
          repeating: 0x41,
          count:
            ReallyMeP256SecureEnclaveEcdhKeyReference
            .maximumApplicationTagLength + 1
        )
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
  }

  func testP256SecureEnclaveReferenceRoundTripWhenAvailable() throws {
    let applicationTag = Array(
      "me.really.crypto.tests.p256.reference.\(UUID().uuidString)".utf8
    )
    let reference = try ReallyMeP256SecureEnclaveEcdhKeyReference(
      applicationTag: applicationTag
    )
    let publicKey: [UInt8]
    do {
      publicKey = try ReallyMeP256SecureEnclaveEcdh.generateKey(
        reference: reference,
        accessPolicy: .backgroundWhenUnlocked,
        overwriteExisting: false
      )
    } catch ReallyMeCryptoError.unsupportedPlatform {
      throw XCTSkip("Secure Enclave is not available on this test platform")
    } catch ReallyMeCryptoError.providerFailure {
      throw XCTSkip("Secure Enclave is not available to this test process")
    }
    defer {
      try? ReallyMeP256SecureEnclaveEcdh.deleteKey(reference: reference)
    }

    XCTAssertTrue(
      try ReallyMeP256SecureEnclaveEcdh.keyExists(reference: reference)
    )
    XCTAssertEqual(
      try ReallyMeP256SecureEnclaveEcdh.derivePublicKey(reference: reference),
      publicKey
    )
    let peer = try ReallyMeP256Ecdh.generateKeyPair()
    let enclaveSecret = try ReallyMeP256SecureEnclaveEcdh.deriveSharedSecret(
      publicKey: peer.publicKey,
      reference: reference
    )
    let peerSecret = try ReallyMeP256Ecdh.deriveSharedSecret(
      publicKey: publicKey,
      secretKey: peer.secretKey
    )
    XCTAssertEqual(enclaveSecret, peerSecret)

    try ReallyMeP256SecureEnclaveEcdh.deleteKey(reference: reference)
    XCTAssertFalse(
      try ReallyMeP256SecureEnclaveEcdh.keyExists(reference: reference)
    )
    XCTAssertThrowsError(
      try ReallyMeP256SecureEnclaveEcdh.derivePublicKey(reference: reference)
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertNoThrow(
      try ReallyMeP256SecureEnclaveEcdh.deleteKey(reference: reference)
    )
  }
}
