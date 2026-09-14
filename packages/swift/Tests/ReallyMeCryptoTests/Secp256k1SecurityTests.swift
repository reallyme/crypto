// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest

@testable import ReallyMeCrypto

extension ReallyMeCryptoTests {
  func testSecp256k1AcceptedSecretCandidateIsClearedAfterDerivationFailure() {
    let candidate = [UInt8](repeating: 0x42, count: ReallyMeSecp256k1.secretKeyLength)
    var cleanupCallCount = 0
    var observedClearedCandidate = false

    XCTAssertThrowsError(
      try ReallyMeSecp256k1.generateKeyPair(
        fillRandom: { output in
          output = candidate
          return true
        },
        acceptsSecret: { _ in true },
        derivePublicKey: { _ throws(ReallyMeCryptoError) in
          throw ReallyMeCryptoError.providerFailure
        },
        didClear: { output in
          cleanupCallCount += 1
          observedClearedCandidate = output.allSatisfy { $0 == 0 }
        }
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
    }

    XCTAssertEqual(cleanupCallCount, 1)
    XCTAssertTrue(observedClearedCandidate)
  }
}
