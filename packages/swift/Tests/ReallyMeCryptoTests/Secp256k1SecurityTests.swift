// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

@testable import ReallyMeCrypto
import XCTest

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
                derivePublicKey: { _ in
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
