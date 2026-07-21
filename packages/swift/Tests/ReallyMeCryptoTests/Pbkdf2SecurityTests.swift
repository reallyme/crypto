// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

@testable import ReallyMeCrypto
import XCTest

final class Pbkdf2SecurityTests: XCTestCase {
    func testModernIterationFloorIsEnforced() {
        XCTAssertThrowsError(
            try ReallyMePbkdf2.deriveHmacSha256(
                password: Array("password".utf8),
                salt: Array("salt".utf8),
                iterations: ReallyMePbkdf2.minIterations - 1,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testIterationCeilingIsEnforcedBeforeProviderDispatch() {
        XCTAssertThrowsError(
            try ReallyMePbkdf2.deriveHmacSha512(
                password: Array("password".utf8),
                salt: Array("salt".utf8),
                iterations: ReallyMePbkdf2.maxIterations + 1,
                outputLength: 32
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    func testProviderFailureClearsPreviouslyAccumulatedOutput() {
        let sentinel = [UInt8](repeating: 0xa5, count: 32)
        let iterations = ReallyMePbkdf2.minIterations + 1
        var authenticationCalls: UInt32 = 0
        var lastBytesBeforeClear = [UInt8]()
        var lastBytesAfterClear = [UInt8]()

        XCTAssertThrowsError(
            try ReallyMePbkdf2.derive(
                password: Array("password".utf8),
                salt: Array("salt".utf8),
                iterations: iterations,
                outputLength: 33,
                hashLength: 32,
                authenticate: { _, _ in
                    authenticationCalls += 1
                    if authenticationCalls > iterations {
                        throw ReallyMeCryptoError.providerFailure
                    }
                    return sentinel
                },
                clear: { bytes in
                    lastBytesBeforeClear = bytes
                    ReallyMeCryptoMemory.bestEffortClear(&bytes)
                    lastBytesAfterClear = bytes
                }
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }

        XCTAssertEqual(authenticationCalls, iterations + 1)
        XCTAssertEqual(lastBytesBeforeClear, sentinel)
        XCTAssertEqual(lastBytesAfterClear, [UInt8](repeating: 0, count: sentinel.count))
    }

    func testMalformedProviderBlockFailsClosedAndIsCleared() {
        let validBlock = [UInt8](repeating: 0xa5, count: 32)
        let malformedBlock = [UInt8](repeating: 0x5a, count: 31)
        var authenticationCalls = 0
        var malformedBlockWasCleared = false

        XCTAssertThrowsError(
            try ReallyMePbkdf2.derive(
                password: Array("password".utf8),
                salt: Array("salt".utf8),
                iterations: ReallyMePbkdf2.minIterations,
                outputLength: 32,
                hashLength: 32,
                authenticate: { _, _ in
                    authenticationCalls += 1
                    return authenticationCalls == 1 ? validBlock : malformedBlock
                },
                clear: { bytes in
                    let isMalformedBlock = bytes == malformedBlock
                    ReallyMeCryptoMemory.bestEffortClear(&bytes)
                    if isMalformedBlock {
                        malformedBlockWasCleared = bytes.allSatisfy { $0 == 0 }
                    }
                }
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
        }

        XCTAssertEqual(authenticationCalls, 2)
        XCTAssertTrue(malformedBlockWasCleared)
    }

    func testInvalidInjectedHashLengthFailsBeforeAuthentication() {
        var authenticationWasCalled = false

        XCTAssertThrowsError(
            try ReallyMePbkdf2.derive(
                password: Array("password".utf8),
                salt: Array("salt".utf8),
                iterations: ReallyMePbkdf2.minIterations,
                outputLength: 32,
                hashLength: 0,
                authenticate: { _, _ in
                    authenticationWasCalled = true
                    return []
                }
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        XCTAssertFalse(authenticationWasCalled)
    }
}
