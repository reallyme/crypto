// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeCodec
@testable import ReallyMeCrypto
import XCTest

final class CodecErrorMappingTests: XCTestCase {
  func testCodecErrorsMapToStableCryptoErrors() {
    let cases: [(ReallyMeCodecError, ReallyMeCryptoError)] = [
      (.unsupportedPlatform, .unsupportedPlatform),
      (.dynamicLibraryNotFound, .dynamicLibraryNotFound),
      (.dynamicLibraryLoadFailed, .dynamicLibraryLoadFailed),
      (.symbolNotFound, .symbolNotFound),
      (.invalidInput, .invalidInput),
      (.nonCanonical, .invalidInput),
      (.unsupportedIpldValue, .invalidInput),
      (.providerUnavailable, .unsupportedAlgorithm),
      (.unsupportedCodec, .unsupportedAlgorithm),
      (.providerFailure, .providerFailure),
    ]

    for (codecError, expected) in cases {
      XCTAssertEqual(mapCodecError(codecError), expected)
    }
  }
}
