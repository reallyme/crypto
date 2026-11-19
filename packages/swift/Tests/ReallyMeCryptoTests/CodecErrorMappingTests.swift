// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
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
      (.unsupportedCodec, .invalidInput),
      (.providerFailure, .providerFailure),
    ]

    for (codecError, expected) in cases {
      XCTAssertEqual(mapCodecError(codecError), expected)
    }
  }

  func testOperationFailuresMapToStableCryptoErrors() {
    let cases: [(ReallyMeCodecError, ReallyMeCryptoError)] = [
      (
        .operationFailure(
          category: .invalidInput, reason: .baseInvalidBase64URL, origin: .caller
        ), .invalidInput
      ),
      (
        .operationFailure(
          category: .nonCanonical, reason: .baseNonCanonicalHex, origin: .caller
        ), .invalidInput
      ),
      (
        .operationFailure(
          category: .unsupportedIpldValue, reason: .canonicalUnsupportedIpldValue, origin: .caller
        ), .invalidInput
      ),
      (
        .operationFailure(
          category: .unsupportedCodec, reason: .multiformatUnknownMulticodec, origin: .caller
        ), .invalidInput
      ),
      (
        .operationFailure(
          category: .providerFailure, reason: .backendInternal, origin: .provider
        ), .providerFailure
      ),
    ]

    for (codecError, expected) in cases {
      XCTAssertEqual(mapCodecError(codecError), expected)
    }
  }

  func testUnknownOperationCategoriesFailClosed() {
    for category in [ReallyMeProtoCodecSdkErrorCategory.unspecified, .UNRECOGNIZED(Int.max)] {
      let error = ReallyMeCodecError.operationFailure(
        category: category, reason: .backendInternal, origin: .provider
      )
      XCTAssertEqual(mapCodecError(error), .providerFailure)
    }
  }
}
