// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest

@testable import ReallyMeCrypto

private typealias MatchingProcessFunction =
  @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
  ) -> Int32

private typealias MismatchedProcessFunction = @convention(c) () -> Int32

final class ReallyMeCryptoLinkedRustCAbiTypeSafetyTests: XCTestCase {
  func testLinkedSymbolRejectsMismatchedFunctionType() throws {
    guard ReallyMeRustCAbiLibrary.isBundledProviderAvailable else {
      throw XCTSkip("linked Rust provider is not part of this development build")
    }
    let library = try ReallyMeRustCAbiLibrary.bundledProvider()
    let _: MatchingProcessFunction = try library.loadFunction(
      "rm_crypto_process_operation_response",
      as: MatchingProcessFunction.self
    )

    do {
      let _: MismatchedProcessFunction = try library.loadFunction(
        "rm_crypto_process_operation_response",
        as: MismatchedProcessFunction.self
      )
      XCTFail("linked FFI accepted a mismatched function type")
    } catch {
      XCTAssertEqual(error, .providerFailure)
    }
  }
}
