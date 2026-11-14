// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

@testable import ReallyMeCrypto
import XCTest

final class AeadPlaintextReleaseTests: XCTestCase {
  func testAuthenticationFailureDiscardsEverySubsetOfProviderWrites() {
    let candidate: [UInt8] = [0x12, 0x34, 0x56, 0x78]
    let lengths = [Int.min, -1, 0, 1, 2, 3, 4, 5, Int.max]
    for mask in 0..<(1 << candidate.count) {
      for length in lengths {
        XCTAssertThrowsError(
          try ReallyMeRustCAbiStatus.withAuthenticatedPlaintext(capacity: candidate.count) {
            staging, producedLength in
            for index in candidate.indices where mask & (1 << index) != 0 {
              staging[index] = candidate[index]
            }
            producedLength = length
            return ReallyMeRustCAbiStatus.authenticationFailed
          }
        ) { error in
          XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
      }
    }
  }

  func testSuccessfulStatusRequiresAValidLengthBeforeCopyingPlaintext() throws {
    let plaintext: [UInt8] = [0x12, 0x34, 0x56, 0x78]
    for length in 0...plaintext.count {
      XCTAssertEqual(
        try openSuccessfully(plaintext, producedLength: length),
        Array(plaintext.prefix(length))
      )
    }
    for length in [Int.min, -1, plaintext.count + 1, Int.max] {
      XCTAssertThrowsError(
        try openSuccessfully(plaintext, producedLength: length)
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .providerFailure)
      }
    }
  }

  private func openSuccessfully(_ plaintext: [UInt8], producedLength: Int) throws -> [UInt8] {
    try ReallyMeRustCAbiStatus.withAuthenticatedPlaintext(capacity: plaintext.count) {
      staging, length in
      for index in plaintext.indices {
        staging[index] = plaintext[index]
      }
      length = producedLength
      return ReallyMeRustCAbiStatus.ok
    }
  }

  func testCryptoKitOpenRejectsTamperedRecords() throws {
    let suites: [(ReallyMeAeadAlgorithm, Int)] = [
      (.aes128Gcm, 16), (.aes192Gcm, 24), (.aes256Gcm, 32), (.chacha20Poly1305, 32),
    ]
    for (algorithm, keyLength) in suites {
      let key = [UInt8](repeating: 0x21, count: keyLength)
      let nonce = [UInt8](repeating: 0x42, count: 12)
      let aad: [UInt8] = [0x63]
      let plaintext: [UInt8] = [0x12, 0x34, 0x56, 0x78]
      let record = try ReallyMeCrypto.seal(
        algorithm, key: key, nonce: nonce, aad: aad, plaintext: plaintext
      )
      XCTAssertEqual(
        try ReallyMeCrypto.open(
          algorithm, key: key, nonce: nonce, aad: aad, ciphertextWithTag: record
        ),
        plaintext
      )
      var badTag = record
      badTag[badTag.count - 1] ^= 1
      var badCiphertext = record
      badCiphertext[0] ^= 1
      for (input, context) in [(badTag, aad), (badCiphertext, aad), (record, [0x64])] {
        XCTAssertThrowsError(
          try ReallyMeCrypto.open(
            algorithm, key: key, nonce: nonce, aad: context, ciphertextWithTag: input
          )
        ) { error in
          XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }
      }
    }
  }

  func testDirectRustAes192GcmOpenRejectsTamperedTag() throws {
    let library = try ReallyMeCryptoRustCAbiTests.configuredRustCAbiLibrary()
    let provider = try ReallyMeRustCAbiAead(library: library)
    let key = [UInt8](repeating: 0x21, count: 24)
    let nonce = [UInt8](repeating: 0x42, count: 12)
    let aad: [UInt8] = [0x63]
    let plaintext: [UInt8] = [0x12, 0x34, 0x56, 0x78]
    var record = try provider.sealAes192Gcm(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    XCTAssertEqual(
      try provider.openAes192Gcm(key: key, nonce: nonce, aad: aad, ciphertextWithTag: record),
      plaintext
    )

    record[record.count - 1] ^= 1
    XCTAssertThrowsError(
      try provider.openAes192Gcm(key: key, nonce: nonce, aad: aad, ciphertextWithTag: record)
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
    }
  }
}
