// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

private typealias Ed25519DecodePublicKeyFunction =
  @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
  ) -> Int32

/// Identity-bearing Ed25519 envelopes must use the same point policy as Rust verification.
/// CryptoKit accepts low-order and noncanonical encodings as public-key objects, so the
/// bundled Rust decoder is the authority for these boundaries.
enum ReallyMeEd25519Identity {
  private static let publicKeyLength = 32

  static func validate(_ publicKey: [UInt8]) throws(ReallyMeCryptoError) {
    guard publicKey.count == publicKeyLength else {
      throw ReallyMeCryptoError.invalidInput
    }
    let library: ReallyMeRustCAbiLibrary
    #if REALLYME_CRYPTO_LINKED_FFI
      library = try ReallyMeRustCAbiLibrary.bundledProvider()
    #else
      // Source-tree tests exercise the same ABI through their explicitly built library.
      guard let path = ProcessInfo.processInfo.environment["REALLYME_CRYPTO_FFI_LIBRARY_PATH"]
      else {
        throw ReallyMeCryptoError.providerFailure
      }
      library = try ReallyMeRustCAbiLibrary(path: path)
    #endif
    let decode = try library.loadFunction(
      "rm_crypto_ed25519_decode_public_key", as: Ed25519DecodePublicKeyFunction.self)
    var decoded = [UInt8](repeating: 0, count: publicKeyLength)
    defer {
      for index in decoded.indices {
        decoded[index] = 0
      }
    }
    let status = publicKey.withUnsafeBufferPointer { input in
      decoded.withUnsafeMutableBufferPointer { output in
        decode(input.baseAddress, input.count, output.baseAddress, output.count)
      }
    }
    try ReallyMeRustCAbiStatus.throwIfError(status)
    guard decoded == publicKey else {
      throw ReallyMeCryptoError.providerFailure
    }
  }
}
