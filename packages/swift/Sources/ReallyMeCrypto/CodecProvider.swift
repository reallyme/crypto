// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCodec
#if canImport(os)
  import os
#else
  import Synchronization
#endif

/// Explicit codec provider hook for Swift package consumers.
///
/// Crypto keeps its JWK and multikey public API stable, but codec primitives
/// are owned by `reallyme-codec`. Applications install that provider once at
/// startup; codec-dependent static crypto helpers then fail closed if it is
/// missing instead of falling back to duplicated Swift codec code.
public enum ReallyMeCryptoCodecProvider {
  private static let storage = ReallyMeCryptoCodecProviderStorage()

  public static func install(_ codec: ReallyMeCodec) {
    storage.install(codec)
  }

  static func requireCodec() throws(ReallyMeCryptoError) -> ReallyMeCodec {
    try storage.requireCodec()
  }
}

private final class ReallyMeCryptoCodecProviderStorage: Sendable {
  // Apple platforms use the back-deployable lock required by the package's
  // macOS 13 and iOS 16 minimums. Linux has no `os` module, so SwiftPM source
  // validation uses the standard-library mutex instead. Both locks enforce
  // Sendable state ownership without a concurrency escape hatch.
  #if canImport(os)
    private let codec = OSAllocatedUnfairLock<ReallyMeCodec?>(initialState: nil)
  #else
    private let codec = Mutex<ReallyMeCodec?>(nil)
  #endif

  func install(_ installedCodec: ReallyMeCodec) {
    codec.withLock { value in
      value = installedCodec
    }
  }

  func requireCodec() throws(ReallyMeCryptoError) -> ReallyMeCodec {
    let installed = codec.withLock { value in value }
    guard let installed else {
      throw ReallyMeCryptoError.providerFailure
    }
    return installed
  }
}

func mapCodecError(_ error: Error) -> ReallyMeCryptoError {
  guard let codecError = error as? ReallyMeCodecError else {
    return .providerFailure
  }
  switch codecError {
  case .unsupportedPlatform:
    return .unsupportedPlatform
  case .dynamicLibraryNotFound:
    return .dynamicLibraryNotFound
  case .dynamicLibraryLoadFailed:
    return .dynamicLibraryLoadFailed
  case .symbolNotFound:
    return .symbolNotFound
  case .invalidInput:
    return .invalidInput
  case .providerFailure:
    return .providerFailure
  }
}
