// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCodec

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

private final class ReallyMeCryptoCodecProviderStorage: @unchecked Sendable {
  // `NSLock` is available on every SwiftPM platform we support, unlike the
  // Apple-platform-only `OSAllocatedUnfairLock`. The unchecked Sendable
  // boundary is safe because this is the sole mutable state and every access
  // holds `codecLock`.
  private let codecLock = NSLock()
  private var codec: ReallyMeCodec?

  func install(_ installedCodec: ReallyMeCodec) {
    codecLock.lock()
    defer { codecLock.unlock() }
    codec = installedCodec
  }

  func requireCodec() throws(ReallyMeCryptoError) -> ReallyMeCodec {
    codecLock.lock()
    defer { codecLock.unlock() }
    let installed = codec
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
