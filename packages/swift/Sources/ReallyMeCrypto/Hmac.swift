// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation

public enum ReallyMeHmac {
  public static let maxKeyLength = 4096
  public static let sha256TagLength = 32
  public static let sha384TagLength = 48
  public static let sha512TagLength = 64

  public static func authenticateSha256(key: [UInt8], message: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    try validateKey(key)
    return Array(
      HMAC<SHA256>.authenticationCode(
        for: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    )
  }

  public static func authenticateSha512(key: [UInt8], message: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    try validateKey(key)
    return Array(
      HMAC<SHA512>.authenticationCode(
        for: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    )
  }

  public static func authenticateSha384(key: [UInt8], message: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    try validateKey(key)
    return Array(
      HMAC<SHA384>.authenticationCode(
        for: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    )
  }

  public static func verifySha256(tag: [UInt8], key: [UInt8], message: [UInt8])
    throws(ReallyMeCryptoError)
  {
    try validateKey(key)
    guard tag.count == sha256TagLength else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard
      HMAC<SHA256>.isValidAuthenticationCode(
        tag,
        authenticating: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    else {
      // Invalid authentication must fail even if the caller ignores the result.
      throw ReallyMeCryptoError.authenticationFailed
    }
  }

  public static func verifySha512(tag: [UInt8], key: [UInt8], message: [UInt8])
    throws(ReallyMeCryptoError)
  {
    try validateKey(key)
    guard tag.count == sha512TagLength else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard
      HMAC<SHA512>.isValidAuthenticationCode(
        tag,
        authenticating: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    else {
      throw ReallyMeCryptoError.authenticationFailed
    }
  }

  public static func verifySha384(tag: [UInt8], key: [UInt8], message: [UInt8])
    throws(ReallyMeCryptoError)
  {
    try validateKey(key)
    guard tag.count == sha384TagLength else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard
      HMAC<SHA384>.isValidAuthenticationCode(
        tag,
        authenticating: Data(message),
        using: SymmetricKey(data: Data(key))
      )
    else {
      throw ReallyMeCryptoError.authenticationFailed
    }
  }

  private static func validateKey(_ key: [UInt8]) throws(ReallyMeCryptoError) {
    guard key.isEmpty == false, key.count <= maxKeyLength else {
      throw ReallyMeCryptoError.invalidInput
    }
  }
}
