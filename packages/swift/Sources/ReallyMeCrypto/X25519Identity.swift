// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

internal enum ReallyMeX25519Identity {
  private static let publicKeyLength = 32
  private static let fieldPrimeLowByte: UInt8 = 0xed
  private static let fieldPrimeHighByte: UInt8 = 0x7f

  internal static func isCanonical(_ publicKey: [UInt8]) -> Bool {
    guard publicKey.count == publicKeyLength,
      publicKey[31] <= fieldPrimeHighByte
    else {
      return false
    }
    // The agreement primitive accepts non-canonical u-coordinates. JWK and
    // multikey identities reject p through 2^255-1 as aliases.
    return publicKey[31] != fieldPrimeHighByte
      || publicKey[1..<31].contains(where: { $0 != 0xff })
      || publicKey[0] < fieldPrimeLowByte
  }
}
