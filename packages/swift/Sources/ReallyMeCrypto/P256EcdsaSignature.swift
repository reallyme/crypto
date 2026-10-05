// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

private let p256ScalarLength = 32
private let p256DerSignatureMaxLength = 72
private let p256DerSequenceTag: UInt8 = 0x30
private let p256DerIntegerTag: UInt8 = 0x02
private let p256CurveOrder: [UInt8] = [
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
  0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]
private let p256HalfCurveOrder: [UInt8] = [
  0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
  0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
]

/// Canonical representation policy for DER-encoded P-256 ECDSA signatures.
public enum ReallyMeP256EcdsaSignature {
  /// Returns the canonical low-S form of a canonical DER signature.
  ///
  /// Use this for signatures returned by an HSM, Secure Enclave, or platform
  /// keystore. The transform does not authenticate the signature; callers must
  /// still verify it against the exact message that was signed.
  public static func normalizeDerLowS(_ signature: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    let (r, s) = try decodeCanonicalDer(signature)
    let normalized = try normalizeJoseLowS(r + s)
    return try encodeDer(
      r: Array(normalized[..<p256ScalarLength]),
      s: Array(normalized[p256ScalarLength...])
    )
  }

  /// Returns the canonical low-S form of an exact 64-byte JOSE `r || s`
  /// signature without transcoding through DER.
  public static func normalizeJoseLowS(_ signature: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    guard signature.count == p256ScalarLength * 2 else {
      throw ReallyMeCryptoError.invalidInput
    }
    let r = Array(signature[..<p256ScalarLength])
    let s = Array(signature[p256ScalarLength...])
    guard r.contains(where: { $0 != 0 }), s.contains(where: { $0 != 0 }),
      compareScalar(r, p256CurveOrder) < 0,
      compareScalar(s, p256CurveOrder) < 0
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    let normalizedS =
      compareScalar(s, p256HalfCurveOrder) > 0
      ? try subtractScalar(p256CurveOrder, s)
      : s
    return r + normalizedS
  }

  private static func decodeCanonicalDer(_ signature: [UInt8]) throws(ReallyMeCryptoError)
    -> ([UInt8], [UInt8])
  {
    guard signature.count >= 8, signature.count <= p256DerSignatureMaxLength,
      signature[0] == p256DerSequenceTag,
      signature[1] & 0x80 == 0,
      Int(signature[1]) == signature.count - 2
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    var offset = 2
    let r = try readDerInteger(signature, offset: &offset)
    let s = try readDerInteger(signature, offset: &offset)
    guard offset == signature.count,
      compareScalar(r, p256CurveOrder) < 0,
      compareScalar(s, p256CurveOrder) < 0
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    return (r, s)
  }

  private static func readDerInteger(
    _ signature: [UInt8],
    offset: inout Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    let (lengthOffset, lengthOffsetOverflow) = offset.addingReportingOverflow(1)
    let (start, startOverflow) = offset.addingReportingOverflow(2)
    guard offset >= 0, !lengthOffsetOverflow, !startOverflow, start <= signature.count,
      signature[offset] == p256DerIntegerTag
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    let length = Int(signature[lengthOffset])
    let (end, overflow) = start.addingReportingOverflow(length)
    guard overflow == false, length > 0, length <= p256ScalarLength + 1,
      end <= signature.count
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    let encoded = Array(signature[start..<end])
    guard let first = encoded.first, first & 0x80 == 0 else {
      throw ReallyMeCryptoError.invalidInput
    }
    if encoded.count > 1, first == 0, encoded[1] & 0x80 == 0 {
      throw ReallyMeCryptoError.invalidInput
    }
    let unpadded = first == 0 ? Array(encoded.dropFirst()) : encoded
    guard unpadded.count <= p256ScalarLength, unpadded.contains(where: { $0 != 0 }) else {
      throw ReallyMeCryptoError.invalidInput
    }
    let (paddingLength, paddingOverflow) = p256ScalarLength.subtractingReportingOverflow(
      unpadded.count)
    guard paddingOverflow == false else {
      throw ReallyMeCryptoError.invalidInput
    }
    var scalar = [UInt8](repeating: 0, count: p256ScalarLength)
    scalar.replaceSubrange(paddingLength..<p256ScalarLength, with: unpadded)
    offset = end
    return scalar
  }

  private static func encodeDer(r: [UInt8], s: [UInt8]) throws(ReallyMeCryptoError) -> [UInt8] {
    let encodedR = try encodeDerInteger(r)
    let encodedS = try encodeDerInteger(s)
    let (payloadLength, overflow) = encodedR.count.addingReportingOverflow(encodedS.count)
    guard overflow == false, let encodedLength = UInt8(exactly: payloadLength) else {
      throw ReallyMeCryptoError.providerFailure
    }
    var result = [p256DerSequenceTag, encodedLength]
    result.append(contentsOf: encodedR)
    result.append(contentsOf: encodedS)
    return result
  }

  private static func encodeDerInteger(_ scalar: [UInt8]) throws(ReallyMeCryptoError) -> [UInt8] {
    guard scalar.count == p256ScalarLength,
      let firstNonzero = scalar.firstIndex(where: { $0 != 0 })
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    var content = Array(scalar[firstNonzero...])
    if let first = content.first, first & 0x80 != 0 {
      content.insert(0, at: 0)
    }
    guard content.count <= p256ScalarLength + 1,
      let encodedLength = UInt8(exactly: content.count)
    else {
      throw ReallyMeCryptoError.providerFailure
    }
    return [p256DerIntegerTag, encodedLength] + content
  }

  private static func compareScalar(_ left: [UInt8], _ right: [UInt8]) -> Int {
    for (leftByte, rightByte) in zip(left, right) where leftByte != rightByte {
      return leftByte < rightByte ? -1 : 1
    }
    return left.count == right.count ? 0 : (left.count < right.count ? -1 : 1)
  }

  private static func subtractScalar(
    _ left: [UInt8],
    _ right: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    guard left.count == p256ScalarLength, right.count == p256ScalarLength,
      compareScalar(left, right) >= 0
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    var result = [UInt8](repeating: 0, count: p256ScalarLength)
    var borrow = 0
    for index in stride(from: p256ScalarLength - 1, through: 0, by: -1) {
      let difference = Int(left[index]) - Int(right[index]) - borrow
      let adjustedDifference = difference < 0 ? difference + 256 : difference
      guard let encodedDifference = UInt8(exactly: adjustedDifference) else {
        throw ReallyMeCryptoError.providerFailure
      }
      result[index] = encodedDifference
      borrow = difference < 0 ? 1 : 0
    }
    guard borrow == 0 else {
      throw ReallyMeCryptoError.invalidInput
    }
    return result
  }
}
