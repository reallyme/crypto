// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Secp256k1ABI
import Security
import SwiftProviderProbes
import XCTest

enum SwiftJwk {
  static func toJcs(alg: String, publicKey: Data) throws -> String {
    let spec = try spec(for: alg)
    guard publicKey.count == spec.publicKeyLength else {
      throw VectorError.invalidField
    }

    if spec.kty == "EC" {
      let uncompressed = try decompressEcPublicKey(alg: alg, publicKey: publicKey)
      let x = uncompressed.subdata(in: 1..<33).base64UrlEncodedString()
      let y = uncompressed.subdata(in: 33..<65).base64UrlEncodedString()
      return try
        #"{"alg":\#(jsonString(spec.alg)),"crv":\#(jsonString(spec.crv)),"kty":"EC","use":"sig","x":\#(jsonString(x)),"y":\#(jsonString(y))}"#
    }

    let encodedPublicKey = publicKey.base64UrlEncodedString()
    if spec.kty == "AKP" {
      return try
        #"{"alg":\#(jsonString(spec.alg)),"kty":"AKP","pub":\#(jsonString(encodedPublicKey)),"use":\#(jsonString(spec.keyUse))}"#
    }
    return try
      #"{"alg":\#(jsonString(spec.alg)),"crv":\#(jsonString(spec.crv)),"kty":"OKP","use":\#(jsonString(spec.keyUse)),"x":\#(jsonString(encodedPublicKey))}"#
  }

  static func fromJcs(_ value: String) throws -> ParsedJwk {
    guard let data = value.data(using: .utf8) else {
      throw VectorError.invalidField
    }
    let object = try JSONSerialization.jsonObject(with: data)
    guard
      let jwk = object as? [String: Any],
      let kty = jwk["kty"] as? String
    else {
      throw VectorError.invalidField
    }
    let keyIdentifier: String
    let publicKeyMember: String
    if kty == "AKP" {
      guard
        let alg = jwk["alg"] as? String,
        let encodedPublicKey = jwk["pub"] as? String
      else {
        throw VectorError.invalidField
      }
      keyIdentifier = alg
      publicKeyMember = encodedPublicKey
    } else {
      guard
        let crv = jwk["crv"] as? String,
        let encodedPublicKey = jwk["x"] as? String
      else {
        throw VectorError.invalidField
      }
      keyIdentifier = crv
      publicKeyMember = encodedPublicKey
    }
    let spec = try spec(for: keyIdentifier)
    guard
      kty == spec.kty,
      (jwk["alg"] as? String) == spec.alg,
      (jwk["use"] as? String) == spec.keyUse
    else {
      throw VectorError.invalidField
    }

    if spec.kty == "EC" {
      guard let y = jwk["y"] as? String else {
        throw VectorError.invalidField
      }
      let compressed = try compressEcPublicKey(
        alg: keyIdentifier,
        x: Data(base64Url: publicKeyMember),
        y: Data(base64Url: y)
      )
      return ParsedJwk(alg: keyIdentifier, publicKey: compressed)
    }

    let publicKey = try Data(base64Url: publicKeyMember)
    guard publicKey.count == spec.publicKeyLength else {
      throw VectorError.invalidField
    }
    return ParsedJwk(alg: keyIdentifier, publicKey: publicKey)
  }

  static func spec(for alg: String) throws -> SwiftJwkSpec {
    switch alg {
    case "Ed25519":
      return SwiftJwkSpec(
        alg: "EdDSA", crv: "Ed25519", kty: "OKP", keyUse: "sig", publicKeyLength: 32)
    case "X25519":
      return SwiftJwkSpec(
        alg: "ECDH-ES", crv: "X25519", kty: "OKP", keyUse: "enc", publicKeyLength: 32)
    case "P-256":
      return SwiftJwkSpec(alg: "ES256", crv: "P-256", kty: "EC", keyUse: "sig", publicKeyLength: 33)
    case "secp256k1":
      return SwiftJwkSpec(
        alg: "ES256K", crv: "secp256k1", kty: "EC", keyUse: "sig", publicKeyLength: 33)
    case "ML-DSA-44":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 1_312)
    case "ML-DSA-65":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 1_952)
    case "ML-DSA-87":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 2_592)
    case "ML-KEM-512":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 800)
    case "ML-KEM-768":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_184)
    case "ML-KEM-1024":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_568)
    case "SLH-DSA-SHA2-128s":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "sig", publicKeyLength: 32)
    case "X-Wing-768":
      return SwiftJwkSpec(alg: alg, crv: alg, kty: "AKP", keyUse: "enc", publicKeyLength: 1_216)
    default:
      throw VectorError.invalidField
    }
  }

  static func decompressEcPublicKey(alg: String, publicKey: Data) throws -> Data {
    if alg == "P-256" {
      return try P256.Signing.PublicKey(compressedRepresentation: publicKey).x963Representation
    }

    guard alg == "secp256k1" else {
      throw VectorError.invalidField
    }

    var x = [UInt8](repeating: 0, count: 32)
    var y = [UInt8](repeating: 0, count: 32)
    let compressed = [UInt8](publicKey)
    let status = compressed.withUnsafeBytes { publicBytes in
      guard let publicPointer = publicBytes.bindMemory(to: UInt8.self).baseAddress else {
        return Int32(-128)
      }
      return secp256k1_decompress_public_key(publicPointer, &x, &y)
    }
    guard status == 0 else {
      throw VectorError.invalidField
    }

    var uncompressed = Data([0x04])
    uncompressed.append(contentsOf: x)
    uncompressed.append(contentsOf: y)
    return uncompressed
  }

  static func compressEcPublicKey(alg: String, x: Data, y: Data) throws -> Data {
    guard x.count == 32, y.count == 32 else {
      throw VectorError.invalidField
    }
    var uncompressed = Data([0x04])
    uncompressed.append(x)
    uncompressed.append(y)

    if alg == "P-256" {
      return try P256.Signing.PublicKey(x963Representation: uncompressed).compressedRepresentation
    }

    guard alg == "secp256k1" else {
      throw VectorError.invalidField
    }

    let yLast = try XCTUnwrap(y.last)
    var compressed = Data([yLast & 1 == 0 ? 0x02 : 0x03])
    compressed.append(x)
    let roundTrip = try decompressEcPublicKey(alg: alg, publicKey: compressed)
    guard roundTrip == uncompressed else {
      throw VectorError.invalidField
    }
    return compressed
  }

  static func jsonString(_ value: String) throws -> String {
    let data = try JSONEncoder().encode(value)
    guard let encoded = String(data: data, encoding: .utf8) else {
      throw VectorError.invalidField
    }
    return encoded
  }
}
