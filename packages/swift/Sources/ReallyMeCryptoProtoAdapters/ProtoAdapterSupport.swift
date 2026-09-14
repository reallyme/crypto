// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

extension ReallyMeCryptoProtoAdapters {
  static func serialized<T: SwiftProtobuf.Message>(_ value: T) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    do {
      return try value.serializedBytes()
    } catch {
      throw ReallyMeCryptoError.providerFailure
    }
  }

  static func keyPairToProto(
    algorithm: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    publicKey: [UInt8],
    secretKey: [UInt8]
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair()
    proto.algorithm = algorithm
    proto.publicKey = Data(publicKey)
    proto.secretKey = Data(secretKey)
    return proto
  }

  static func signatureAlgorithmIdentifierToProto(
    _ value: ReallyMeSignatureAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
    var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
    algorithm.signature = toProto(value)
    return algorithm
  }

  static func keyAgreementAlgorithmIdentifierToProto(
    _ value: ReallyMeKeyAgreementAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
    var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
    algorithm.keyAgreement = toProto(value)
    return algorithm
  }

  static func kemAlgorithmIdentifierToProto(
    _ value: ReallyMeKemAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
    var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
    algorithm.kem = toProto(value)
    return algorithm
  }

  static func hpkeSuiteIdentifierToProto(
    _ value: ReallyMeHpkeSuite
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
    var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
    algorithm.hpkeSuite = toProto(value)
    return algorithm
  }

  static func signatureAlgorithm(
    fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    isPresent: Bool
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureAlgorithm {
    guard isPresent else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard case .signature(let signature)? = value.algorithm else {
      throw ReallyMeCryptoError.invalidInput
    }
    return try fromProto(signature)
  }

  static func keyAgreementAlgorithm(
    fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    isPresent: Bool
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementAlgorithm {
    guard isPresent else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard case .keyAgreement(let keyAgreement)? = value.algorithm else {
      throw ReallyMeCryptoError.invalidInput
    }
    return try fromProto(keyAgreement)
  }

  static func kemAlgorithm(
    fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    isPresent: Bool
  ) throws(ReallyMeCryptoError) -> ReallyMeKemAlgorithm {
    guard isPresent else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard case .kem(let kem)? = value.algorithm else {
      throw ReallyMeCryptoError.invalidInput
    }
    return try fromProto(kem)
  }

  static func hpkeSuite(
    fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    isPresent: Bool
  ) throws(ReallyMeCryptoError) -> ReallyMeHpkeSuite {
    guard isPresent else {
      throw ReallyMeCryptoError.invalidInput
    }
    guard case .hpkeSuite(let hpke)? = value.algorithm else {
      throw ReallyMeCryptoError.invalidInput
    }
    return try fromProto(hpke)
  }

  static func jwkAlgorithmToProto(
    _ value: ReallyMeJwkAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
    var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
    switch value {
    case .ed25519:
      algorithm.signature = .ed25519
    case .x25519:
      algorithm.keyAgreement = .x25519
    case .p256:
      algorithm.signature = .ecdsaP256Sha256
    case .secp256k1:
      algorithm.signature = .ecdsaSecp256K1Sha256
    case .mlDsa44:
      algorithm.signature = .mlDsa44
    case .mlDsa65:
      algorithm.signature = .mlDsa65
    case .mlDsa87:
      algorithm.signature = .mlDsa87
    case .mlKem512:
      algorithm.kem = .mlKem512
    case .mlKem768:
      algorithm.kem = .mlKem768
    case .mlKem1024:
      algorithm.kem = .mlKem1024
    case .slhDsaSha2_128s:
      algorithm.signature = .slhDsaSha2128S
    case .xWing768:
      algorithm.kem = .xWing768
    }
    return algorithm
  }

  static func jwkAlgorithm(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier
  ) throws(ReallyMeCryptoError) -> ReallyMeJwkAlgorithm {
    switch value.algorithm {
    case .signature(let signature):
      switch signature {
      case .ed25519:
        return .ed25519
      case .ecdsaP256Sha256:
        return .p256
      case .ecdsaSecp256K1Sha256:
        return .secp256k1
      case .mlDsa44:
        return .mlDsa44
      case .mlDsa65:
        return .mlDsa65
      case .mlDsa87:
        return .mlDsa87
      case .slhDsaSha2128S:
        return .slhDsaSha2_128s
      default:
        throw ReallyMeCryptoError.unsupportedAlgorithm
      }
    case .keyAgreement(let keyAgreement):
      guard keyAgreement == .x25519 else {
        throw ReallyMeCryptoError.unsupportedAlgorithm
      }
      return .x25519
    case .kem(let kem):
      switch kem {
      case .mlKem512:
        return .mlKem512
      case .mlKem768:
        return .mlKem768
      case .mlKem1024:
        return .mlKem1024
      case .xWing768:
        return .xWing768
      default:
        throw ReallyMeCryptoError.unsupportedAlgorithm
      }
    case nil:
      throw ReallyMeCryptoError.invalidInput
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }
}
