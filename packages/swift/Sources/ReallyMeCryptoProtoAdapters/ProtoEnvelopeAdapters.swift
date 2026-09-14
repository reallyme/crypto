// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

extension ReallyMeCryptoProtoAdapters {
  public static func signatureKeyPairToProto(
    algorithm: ReallyMeSignatureAlgorithm,
    keyPair: ReallyMeSignatureKeyPair
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair {
    keyPairToProto(
      algorithm: signatureAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey)
  }

  public static func signatureKeyPairToProtoBytes(
    algorithm: ReallyMeSignatureAlgorithm,
    keyPair: ReallyMeSignatureKeyPair
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(signatureKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
  }

  public static func signatureKeyPair(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPairProtoValue {
    ReallyMeSignatureKeyPairProtoValue(
      algorithm: try signatureAlgorithm(
        fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
      keyPair: ReallyMeSignatureKeyPair(
        publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
    )
  }

  public static func signatureKeyPair(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeSignatureKeyPairProtoValue
  {
    do {
      return try signatureKeyPair(fromProto: ReallyMeProtoCryptoKeyPair(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func keyAgreementKeyPairToProto(
    algorithm: ReallyMeKeyAgreementAlgorithm,
    keyPair: ReallyMeKeyAgreementKeyPair
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair {
    keyPairToProto(
      algorithm: keyAgreementAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey)
  }

  public static func keyAgreementKeyPairToProtoBytes(
    algorithm: ReallyMeKeyAgreementAlgorithm,
    keyPair: ReallyMeKeyAgreementKeyPair
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(keyAgreementKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
  }

  public static func keyAgreementKeyPair(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementKeyPairProtoValue {
    ReallyMeKeyAgreementKeyPairProtoValue(
      algorithm: try keyAgreementAlgorithm(
        fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
      keyPair: ReallyMeKeyAgreementKeyPair(
        publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
    )
  }

  public static func keyAgreementKeyPair(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeKeyAgreementKeyPairProtoValue
  {
    do {
      return try keyAgreementKeyPair(fromProto: ReallyMeProtoCryptoKeyPair(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func kemKeyPairToProto(
    algorithm: ReallyMeKemAlgorithm,
    keyPair: ReallyMeKemKeyPair
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair {
    keyPairToProto(
      algorithm: kemAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey)
  }

  public static func kemKeyPairToProtoBytes(
    algorithm: ReallyMeKemAlgorithm,
    keyPair: ReallyMeKemKeyPair
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(kemKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
  }

  public static func kemKeyPair(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
  ) throws(ReallyMeCryptoError) -> ReallyMeKemKeyPairProtoValue {
    ReallyMeKemKeyPairProtoValue(
      algorithm: try kemAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
      keyPair: ReallyMeKemKeyPair(
        publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
    )
  }

  public static func kemKeyPair(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeKemKeyPairProtoValue
  {
    do {
      return try kemKeyPair(fromProto: ReallyMeProtoCryptoKeyPair(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func kemEncapsulationToProto(
    algorithm: ReallyMeKemAlgorithm,
    encapsulation: ReallyMeKemEncapsulation
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKemEncapsulation {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoKemEncapsulation()
    proto.algorithm = kemAlgorithmIdentifierToProto(algorithm)
    proto.ciphertext = Data(encapsulation.ciphertext)
    proto.sharedSecret = Data(encapsulation.sharedSecret)
    return proto
  }

  public static func kemEncapsulationToProtoBytes(
    algorithm: ReallyMeKemAlgorithm,
    encapsulation: ReallyMeKemEncapsulation
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(kemEncapsulationToProto(algorithm: algorithm, encapsulation: encapsulation))
  }

  public static func kemEncapsulation(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKemEncapsulation
  ) throws(ReallyMeCryptoError) -> ReallyMeKemEncapsulationProtoValue {
    ReallyMeKemEncapsulationProtoValue(
      algorithm: try kemAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
      encapsulation: ReallyMeKemEncapsulation(
        sharedSecret: Array(value.sharedSecret), ciphertext: Array(value.ciphertext))
    )
  }

  public static func kemEncapsulation(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeKemEncapsulationProtoValue
  {
    do {
      return try kemEncapsulation(
        fromProto: ReallyMeProtoCryptoKemEncapsulation(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func hpkeSealedMessageToProto(
    suite: ReallyMeHpkeSuite,
    sealedMessage: ReallyMeHpkeSealedMessage
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoHpkeSealedMessage {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoHpkeSealedMessage()
    proto.algorithm = hpkeSuiteIdentifierToProto(suite)
    proto.encapsulatedKey = Data(sealedMessage.encapsulatedKey)
    proto.ciphertext = Data(sealedMessage.ciphertext)
    return proto
  }

  public static func hpkeSealedMessageToProtoBytes(
    suite: ReallyMeHpkeSuite,
    sealedMessage: ReallyMeHpkeSealedMessage
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(hpkeSealedMessageToProto(suite: suite, sealedMessage: sealedMessage))
  }

  public static func hpkeSealedMessage(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoHpkeSealedMessage
  ) throws(ReallyMeCryptoError) -> ReallyMeHpkeSealedMessageProtoValue {
    ReallyMeHpkeSealedMessageProtoValue(
      sealedMessage: ReallyMeHpkeSealedMessage(
        encapsulatedKey: Array(value.encapsulatedKey), ciphertext: Array(value.ciphertext)),
      suite: try hpkeSuite(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm)
    )
  }

  public static func hpkeSealedMessage(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeHpkeSealedMessageProtoValue
  {
    do {
      return try hpkeSealedMessage(
        fromProto: ReallyMeProtoCryptoHpkeSealedMessage(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func verificationResultToProto(
    algorithm: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    valid: Bool
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult()
    proto.algorithm = algorithm
    proto.status = valid ? .valid : .invalid
    return proto
  }

  public static func verificationErrorToProto(
    algorithm: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
    error: ReallyMeCryptoError
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult()
    proto.algorithm = algorithm
    proto.status = .error
    proto.error = toProto(error)
    return proto
  }

  public static func verificationResultToProtoBytes(
    _ value: ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(value)
  }

  public static func verificationResult(fromProtoBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult
  {
    do {
      return try ReallyMeProtoCryptoVerificationResult(serializedBytes: bytes)
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func providerCapabilityToProto(
    _ value: ReallyMeProviderCapabilityProtoValue
  ) throws(ReallyMeCryptoError) -> ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapability {
    guard value.algorithm.algorithm != nil,
      value.family != .unspecified,
      value.status != .unspecified
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapability()
    proto.algorithm = value.algorithm
    proto.family = value.family
    proto.providerNames = value.providerNames
    proto.status = value.status
    proto.usesRust = value.usesRust
    return proto
  }

  public static func providerCapabilitySetToProto(
    _ values: [ReallyMeProviderCapabilityProtoValue]
  ) throws(ReallyMeCryptoError) -> ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet {
    var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet()
    var capabilities: [ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapability] = []
    capabilities.reserveCapacity(values.count)
    for value in values {
      capabilities.append(try providerCapabilityToProto(value))
    }
    proto.capabilities = capabilities
    return proto
  }

  public static func providerCapabilitySetToProtoBytes(
    _ values: [ReallyMeProviderCapabilityProtoValue]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try serialized(providerCapabilitySetToProto(values))
  }

  public static func providerCapabilitySet(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet
  ) throws(ReallyMeCryptoError) -> [ReallyMeProviderCapabilityProtoValue] {
    var capabilities: [ReallyMeProviderCapabilityProtoValue] = []
    capabilities.reserveCapacity(value.capabilities.count)
    for capability in value.capabilities {
      guard capability.hasAlgorithm,
        capability.family != .unspecified,
        capability.status != .unspecified
      else {
        throw ReallyMeCryptoError.invalidInput
      }
      capabilities.append(
        ReallyMeProviderCapabilityProtoValue(
          algorithm: capability.algorithm,
          family: capability.family,
          providerNames: capability.providerNames,
          status: capability.status,
          usesRust: capability.usesRust
        ))
    }
    return capabilities
  }

  public static func providerCapabilitySet(fromProtoBytes bytes: [UInt8])
    throws(ReallyMeCryptoError)
    -> [ReallyMeProviderCapabilityProtoValue]
  {
    do {
      return try providerCapabilitySet(
        fromProto: ReallyMeProtoCryptoProviderCapabilitySet(serializedBytes: bytes))
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

}
