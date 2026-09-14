// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

extension ReallyMeCryptoProtoAdapters {
  public static func wireError(
    fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoError
  ) -> ReallyMeCryptoWireError {
    switch value.error {
    case .primitive(let error):
      return strictWireError(branch: .primitive, reason: error.reason)
    case .provider(let error):
      return strictWireError(branch: .provider, reason: error.reason)
    case .backend(let error):
      return strictWireError(branch: .backend, reason: error.reason)
    case nil:
      return malformedCryptoErrorEnvelope()
    }
  }

  public static func wireError(fromProtoErrorBytes bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeCryptoWireError
  {
    do {
      let error = try ReallyMeCryptoProto.ReallyMeProtoCryptoError(
        serializedBytes: bytes
      )
      return wireError(fromProto: error)
    } catch {
      return malformedCryptoErrorEnvelope()
    }
  }

  public static func wireErrorToProto(
    _ value: ReallyMeCryptoWireError
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoError {
    var error = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
    switch value.branch {
    case .primitive:
      var primitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
      primitive.reason = value.reason
      error.primitive = primitive
    case .provider:
      var provider = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderError()
      provider.reason = value.reason
      error.provider = provider
    case .backend:
      var backend = ReallyMeCryptoProto.ReallyMeProtoCryptoBackendError()
      backend.reason = value.reason
      error.backend = backend
    }
    return error
  }

  public static func wireErrorToProtoBytes(_ value: ReallyMeCryptoWireError)
    throws(ReallyMeCryptoError) -> [UInt8]
  {
    do {
      return try wireErrorToProto(value).serializedBytes()
    } catch {
      throw ReallyMeCryptoError.providerFailure
    }
  }

  public static func facadeError(fromWireError value: ReallyMeCryptoWireError)
    -> ReallyMeCryptoError
  {
    fromProto(value.reason)
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoCryptoError
  ) -> ReallyMeCryptoError {
    facadeError(fromWireError: wireError(fromProto: value))
  }

  public static func fromProtoErrorBytes(_ bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeCryptoError
  {
    facadeError(fromWireError: try wireError(fromProtoErrorBytes: bytes))
  }

  public static func toProto(
    _ value: ReallyMeCryptoError
  ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoError {
    var error = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
    switch value {
    case .invalidInput:
      var primitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
      primitive.reason = .primitiveInvalidParameter
      error.primitive = primitive
    case .invalidSignature:
      var primitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
      primitive.reason = .primitiveInvalidSignature
      error.primitive = primitive
    case .authenticationFailed:
      var primitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
      primitive.reason = .primitiveAuthenticationFailed
      error.primitive = primitive
    case .unsupportedAlgorithm:
      var provider = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderError()
      provider.reason = .providerUnsupportedAlgorithm
      error.provider = provider
    case .unsupportedPlatform:
      var provider = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderError()
      provider.reason = .providerUnsupportedBackend
      error.provider = provider
    case .providerFailure,
      .dynamicLibraryNotFound,
      .dynamicLibraryLoadFailed,
      .symbolNotFound:
      var backend = ReallyMeCryptoProto.ReallyMeProtoCryptoBackendError()
      backend.reason = .backendInternal
      error.backend = backend
    }
    return error
  }

  public static func toProtoBytes(_ value: ReallyMeCryptoError) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    do {
      return try toProto(value).serializedBytes()
    } catch {
      throw ReallyMeCryptoError.providerFailure
    }
  }

  private static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
  ) -> ReallyMeCryptoError {
    switch value {
    case .primitiveInvalidSignature,
      .primitiveVerificationFailed:
      return .invalidSignature
    case .primitiveAuthenticationFailed:
      return .authenticationFailed
    case .providerUnsupportedAlgorithm,
      .providerUnsupportedBackend:
      return .unsupportedAlgorithm
    case .providerUnavailable,
      .providerRandomnessUnavailable,
      .providerKeyExists,
      .providerKeyNotFound,
      .providerAccessDenied,
      .providerUserAuthenticationRequired,
      .providerUserCanceled,
      .providerHardwareRejectedKey,
      .backendInvalidState,
      .backendInternal:
      return .providerFailure
    case .providerHardwareUnavailable:
      return .unsupportedPlatform
    case .primitiveInvalidParameter,
      .primitiveInvalidLength,
      .primitiveInvalidKey,
      .primitiveInvalidPublicKey,
      .primitiveInvalidPrivateKey,
      .primitiveInvalidNonce,
      .primitiveInvalidSalt,
      .primitiveInvalidPassword,
      .primitiveInvalidEncoding,
      .primitiveMalformedCiphertext,
      .primitiveInvalidTag,
      .primitiveInvalidSharedSecret,
      .primitiveMalformedProtobuf,
      .primitiveMalformedJson,
      .primitiveResourceLimitExceeded,
      .primitiveMissingOperation,
      .unspecified,
      .UNRECOGNIZED:
      return .invalidInput
    }
  }

  private static func strictWireError(
    branch: ReallyMeCryptoWireErrorBranch,
    reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
  ) -> ReallyMeCryptoWireError {
    do {
      return try ReallyMeCryptoWireError.tryNew(branch: branch, reason: reason)
    } catch {
      return malformedCryptoErrorEnvelope()
    }
  }

  private static func malformedCryptoErrorEnvelope() -> ReallyMeCryptoWireError {
    ReallyMeCryptoWireError(uncheckedBranch: .primitive, reason: .primitiveMalformedProtobuf)
  }

  static func reasonMatchesBranch(
    branch: ReallyMeCryptoWireErrorBranch,
    reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
  ) -> Bool {
    switch branch {
    case .primitive:
      return primitiveCryptoErrorReasons.contains(reason)
    case .provider:
      return providerCryptoErrorReasons.contains(reason)
    case .backend:
      return backendCryptoErrorReasons.contains(reason)
    }
  }

  static func reasonCodeMatchesBranch(
    branch: ReallyMeCryptoWireErrorBranch,
    reasonCode: Int
  ) -> Bool {
    switch branch {
    case .primitive:
      return (100...199).contains(reasonCode)
    case .provider:
      return (200...299).contains(reasonCode)
    case .backend:
      return (300...399).contains(reasonCode)
    }
  }

  private static let primitiveCryptoErrorReasons:
    Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
      .primitiveInvalidParameter,
      .primitiveInvalidLength,
      .primitiveInvalidKey,
      .primitiveInvalidPublicKey,
      .primitiveInvalidPrivateKey,
      .primitiveInvalidNonce,
      .primitiveInvalidSalt,
      .primitiveInvalidPassword,
      .primitiveInvalidEncoding,
      .primitiveInvalidSignature,
      .primitiveVerificationFailed,
      .primitiveAuthenticationFailed,
      .primitiveMalformedCiphertext,
      .primitiveInvalidTag,
      .primitiveInvalidSharedSecret,
      .primitiveMalformedProtobuf,
      .primitiveMalformedJson,
      .primitiveResourceLimitExceeded,
      .primitiveMissingOperation,
    ]

  private static let providerCryptoErrorReasons:
    Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
      .providerUnsupportedAlgorithm,
      .providerUnsupportedBackend,
      .providerUnavailable,
      .providerRandomnessUnavailable,
      .providerKeyExists,
      .providerKeyNotFound,
      .providerAccessDenied,
      .providerUserAuthenticationRequired,
      .providerUserCanceled,
      .providerHardwareUnavailable,
      .providerHardwareRejectedKey,
    ]

  private static let backendCryptoErrorReasons:
    Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
      .backendInvalidState,
      .backendInternal,
    ]

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoJsonWebKey
  ) throws(ReallyMeCryptoError) -> ReallyMeJwkKey {
    guard value.hasAlgorithm else {
      throw ReallyMeCryptoError.invalidInput
    }
    let algorithm = try jwkAlgorithm(fromProto: value.algorithm)
    let publicKey = Array(value.publicKey)
    let jwk = try ReallyMeJwk.toJwk(algorithm: algorithm, publicKey: publicKey)
    if value.canonicalJcs.isEmpty == false {
      guard let canonicalJcs = String(data: value.canonicalJcs, encoding: .utf8) else {
        throw ReallyMeCryptoError.invalidInput
      }
      guard canonicalJcs == (try ReallyMeJwk.toJcs(jwk)) else {
        throw ReallyMeCryptoError.invalidInput
      }
    }
    return ReallyMeJwkKey(algorithm: algorithm, publicKey: publicKey, jwk: jwk)
  }

  public static func fromProtoJsonWebKeyBytes(_ bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeJwkKey
  {
    do {
      let key = try ReallyMeCryptoProto.ReallyMeProtoJsonWebKey(serializedBytes: bytes)
      return try fromProto(key)
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func toProto(
    _ value: ReallyMeJwkKey
  ) throws(ReallyMeCryptoError) -> ReallyMeCryptoProto.ReallyMeProtoJsonWebKey {
    var key = ReallyMeCryptoProto.ReallyMeProtoJsonWebKey()
    key.algorithm = try jwkAlgorithmToProto(value.algorithm)
    key.publicKey = Data(value.publicKey)
    key.canonicalJcs = Data(try ReallyMeJwk.toJcs(value.jwk).utf8)
    return key
  }

  public static func toProtoBytes(_ value: ReallyMeJwkKey) throws(ReallyMeCryptoError) -> [UInt8] {
    do {
      return try toProto(value).serializedBytes()
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.providerFailure
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet
  ) throws(ReallyMeCryptoError) -> [ReallyMeJwkKey] {
    var keys: [ReallyMeJwkKey] = []
    keys.reserveCapacity(value.keys.count)
    for value in value.keys {
      keys.append(try fromProto(value))
    }
    return keys
  }

  public static func fromProtoJsonWebKeySetBytes(_ bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> [ReallyMeJwkKey]
  {
    do {
      let keySet = try ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet(
        serializedBytes: bytes
      )
      return try fromProto(keySet)
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  public static func toProto(
    _ values: [ReallyMeJwkKey]
  ) throws(ReallyMeCryptoError) -> ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet {
    var keySet = ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet()
    var keys: [ReallyMeCryptoProto.ReallyMeProtoJsonWebKey] = []
    keys.reserveCapacity(values.count)
    for value in values {
      keys.append(try toProto(value))
    }
    keySet.keys = keys
    return keySet
  }

  public static func toProtoJsonWebKeySetBytes(_ values: [ReallyMeJwkKey])
    throws(ReallyMeCryptoError) -> [UInt8]
  {
    do {
      return try toProto(values).serializedBytes()
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.providerFailure
    }
  }

}
