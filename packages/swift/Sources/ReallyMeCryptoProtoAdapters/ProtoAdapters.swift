// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import ReallyMeCrypto
import ReallyMeCryptoProto
import Foundation
import SwiftProtobuf

public struct ReallyMeSignatureKeyPairProtoValue: Equatable, Sendable {
    public let algorithm: ReallyMeSignatureAlgorithm
    public let keyPair: ReallyMeSignatureKeyPair
}

public struct ReallyMeKeyAgreementKeyPairProtoValue: Equatable, Sendable {
    public let algorithm: ReallyMeKeyAgreementAlgorithm
    public let keyPair: ReallyMeKeyAgreementKeyPair
}

public struct ReallyMeKemKeyPairProtoValue: Equatable, Sendable {
    public let algorithm: ReallyMeKemAlgorithm
    public let keyPair: ReallyMeKemKeyPair
}

public struct ReallyMeKemEncapsulationProtoValue: Equatable, Sendable {
    public let algorithm: ReallyMeKemAlgorithm
    public let encapsulation: ReallyMeKemEncapsulation
}

public struct ReallyMeHpkeSealedMessageProtoValue: Equatable, Sendable {
    public let sealedMessage: ReallyMeHpkeSealedMessage
    public let suite: ReallyMeHpkeSuite
}

public struct ReallyMeProviderCapabilityProtoValue: Equatable, Sendable {
    public let algorithm: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier
    public let family: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmFamily
    public let providerNames: [String]
    public let status: ReallyMeCryptoProto.ReallyMeProtoCryptoProviderSupportStatus
    public let usesRust: Bool

    public init(
        algorithm: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
        family: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmFamily,
        providerNames: [String],
        status: ReallyMeCryptoProto.ReallyMeProtoCryptoProviderSupportStatus,
        usesRust: Bool
    ) {
        self.algorithm = algorithm
        self.family = family
        self.providerNames = providerNames
        self.status = status
        self.usesRust = usesRust
    }
}

public enum ReallyMeCryptoWireErrorBranch: Equatable, Sendable {
    case primitive
    case provider
    case backend
}

public enum ReallyMeCryptoWireErrorValidationError: Error, Equatable, Sendable {
    case unspecifiedReason
    case branchReasonMismatch
    case reasonCodeOutOfRange
}

public struct ReallyMeCryptoWireError: Equatable, Sendable {
    public let branch: ReallyMeCryptoWireErrorBranch
    public let reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason

    public var reasonCode: Int {
        reason.rawValue
    }

    public static func tryNew(
        branch: ReallyMeCryptoWireErrorBranch,
        reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
    ) throws -> ReallyMeCryptoWireError {
        if reason == .unspecified {
            throw ReallyMeCryptoWireErrorValidationError.unspecifiedReason
        }
        if case .UNRECOGNIZED = reason {
            guard ReallyMeCryptoProtoAdapters.reasonCodeMatchesBranch(
                branch: branch,
                reasonCode: reason.rawValue
            ) else {
                throw ReallyMeCryptoWireErrorValidationError.reasonCodeOutOfRange
            }
            return ReallyMeCryptoWireError(uncheckedBranch: branch, reason: reason)
        }
        guard ReallyMeCryptoProtoAdapters.reasonMatchesBranch(branch: branch, reason: reason) else {
            throw ReallyMeCryptoWireErrorValidationError.branchReasonMismatch
        }
        return ReallyMeCryptoWireError(uncheckedBranch: branch, reason: reason)
    }

    fileprivate init(
        uncheckedBranch branch: ReallyMeCryptoWireErrorBranch,
        reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
    ) {
        self.branch = branch
        self.reason = reason
    }
}

public enum ReallyMeCryptoProtoStatus: Equatable, Sendable {
    case result
    case cryptoError
}

public struct ReallyMeCryptoProtoResult: Sendable, CustomDebugStringConvertible {
    public let status: ReallyMeCryptoProtoStatus
    private var storage: [UInt8]

    /// Returns a managed copy. Clear the returned array after processing when
    /// the operation may carry secret or PII-bearing bytes.
    public var bytes: [UInt8] {
        storage
    }

    public var isCryptoError: Bool {
        status == .cryptoError
    }

    public init(status: ReallyMeCryptoProtoStatus, bytes: [UInt8]) {
        self.status = status
        self.storage = bytes
    }

    /// Best-effort overwrite of this value's managed byte storage.
    public mutating func bestEffortClear() {
        _ = storage.withUnsafeMutableBytes { rawBuffer in
            rawBuffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
        storage.removeAll(keepingCapacity: false)
    }

    public var debugDescription: String {
        "ReallyMeCryptoProtoResult(status: \(status), bytes: <redacted>)"
    }
}

public enum ReallyMeCryptoProtoAdapters {
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

    public static func wireError(fromProtoErrorBytes bytes: [UInt8]) throws -> ReallyMeCryptoWireError {
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

    public static func wireErrorToProtoBytes(_ value: ReallyMeCryptoWireError) throws -> [UInt8] {
        do {
            return try wireErrorToProto(value).serializedBytes()
        } catch {
            throw ReallyMeCryptoError.providerFailure
        }
    }

    public static func protoResult(bytes: [UInt8]) -> ReallyMeCryptoProtoResult {
        ReallyMeCryptoProtoResult(status: .result, bytes: bytes)
    }

    public static func protoErrorResult(
        _ value: ReallyMeCryptoWireError
    ) throws -> ReallyMeCryptoProtoResult {
        ReallyMeCryptoProtoResult(
            status: .cryptoError,
            bytes: try wireErrorToProtoBytes(value)
        )
    }

    public static func protoErrorResult(
        _ value: ReallyMeCryptoError
    ) throws -> ReallyMeCryptoProtoResult {
        ReallyMeCryptoProtoResult(status: .cryptoError, bytes: try toProtoBytes(value))
    }

    public static func facadeError(fromWireError value: ReallyMeCryptoWireError) -> ReallyMeCryptoError {
        fromProto(value.reason)
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoCryptoError
    ) -> ReallyMeCryptoError {
        facadeError(fromWireError: wireError(fromProto: value))
    }

    public static func fromProtoErrorBytes(_ bytes: [UInt8]) throws -> ReallyMeCryptoError {
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

    public static func toProtoBytes(_ value: ReallyMeCryptoError) throws -> [UInt8] {
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
             .backendInvalidState,
             .backendInternal,
             .backendMalformedProtobuf,
             .backendMalformedJson,
             .backendResourceLimitExceeded:
            return .providerFailure
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
        ReallyMeCryptoWireError(uncheckedBranch: .backend, reason: .backendMalformedProtobuf)
    }

    fileprivate static func reasonMatchesBranch(
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

    fileprivate static func reasonCodeMatchesBranch(
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

    private static let primitiveCryptoErrorReasons: Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
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
    ]

    private static let providerCryptoErrorReasons: Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
        .providerUnsupportedAlgorithm,
        .providerUnsupportedBackend,
        .providerUnavailable,
        .providerRandomnessUnavailable,
    ]

    private static let backendCryptoErrorReasons: Set<ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason> = [
        .backendInvalidState,
        .backendInternal,
        .backendMalformedProtobuf,
        .backendMalformedJson,
        .backendResourceLimitExceeded,
    ]

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoJsonWebKey
    ) throws -> ReallyMeJwkKey {
        guard value.hasAlgorithm else {
            throw ReallyMeCryptoError.invalidInput
        }
        let algorithm = try jwkAlgorithm(fromProto: value.algorithm)
        let publicKey = Array(value.publicKey)
        let jwk = try ReallyMeJwk.toJwk(algorithm: algorithm, publicKey: publicKey)
        if !value.canonicalJcs.isEmpty {
            guard let canonicalJcs = String(data: value.canonicalJcs, encoding: .utf8) else {
                throw ReallyMeCryptoError.invalidInput
            }
            guard canonicalJcs == (try ReallyMeJwk.toJcs(jwk)) else {
                throw ReallyMeCryptoError.invalidInput
            }
        }
        return ReallyMeJwkKey(algorithm: algorithm, publicKey: publicKey, jwk: jwk)
    }

    public static func fromProtoJsonWebKeyBytes(_ bytes: [UInt8]) throws -> ReallyMeJwkKey {
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
    ) throws -> ReallyMeCryptoProto.ReallyMeProtoJsonWebKey {
        var key = ReallyMeCryptoProto.ReallyMeProtoJsonWebKey()
        key.algorithm = try jwkAlgorithmToProto(value.algorithm)
        key.publicKey = Data(value.publicKey)
        key.canonicalJcs = Data(try ReallyMeJwk.toJcs(value.jwk).utf8)
        return key
    }

    public static func toProtoBytes(_ value: ReallyMeJwkKey) throws -> [UInt8] {
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
    ) throws -> [ReallyMeJwkKey] {
        try value.keys.map { try fromProto($0) }
    }

    public static func fromProtoJsonWebKeySetBytes(_ bytes: [UInt8]) throws -> [ReallyMeJwkKey] {
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
    ) throws -> ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet {
        var keySet = ReallyMeCryptoProto.ReallyMeProtoJsonWebKeySet()
        keySet.keys = try values.map { try toProto($0) }
        return keySet
    }

    public static func toProtoJsonWebKeySetBytes(_ values: [ReallyMeJwkKey]) throws -> [UInt8] {
        do {
            return try toProto(values).serializedBytes()
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.providerFailure
        }
    }

    public static func signatureKeyPairToProto(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair
    ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair {
        keyPairToProto(algorithm: signatureAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    }

    public static func signatureKeyPairToProtoBytes(
        algorithm: ReallyMeSignatureAlgorithm,
        keyPair: ReallyMeSignatureKeyPair
    ) throws -> [UInt8] {
        try serialized(signatureKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
    }

    public static func signatureKeyPair(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
    ) throws -> ReallyMeSignatureKeyPairProtoValue {
        ReallyMeSignatureKeyPairProtoValue(
            algorithm: try signatureAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
            keyPair: ReallyMeSignatureKeyPair(publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
        )
    }

    public static func signatureKeyPair(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeSignatureKeyPairProtoValue {
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
        keyPairToProto(algorithm: keyAgreementAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    }

    public static func keyAgreementKeyPairToProtoBytes(
        algorithm: ReallyMeKeyAgreementAlgorithm,
        keyPair: ReallyMeKeyAgreementKeyPair
    ) throws -> [UInt8] {
        try serialized(keyAgreementKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
    }

    public static func keyAgreementKeyPair(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
    ) throws -> ReallyMeKeyAgreementKeyPairProtoValue {
        ReallyMeKeyAgreementKeyPairProtoValue(
            algorithm: try keyAgreementAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
            keyPair: ReallyMeKeyAgreementKeyPair(publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
        )
    }

    public static func keyAgreementKeyPair(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeKeyAgreementKeyPairProtoValue {
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
        keyPairToProto(algorithm: kemAlgorithmIdentifierToProto(algorithm), publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    }

    public static func kemKeyPairToProtoBytes(
        algorithm: ReallyMeKemAlgorithm,
        keyPair: ReallyMeKemKeyPair
    ) throws -> [UInt8] {
        try serialized(kemKeyPairToProto(algorithm: algorithm, keyPair: keyPair))
    }

    public static func kemKeyPair(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKeyPair
    ) throws -> ReallyMeKemKeyPairProtoValue {
        ReallyMeKemKeyPairProtoValue(
            algorithm: try kemAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
            keyPair: ReallyMeKemKeyPair(publicKey: Array(value.publicKey), secretKey: Array(value.secretKey))
        )
    }

    public static func kemKeyPair(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeKemKeyPairProtoValue {
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
    ) throws -> [UInt8] {
        try serialized(kemEncapsulationToProto(algorithm: algorithm, encapsulation: encapsulation))
    }

    public static func kemEncapsulation(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoKemEncapsulation
    ) throws -> ReallyMeKemEncapsulationProtoValue {
        ReallyMeKemEncapsulationProtoValue(
            algorithm: try kemAlgorithm(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm),
            encapsulation: ReallyMeKemEncapsulation(sharedSecret: Array(value.sharedSecret), ciphertext: Array(value.ciphertext))
        )
    }

    public static func kemEncapsulation(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeKemEncapsulationProtoValue {
        do {
            return try kemEncapsulation(fromProto: ReallyMeProtoCryptoKemEncapsulation(serializedBytes: bytes))
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
    ) throws -> [UInt8] {
        try serialized(hpkeSealedMessageToProto(suite: suite, sealedMessage: sealedMessage))
    }

    public static func hpkeSealedMessage(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoHpkeSealedMessage
    ) throws -> ReallyMeHpkeSealedMessageProtoValue {
        ReallyMeHpkeSealedMessageProtoValue(
            sealedMessage: ReallyMeHpkeSealedMessage(encapsulatedKey: Array(value.encapsulatedKey), ciphertext: Array(value.ciphertext)),
            suite: try hpkeSuite(fromIdentifier: value.algorithm, isPresent: value.hasAlgorithm)
        )
    }

    public static func hpkeSealedMessage(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeHpkeSealedMessageProtoValue {
        do {
            return try hpkeSealedMessage(fromProto: ReallyMeProtoCryptoHpkeSealedMessage(serializedBytes: bytes))
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
    ) throws -> [UInt8] {
        try serialized(value)
    }

    public static func verificationResult(fromProtoBytes bytes: [UInt8]) throws -> ReallyMeCryptoProto.ReallyMeProtoCryptoVerificationResult {
        do {
            return try ReallyMeProtoCryptoVerificationResult(serializedBytes: bytes)
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    public static func providerCapabilityToProto(
        _ value: ReallyMeProviderCapabilityProtoValue
    ) throws -> ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapability {
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
    ) throws -> ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet {
        var proto = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet()
        proto.capabilities = try values.map { try providerCapabilityToProto($0) }
        return proto
    }

    public static func providerCapabilitySetToProtoBytes(
        _ values: [ReallyMeProviderCapabilityProtoValue]
    ) throws -> [UInt8] {
        try serialized(providerCapabilitySetToProto(values))
    }

    public static func providerCapabilitySet(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoProviderCapabilitySet
    ) throws -> [ReallyMeProviderCapabilityProtoValue] {
        try value.capabilities.map { capability in
            guard capability.hasAlgorithm,
                  capability.family != .unspecified,
                  capability.status != .unspecified
            else {
                throw ReallyMeCryptoError.invalidInput
            }
            return ReallyMeProviderCapabilityProtoValue(
                algorithm: capability.algorithm,
                family: capability.family,
                providerNames: capability.providerNames,
                status: capability.status,
                usesRust: capability.usesRust
            )
        }
    }

    public static func providerCapabilitySet(fromProtoBytes bytes: [UInt8]) throws -> [ReallyMeProviderCapabilityProtoValue] {
        do {
            return try providerCapabilitySet(fromProto: ReallyMeProtoCryptoProviderCapabilitySet(serializedBytes: bytes))
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm
    ) throws -> ReallyMeSignatureAlgorithm {
        switch value {
        case .ed25519:
            .ed25519
        case .ecdsaP256Sha256:
            .ecdsaP256Sha256
        case .ecdsaP384Sha384:
            .ecdsaP384Sha384
        case .ecdsaP521Sha512:
            .ecdsaP521Sha512
        case .ecdsaSecp256K1Sha256:
            .ecdsaSecp256k1Sha256
        case .bip340SchnorrSecp256K1Sha256:
            .bip340SchnorrSecp256k1Sha256
        case .rsaPkcs1V15Sha1:
            .rsaPkcs1v15Sha1
        case .rsaPkcs1V15Sha256:
            .rsaPkcs1v15Sha256
        case .rsaPkcs1V15Sha384:
            .rsaPkcs1v15Sha384
        case .rsaPkcs1V15Sha512:
            .rsaPkcs1v15Sha512
        case .rsaPssSha1Mgf1Sha1:
            .rsaPssSha1Mgf1Sha1
        case .rsaPssSha256Mgf1Sha256:
            .rsaPssSha256Mgf1Sha256
        case .rsaPssSha384Mgf1Sha384:
            .rsaPssSha384Mgf1Sha384
        case .rsaPssSha512Mgf1Sha512:
            .rsaPssSha512Mgf1Sha512
        case .mlDsa44:
            .mlDsa44
        case .mlDsa65:
            .mlDsa65
        case .mlDsa87:
            .mlDsa87
        case .slhDsaSha2128S:
            .slhDsaSha2_128s
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeSignatureAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm {
        switch value {
        case .ed25519:
            .ed25519
        case .ecdsaP256Sha256:
            .ecdsaP256Sha256
        case .ecdsaP384Sha384:
            .ecdsaP384Sha384
        case .ecdsaP521Sha512:
            .ecdsaP521Sha512
        case .ecdsaSecp256k1Sha256:
            .ecdsaSecp256K1Sha256
        case .bip340SchnorrSecp256k1Sha256:
            .bip340SchnorrSecp256K1Sha256
        case .rsaPkcs1v15Sha1:
            .rsaPkcs1V15Sha1
        case .rsaPkcs1v15Sha256:
            .rsaPkcs1V15Sha256
        case .rsaPkcs1v15Sha384:
            .rsaPkcs1V15Sha384
        case .rsaPkcs1v15Sha512:
            .rsaPkcs1V15Sha512
        case .rsaPssSha1Mgf1Sha1:
            .rsaPssSha1Mgf1Sha1
        case .rsaPssSha256Mgf1Sha256:
            .rsaPssSha256Mgf1Sha256
        case .rsaPssSha384Mgf1Sha384:
            .rsaPssSha384Mgf1Sha384
        case .rsaPssSha512Mgf1Sha512:
            .rsaPssSha512Mgf1Sha512
        case .mlDsa44:
            .mlDsa44
        case .mlDsa65:
            .mlDsa65
        case .mlDsa87:
            .mlDsa87
        case .slhDsaSha2_128s:
            .slhDsaSha2128S
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm
    ) throws -> ReallyMeHashAlgorithm {
        switch value {
        case .sha2256:
            .sha2_256
        case .sha2384:
            .sha2_384
        case .sha2512:
            .sha2_512
        case .sha3224:
            .sha3_224
        case .sha3256:
            .sha3_256
        case .sha3384:
            .sha3_384
        case .sha3512:
            .sha3_512
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeHashAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm {
        switch value {
        case .sha2_256:
            .sha2256
        case .sha2_384:
            .sha2384
        case .sha2_512:
            .sha2512
        case .sha3_224:
            .sha3224
        case .sha3_256:
            .sha3256
        case .sha3_384:
            .sha3384
        case .sha3_512:
            .sha3512
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm
    ) throws -> ReallyMeAeadAlgorithm {
        switch value {
        case .aes128Gcm:
            .aes128Gcm
        case .aes192Gcm:
            .aes192Gcm
        case .aes256Gcm:
            .aes256Gcm
        case .aes256GcmSiv:
            .aes256GcmSiv
        case .chacha20Poly1305:
            .chacha20Poly1305
        case .xchacha20Poly1305:
            .xchacha20Poly1305
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeAeadAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm {
        switch value {
        case .aes128Gcm:
            .aes128Gcm
        case .aes192Gcm:
            .aes192Gcm
        case .aes256Gcm:
            .aes256Gcm
        case .aes256GcmSiv:
            .aes256GcmSiv
        case .chacha20Poly1305:
            .chacha20Poly1305
        case .xchacha20Poly1305:
            .xchacha20Poly1305
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm
    ) throws -> ReallyMeKemAlgorithm {
        switch value {
        case .mlKem512:
            .mlKem512
        case .mlKem768:
            .mlKem768
        case .mlKem1024:
            .mlKem1024
        case .xWing768:
            .xWing768
        case .xWing1024:
            .xWing1024
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKemAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm {
        switch value {
        case .mlKem512:
            .mlKem512
        case .mlKem768:
            .mlKem768
        case .mlKem1024:
            .mlKem1024
        case .xWing768:
            .xWing768
        case .xWing1024:
            .xWing1024
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm
    ) throws -> ReallyMeKeyAgreementAlgorithm {
        switch value {
        case .x25519:
            .x25519
        case .p256Ecdh:
            .p256Ecdh
        case .p384Ecdh:
            .p384Ecdh
        case .p521Ecdh:
            .p521Ecdh
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKeyAgreementAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm {
        switch value {
        case .x25519:
            .x25519
        case .p256Ecdh:
            .p256Ecdh
        case .p384Ecdh:
            .p384Ecdh
        case .p521Ecdh:
            .p521Ecdh
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm
    ) throws -> ReallyMeMacAlgorithm {
        switch value {
        case .hmacSha256:
            .hmacSha256
        case .hmacSha512:
            .hmacSha512
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeMacAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm {
        switch value {
        case .hmacSha256:
            .hmacSha256
        case .hmacSha512:
            .hmacSha512
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm
    ) throws -> ReallyMeKdfAlgorithm {
        switch value {
        case .hkdfSha256:
            .hkdfSha256
        case .argon2ID:
            .argon2id
        case .pbkdf2HmacSha256:
            .pbkdf2HmacSha256
        case .pbkdf2HmacSha512:
            .pbkdf2HmacSha512
        case .jwaConcatKdfSha256:
            .jwaConcatKdfSha256
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKdfAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm {
        switch value {
        case .hkdfSha256:
            .hkdfSha256
        case .argon2id:
            .argon2ID
        case .pbkdf2HmacSha256:
            .pbkdf2HmacSha256
        case .pbkdf2HmacSha512:
            .pbkdf2HmacSha512
        case .jwaConcatKdfSha256:
            .jwaConcatKdfSha256
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm
    ) throws -> ReallyMeKeyWrapAlgorithm {
        switch value {
        case .aes256Kw:
            .aes256Kw
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeKeyWrapAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm {
        switch value {
        case .aes256Kw:
            .aes256Kw
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoHpkeSuite
    ) throws -> ReallyMeHpkeSuite {
        switch value {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
            .dhkemP256HkdfSha256HkdfSha256Aes256Gcm
        case .dhkemX25519HkdfSha256HkdfSha256Chacha20Poly1305:
            .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeHpkeSuite
    ) -> ReallyMeCryptoProto.ReallyMeProtoHpkeSuite {
        switch value {
        case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
            .dhkemP256HkdfSha256HkdfSha256Aes256Gcm
        case .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
            .dhkemX25519HkdfSha256HkdfSha256Chacha20Poly1305
        }
    }

    public static func fromProto(
        _ value: ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm
    ) throws -> ReallyMeMulticodecKeyAlgorithm {
        switch value {
        case .ed25519Pub:
            .ed25519PublicKey
        case .x25519Pub:
            .x25519PublicKey
        case .secp256K1Pub:
            .secp256k1PublicKey
        case .p256Pub:
            .p256PublicKey
        case .p384Pub:
            .p384PublicKey
        case .p521Pub:
            .p521PublicKey
        case .ed448Pub:
            .ed448PublicKey
        case .rsaPub:
            .rsaPublicKey
        case .mlKem512Pub:
            .mlKem512PublicKey
        case .mlKem768Pub:
            .mlKem768PublicKey
        case .mlKem1024Pub:
            .mlKem1024PublicKey
        case .mlDsa44Pub:
            .mlDsa44PublicKey
        case .mlDsa65Pub:
            .mlDsa65PublicKey
        case .mlDsa87Pub:
            .mlDsa87PublicKey
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    public static func toProto(
        _ value: ReallyMeMulticodecKeyAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm {
        switch value {
        case .ed25519PublicKey:
            .ed25519Pub
        case .x25519PublicKey:
            .x25519Pub
        case .secp256k1PublicKey:
            .secp256K1Pub
        case .p256PublicKey:
            .p256Pub
        case .p384PublicKey:
            .p384Pub
        case .p521PublicKey:
            .p521Pub
        case .ed448PublicKey:
            .ed448Pub
        case .rsaPublicKey:
            .rsaPub
        case .mlKem512PublicKey:
            .mlKem512Pub
        case .mlKem768PublicKey:
            .mlKem768Pub
        case .mlKem1024PublicKey:
            .mlKem1024Pub
        case .mlDsa44PublicKey:
            .mlDsa44Pub
        case .mlDsa65PublicKey:
            .mlDsa65Pub
        case .mlDsa87PublicKey:
            .mlDsa87Pub
        }
    }

    private static func serialized<T: SwiftProtobuf.Message>(_ value: T) throws -> [UInt8] {
        do {
            return try value.serializedBytes()
        } catch {
            throw ReallyMeCryptoError.providerFailure
        }
    }

    private static func keyPairToProto(
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

    private static func signatureAlgorithmIdentifierToProto(
        _ value: ReallyMeSignatureAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
        var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
        algorithm.signature = toProto(value)
        return algorithm
    }

    private static func keyAgreementAlgorithmIdentifierToProto(
        _ value: ReallyMeKeyAgreementAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
        var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
        algorithm.keyAgreement = toProto(value)
        return algorithm
    }

    private static func kemAlgorithmIdentifierToProto(
        _ value: ReallyMeKemAlgorithm
    ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
        var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
        algorithm.kem = toProto(value)
        return algorithm
    }

    private static func hpkeSuiteIdentifierToProto(
        _ value: ReallyMeHpkeSuite
    ) -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
        var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
        algorithm.hpke = toProto(value)
        return algorithm
    }

    private static func signatureAlgorithm(
        fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
        isPresent: Bool
    ) throws -> ReallyMeSignatureAlgorithm {
        guard isPresent else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard case .signature(let signature)? = value.algorithm else {
            throw ReallyMeCryptoError.invalidInput
        }
        return try fromProto(signature)
    }

    private static func keyAgreementAlgorithm(
        fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
        isPresent: Bool
    ) throws -> ReallyMeKeyAgreementAlgorithm {
        guard isPresent else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard case .keyAgreement(let keyAgreement)? = value.algorithm else {
            throw ReallyMeCryptoError.invalidInput
        }
        return try fromProto(keyAgreement)
    }

    private static func kemAlgorithm(
        fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
        isPresent: Bool
    ) throws -> ReallyMeKemAlgorithm {
        guard isPresent else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard case .kem(let kem)? = value.algorithm else {
            throw ReallyMeCryptoError.invalidInput
        }
        return try fromProto(kem)
    }

    private static func hpkeSuite(
        fromIdentifier value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier,
        isPresent: Bool
    ) throws -> ReallyMeHpkeSuite {
        guard isPresent else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard case .hpke(let hpke)? = value.algorithm else {
            throw ReallyMeCryptoError.invalidInput
        }
        return try fromProto(hpke)
    }

    private static func jwkAlgorithmToProto(
        _ value: ReallyMeJwkAlgorithm
    ) throws -> ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier {
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
        case .xWing1024:
            algorithm.kem = .xWing1024
        }
        return algorithm
    }

    private static func jwkAlgorithm(
        fromProto value: ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier
    ) throws -> ReallyMeJwkAlgorithm {
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
            case .xWing1024:
                return .xWing1024
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
