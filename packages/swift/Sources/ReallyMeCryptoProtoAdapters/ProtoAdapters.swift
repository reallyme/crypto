// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

public struct ReallyMeSignatureKeyPairProtoValue: Sendable {
  public let algorithm: ReallyMeSignatureAlgorithm
  public let keyPair: ReallyMeSignatureKeyPair
}

public struct ReallyMeKeyAgreementKeyPairProtoValue: Sendable {
  public let algorithm: ReallyMeKeyAgreementAlgorithm
  public let keyPair: ReallyMeKeyAgreementKeyPair
}

public struct ReallyMeKemKeyPairProtoValue: Sendable {
  public let algorithm: ReallyMeKemAlgorithm
  public let keyPair: ReallyMeKemKeyPair
}

public struct ReallyMeKemEncapsulationProtoValue: Sendable {
  public let algorithm: ReallyMeKemAlgorithm
  public let encapsulation: ReallyMeKemEncapsulation
}

public struct ReallyMeHpkeSealedMessageProtoValue: Sendable {
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
  ) throws(ReallyMeCryptoWireErrorValidationError) -> ReallyMeCryptoWireError {
    if reason == .unspecified {
      throw ReallyMeCryptoWireErrorValidationError.unspecifiedReason
    }
    if case .UNRECOGNIZED = reason {
      guard
        ReallyMeCryptoProtoAdapters.reasonCodeMatchesBranch(
          branch: branch,
          reasonCode: reason.rawValue
        )
      else {
        throw ReallyMeCryptoWireErrorValidationError.reasonCodeOutOfRange
      }
      return ReallyMeCryptoWireError(uncheckedBranch: branch, reason: reason)
    }
    guard ReallyMeCryptoProtoAdapters.reasonMatchesBranch(branch: branch, reason: reason) else {
      throw ReallyMeCryptoWireErrorValidationError.branchReasonMismatch
    }
    return ReallyMeCryptoWireError(uncheckedBranch: branch, reason: reason)
  }

  init(
    uncheckedBranch branch: ReallyMeCryptoWireErrorBranch,
    reason: ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason
  ) {
    self.branch = branch
    self.reason = reason
  }
}

public enum ReallyMeCryptoProtoAdapters {}
