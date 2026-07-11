// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Typed Swift package errors. Variants intentionally carry no secret or
/// user-provided bytes so callers can log the error code without leaking key
/// material or PII.
public enum ReallyMeCryptoError: Error, Equatable, Sendable {
    case unsupportedPlatform
    case dynamicLibraryNotFound
    case dynamicLibraryLoadFailed
    case symbolNotFound
    case invalidInput
    case invalidSignature
    case authenticationFailed
    case providerFailure
    case unsupportedAlgorithm
}
