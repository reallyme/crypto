// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Status values returned by `crypto-ffi`.
///
/// The SDK maps the C ABI status vocabulary into the package's typed errors at
/// the boundary. Keeping this mapping in one place prevents individual
/// provider wrappers from disagreeing about tamper, shape, and provider faults.
public enum ReallyMeRustCAbiStatus {
    public static let ok: Int32 = 0
    public static let invalidArgument: Int32 = -1
    public static let invalidKey: Int32 = -2
    public static let invalidSignature: Int32 = -3
    public static let invalidCiphertext: Int32 = -4
    public static let bufferTooSmall: Int32 = -5
    public static let authenticationFailed: Int32 = -6
    public static let internalError: Int32 = -128

    public static func throwIfError(_ status: Int32) throws {
        switch status {
        case ok:
            return
        case invalidArgument, invalidKey, invalidCiphertext:
            throw ReallyMeCryptoError.invalidInput
        case invalidSignature:
            throw ReallyMeCryptoError.invalidSignature
        case bufferTooSmall:
            // A too-small output buffer is a wrapper-side sizing fault, not
            // caller-malformed input; surface it as a provider failure so it
            // is not mistaken for bad user input.
            throw ReallyMeCryptoError.providerFailure
        case authenticationFailed:
            throw ReallyMeCryptoError.authenticationFailed
        case internalError:
            throw ReallyMeCryptoError.providerFailure
        default:
            throw ReallyMeCryptoError.providerFailure
        }
    }
}
