// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

/// JWA ECDH-ES Concat KDF over SHA-256.
///
/// This helper owns only the cryptographic derivation. Compact JWE parsing,
/// header policy, `alg`/`enc` validation, and payload decoding belong in the
/// JOSE layer that calls it.
public enum ReallyMeJwaConcatKdf {
    public static let sha256DigestLength = 32
    public static let maxSharedSecretLength = 4096
    public static let maxInfoLength = 4096
    public static let minOutputLength = 1
    public static let maxOutputLength = 4096

    public static func deriveSha256(
        sharedSecret: [UInt8],
        algorithmId: [UInt8],
        partyUInfo: [UInt8],
        partyVInfo: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        try validate(
            sharedSecret: sharedSecret,
            algorithmId: algorithmId,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            outputLength: outputLength
        )

        let outputBits = outputLength * 8
        var otherInfo = try buildOtherInfo(
            algorithmId: algorithmId,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            outputBits: UInt32(outputBits)
        )
        let reps = (outputLength + sha256DigestLength - 1) / sha256DigestLength
        var derived = [UInt8]()
        derived.reserveCapacity(reps * sha256DigestLength)

        for counter in 1...reps {
            var hasher = SHA256()
            hasher.update(data: Data(uint32be(UInt32(counter))))
            hasher.update(data: Data(sharedSecret))
            hasher.update(data: Data(otherInfo))
            derived.append(contentsOf: hasher.finalize())
        }

        let output = Array(derived.prefix(outputLength))
        ReallyMeCryptoMemory.bestEffortClear(&derived)
        ReallyMeCryptoMemory.bestEffortClear(&otherInfo)
        return output
    }

    private static func validate(
        sharedSecret: [UInt8],
        algorithmId: [UInt8],
        partyUInfo: [UInt8],
        partyVInfo: [UInt8],
        outputLength: Int
    ) throws {
        guard !sharedSecret.isEmpty,
              sharedSecret.count <= maxSharedSecretLength,
              !algorithmId.isEmpty,
              algorithmId.count <= maxInfoLength,
              partyUInfo.count <= maxInfoLength,
              partyVInfo.count <= maxInfoLength,
              (minOutputLength...maxOutputLength).contains(outputLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private static func buildOtherInfo(
        algorithmId: [UInt8],
        partyUInfo: [UInt8],
        partyVInfo: [UInt8],
        outputBits: UInt32
    ) throws -> [UInt8] {
        var otherInfo = [UInt8]()
        otherInfo.reserveCapacity(
            lengthPrefixedCapacity(algorithmId)
                + lengthPrefixedCapacity(partyUInfo)
                + lengthPrefixedCapacity(partyVInfo)
                + 4
        )
        try appendLengthPrefixed(algorithmId, to: &otherInfo)
        try appendLengthPrefixed(partyUInfo, to: &otherInfo)
        try appendLengthPrefixed(partyVInfo, to: &otherInfo)
        otherInfo.append(contentsOf: uint32be(outputBits))
        return otherInfo
    }

    private static func lengthPrefixedCapacity(_ bytes: [UInt8]) -> Int {
        4 + bytes.count
    }

    private static func appendLengthPrefixed(_ bytes: [UInt8], to output: inout [UInt8]) throws {
        guard let length = UInt32(exactly: bytes.count) else {
            throw ReallyMeCryptoError.invalidInput
        }
        output.append(contentsOf: uint32be(length))
        output.append(contentsOf: bytes)
    }

    private static func uint32be(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff),
        ]
    }
}
