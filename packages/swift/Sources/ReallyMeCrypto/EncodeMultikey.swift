// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let multibaseBase58BtcPrefix = UInt8(ascii: "z")

public enum ReallyMeMultikey {
    public static func encode(
        _ algorithm: ReallyMeMulticodecKeyAlgorithm,
        publicKey: [UInt8]
    ) throws -> String {
        let spec = ReallyMeMulticodec.spec(for: algorithm)
        try validateKeyLength(spec: spec, publicKey: publicKey)

        guard spec.prefix.count <= Int.max - publicKey.count else {
            throw ReallyMeCryptoError.invalidInput
        }

        let payloadCapacity = spec.prefix.count + publicKey.count
        var payload = [UInt8]()
        payload.reserveCapacity(payloadCapacity)
        payload.append(contentsOf: spec.prefix)
        payload.append(contentsOf: publicKey)

        return String(UnicodeScalar(multibaseBase58BtcPrefix)) + (try ReallyMeBase58Btc.encode(payload))
    }

    public static func parse(_ multikey: String) throws -> ReallyMeParsedMultikey {
        let bytes = Array(multikey.utf8)
        guard bytes.first == multibaseBase58BtcPrefix else {
            throw ReallyMeCryptoError.invalidInput
        }

        let encodedPayload = String(decoding: bytes.dropFirst(), as: UTF8.self)
        let payload = try ReallyMeBase58Btc.decode(encodedPayload)
        guard payload.count >= 2 else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard let spec = ReallyMeMulticodec.lookupPublicKeyPrefix(in: payload) else {
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }

        let publicKey = Array(payload.dropFirst(spec.prefix.count))
        try validateKeyLength(spec: spec, publicKey: publicKey)

        return ReallyMeParsedMultikey(
            algorithm: spec.algorithm,
            algorithmName: spec.algorithmName,
            publicKey: publicKey,
            expectedPublicKeyLength: spec.expectedPublicKeyLength
        )
    }

    private static func validateKeyLength(
        spec: ReallyMeMulticodecKeySpec,
        publicKey: [UInt8]
    ) throws {
        if let expectedLength = spec.expectedPublicKeyLength {
            guard publicKey.count == expectedLength else {
                throw ReallyMeCryptoError.invalidInput
            }
            return
        }

        guard !publicKey.isEmpty else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
