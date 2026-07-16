// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCodecProto

public enum ReallyMeMultikey {
    public static func encode(
        _ algorithm: ReallyMeMulticodecKeyAlgorithm,
        publicKey: [UInt8]
    ) throws -> String {
        do {
            return try ReallyMeCryptoCodecProvider
                .requireCodec()
                .multikeyEncode(codecName: ReallyMeMulticodec.codecName(for: algorithm), publicKey: publicKey)
        } catch {
            throw mapCodecError(error)
        }
    }

    public static func parse(_ multikey: String) throws -> ReallyMeParsedMultikey {
        let codec = try ReallyMeCryptoCodecProvider.requireCodec()
        let parsed: ReallyMeProtoCodecMultikeyParseResult
        do {
            let protoBytes = try codec.multikeyParseProto(multikey)
            parsed = try ReallyMeProtoCodecMultikeyParseResult(serializedBytes: protoBytes)
        } catch {
            throw mapCodecError(error)
        }
        guard let algorithm = ReallyMeMulticodecKeyAlgorithm(rawValue: parsed.codecName) else {
            throw ReallyMeCryptoError.invalidInput
        }
        let expectedPublicKeyLength = parsed.variablePublicKeyLength
            ? nil
            : Int(parsed.expectedPublicKeyLength)

        return ReallyMeParsedMultikey(
            algorithm: algorithm,
            algorithmName: parsed.algorithmName,
            publicKey: Array(parsed.publicKey),
            expectedPublicKeyLength: expectedPublicKeyLength
        )
    }
}
