// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCodec

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
        do {
            let parsed = try codec.multikeyParse(multikey)
            guard let algorithm = ReallyMeMulticodecKeyAlgorithm(rawValue: parsed.codecName) else {
                throw ReallyMeCryptoError.invalidInput
            }
            let expectedPublicKeyLength: Int?
            if let codecExpectedLength = parsed.expectedPublicKeyLength {
                guard let convertedLength = Int(exactly: codecExpectedLength) else {
                    throw ReallyMeCryptoError.invalidInput
                }
                expectedPublicKeyLength = convertedLength
            } else {
                expectedPublicKeyLength = nil
            }

            return ReallyMeParsedMultikey(
                algorithm: algorithm,
                algorithmName: parsed.algorithmName,
                publicKey: parsed.publicKey,
                expectedPublicKeyLength: expectedPublicKeyLength
            )
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw mapCodecError(error)
        }
    }
}
