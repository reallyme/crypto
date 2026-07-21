// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

public enum ReallyMeHkdf {
    public static let minInputKeyMaterialLength = 1
    public static let maxInputLength = 4096
    public static let minOutputLength = 1
    public static let maxOutputLength = 4096

    public static func deriveSha256(
        inputKeyMaterial: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        try validate(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputLength: outputLength
        )
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(inputKeyMaterial)),
            salt: Data(salt),
            info: Data(info),
            outputByteCount: outputLength
        )
        return key.withUnsafeBytes { bytes in
            Array(bytes)
        }
    }

    public static func deriveSha384(
        inputKeyMaterial: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws -> [UInt8] {
        try validate(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputLength: outputLength
        )
        let key = HKDF<SHA384>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(inputKeyMaterial)),
            salt: Data(salt),
            info: Data(info),
            outputByteCount: outputLength
        )
        return key.withUnsafeBytes { bytes in
            Array(bytes)
        }
    }

    private static func validate(
        inputKeyMaterial: [UInt8],
        salt: [UInt8],
        info: [UInt8],
        outputLength: Int
    ) throws {
        guard (minInputKeyMaterialLength...maxInputLength).contains(inputKeyMaterial.count),
              salt.count <= maxInputLength,
              info.count <= maxInputLength,
              (minOutputLength...maxOutputLength).contains(outputLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
