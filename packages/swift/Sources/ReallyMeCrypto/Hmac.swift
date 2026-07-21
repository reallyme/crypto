// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation

public enum ReallyMeHmac {
    public static let maxKeyLength = 4096
    public static let sha256TagLength = 32
    public static let sha384TagLength = 48
    public static let sha512TagLength = 64

    public static func authenticateSha256(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        try validateKey(key)
        return Array(
            HMAC<SHA256>.authenticationCode(
                for: Data(message),
                using: SymmetricKey(data: Data(key))
            )
        )
    }

    public static func authenticateSha512(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        try validateKey(key)
        return Array(
            HMAC<SHA512>.authenticationCode(
                for: Data(message),
                using: SymmetricKey(data: Data(key))
            )
        )
    }

    public static func authenticateSha384(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        try validateKey(key)
        return Array(
            HMAC<SHA384>.authenticationCode(
                for: Data(message),
                using: SymmetricKey(data: Data(key))
            )
        )
    }

    public static func verifySha256(tag: [UInt8], key: [UInt8], message: [UInt8]) throws -> Bool {
        try validateKey(key)
        guard tag.count == sha256TagLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        return HMAC<SHA256>.isValidAuthenticationCode(
            tag,
            authenticating: Data(message),
            using: SymmetricKey(data: Data(key))
        )
    }

    public static func verifySha512(tag: [UInt8], key: [UInt8], message: [UInt8]) throws -> Bool {
        try validateKey(key)
        guard tag.count == sha512TagLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        return HMAC<SHA512>.isValidAuthenticationCode(
            tag,
            authenticating: Data(message),
            using: SymmetricKey(data: Data(key))
        )
    }

    public static func verifySha384(tag: [UInt8], key: [UInt8], message: [UInt8]) throws -> Bool {
        try validateKey(key)
        guard tag.count == sha384TagLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        return HMAC<SHA384>.isValidAuthenticationCode(
            tag,
            authenticating: Data(message),
            using: SymmetricKey(data: Data(key))
        )
    }

    private static func validateKey(_ key: [UInt8]) throws {
        guard !key.isEmpty, key.count <= maxKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
