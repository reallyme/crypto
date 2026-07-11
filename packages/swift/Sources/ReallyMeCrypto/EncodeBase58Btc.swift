// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

private let base58BtcAlphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

enum ReallyMeBase58Btc {
    static func encode(_ bytes: [UInt8]) throws -> String {
        guard !bytes.isEmpty else {
            return ""
        }
        guard bytes.count <= Int.max / 138 else {
            throw ReallyMeCryptoError.invalidInput
        }

        let capacity = (bytes.count * 138 / 100) + 1
        var digits = [UInt8](repeating: 0, count: capacity)
        var digitLength = 1

        for byte in bytes {
            var carry = Int(byte)
            var index = 0
            while index < digitLength {
                carry += Int(digits[index]) << 8
                digits[index] = UInt8(carry % 58)
                carry /= 58
                index += 1
            }
            while carry > 0 {
                guard digitLength < digits.count else {
                    throw ReallyMeCryptoError.invalidInput
                }
                digits[digitLength] = UInt8(carry % 58)
                carry /= 58
                digitLength += 1
            }
        }

        var encoded = [UInt8]()
        encoded.reserveCapacity(digitLength + bytes.prefix { $0 == 0 }.count)
        for byte in bytes {
            guard byte == 0 else {
                break
            }
            encoded.append(base58BtcAlphabet[0])
        }
        for digit in digits.prefix(digitLength).reversed() {
            encoded.append(base58BtcAlphabet[Int(digit)])
        }

        return String(decoding: encoded, as: UTF8.self)
    }

    static func decode(_ text: String) throws -> [UInt8] {
        let input = Array(text.utf8)
        guard !input.isEmpty else {
            return []
        }
        guard input.count <= Int.max / 733 else {
            throw ReallyMeCryptoError.invalidInput
        }

        let capacity = (input.count * 733 / 1_000) + 1
        var output = [UInt8](repeating: 0, count: capacity)
        var outputLength = 1

        for character in input {
            guard let value = value(for: character) else {
                throw ReallyMeCryptoError.invalidInput
            }

            var carry = value
            var index = 0
            while index < outputLength {
                carry += Int(output[index]) * 58
                output[index] = UInt8(carry & 0xff)
                carry >>= 8
                index += 1
            }
            while carry > 0 {
                guard outputLength < output.count else {
                    throw ReallyMeCryptoError.invalidInput
                }
                output[outputLength] = UInt8(carry & 0xff)
                carry >>= 8
                outputLength += 1
            }
        }

        var decoded = [UInt8]()
        decoded.reserveCapacity(outputLength + input.prefix { $0 == base58BtcAlphabet[0] }.count)
        for character in input {
            guard character == base58BtcAlphabet[0] else {
                break
            }
            decoded.append(0)
        }

        var trimmingLeadingZero = true
        for byte in output.prefix(outputLength).reversed() {
            if trimmingLeadingZero && byte == 0 {
                continue
            }
            trimmingLeadingZero = false
            decoded.append(byte)
        }

        return decoded
    }

    private static func value(for character: UInt8) -> Int? {
        for (index, candidate) in base58BtcAlphabet.enumerated() where candidate == character {
            return index
        }
        return nil
    }
}
