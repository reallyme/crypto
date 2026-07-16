// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

public enum ReallyMePbkdf2 {
    public static let minInputLength = 1
    public static let maxInputLength = 4096
    public static let minIterations: UInt32 = 1
    public static let minOutputLength = 1
    public static let maxOutputLength = 4096

    public static func deriveHmacSha256(
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws -> [UInt8] {
        try derive(
            password: password,
            salt: salt,
            iterations: iterations,
            outputLength: outputLength,
            hashLength: ReallyMeHmac.sha256TagLength,
            authenticate: ReallyMeHmac.authenticateSha256
        )
    }

    public static func deriveHmacSha512(
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws -> [UInt8] {
        try derive(
            password: password,
            salt: salt,
            iterations: iterations,
            outputLength: outputLength,
            hashLength: ReallyMeHmac.sha512TagLength,
            authenticate: ReallyMeHmac.authenticateSha512
        )
    }

    private static func derive(
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int,
        hashLength: Int,
        authenticate: (_ key: [UInt8], _ message: [UInt8]) throws -> [UInt8]
    ) throws -> [UInt8] {
        try validate(password: password, salt: salt, iterations: iterations, outputLength: outputLength)

        let adjustedLength = outputLength.addingReportingOverflow(hashLength - 1)
        guard !adjustedLength.overflow else {
            throw ReallyMeCryptoError.invalidInput
        }
        let blockCount = adjustedLength.partialValue / hashLength
        guard blockCount <= Int(UInt32.max) else {
            throw ReallyMeCryptoError.invalidInput
        }

        var derived = [UInt8]()
        derived.reserveCapacity(outputLength)

        for blockIndex in 1...blockCount {
            guard let blockIndex32 = UInt32(exactly: blockIndex) else {
                throw ReallyMeCryptoError.invalidInput
            }
            var blockInput = salt
            blockInput.append(UInt8((blockIndex32 >> 24) & 0xff))
            blockInput.append(UInt8((blockIndex32 >> 16) & 0xff))
            blockInput.append(UInt8((blockIndex32 >> 8) & 0xff))
            blockInput.append(UInt8(blockIndex32 & 0xff))

            do {
                var previous = try authenticate(password, blockInput)
                var block = previous
                defer {
                    ReallyMeCryptoMemory.bestEffortClear(&blockInput)
                    ReallyMeCryptoMemory.bestEffortClear(&previous)
                    ReallyMeCryptoMemory.bestEffortClear(&block)
                }

                if iterations > 1 {
                    for _ in 1..<iterations {
                        let next = try authenticate(password, previous)
                        ReallyMeCryptoMemory.bestEffortClear(&previous)
                        previous = next
                        for index in block.indices {
                            block[index] ^= previous[index]
                        }
                    }
                }

                guard derived.count <= outputLength else {
                    throw ReallyMeCryptoError.providerFailure
                }
                let remaining = outputLength - derived.count
                derived.append(contentsOf: block.prefix(remaining))
            } catch {
                ReallyMeCryptoMemory.bestEffortClear(&blockInput)
                throw error
            }
        }

        return derived
    }

    private static func validate(
        password: [UInt8],
        salt: [UInt8],
        iterations: UInt32,
        outputLength: Int
    ) throws {
        guard (minInputLength...maxInputLength).contains(password.count),
              (minInputLength...maxInputLength).contains(salt.count),
              iterations >= minIterations,
              (minOutputLength...maxOutputLength).contains(outputLength)
        else {
            throw ReallyMeCryptoError.invalidInput
        }
    }
}
