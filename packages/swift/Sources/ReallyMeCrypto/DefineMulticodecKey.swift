// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Public key multicodec identifiers recognized by the Swift package.
///
/// These are codec identifiers, not proof that the corresponding signing or
/// KEM primitive is implemented in Swift. Ed448, for example, is recognized so
/// DID and key-document code can round-trip codec metadata while the signing
/// primitive remains intentionally unsupported.
public enum ReallyMeMulticodecKeyAlgorithm: String, CaseIterable, Sendable {
    case ed25519PublicKey = "ed25519-pub"
    case x25519PublicKey = "x25519-pub"
    case p256PublicKey = "p256-pub"
    case p384PublicKey = "p384-pub"
    case p521PublicKey = "p521-pub"
    case ed448PublicKey = "ed448-pub"
    case rsaPublicKey = "rsa-pub"
    case secp256k1PublicKey = "secp256k1-pub"
    case mlDsa44PublicKey = "mldsa-44-pub"
    case mlDsa65PublicKey = "mldsa-65-pub"
    case mlDsa87PublicKey = "mldsa-87-pub"
    case mlKem512PublicKey = "mlkem-512-pub"
    case mlKem768PublicKey = "mlkem-768-pub"
    case mlKem1024PublicKey = "mlkem-1024-pub"
}

/// Parsed multikey material after multibase and multicodec validation.
public struct ReallyMeParsedMultikey: Equatable, Sendable {
    public let algorithm: ReallyMeMulticodecKeyAlgorithm
    public let algorithmName: String
    public let publicKey: [UInt8]
    public let expectedPublicKeyLength: Int?
}

struct ReallyMeMulticodecKeySpec: Sendable {
    let algorithm: ReallyMeMulticodecKeyAlgorithm
    let algorithmName: String
    let prefix: [UInt8]
    let expectedPublicKeyLength: Int?
}

public enum ReallyMeMulticodec {
    public static let publicKeyAlgorithms = ReallyMeMulticodecKeyAlgorithm.allCases

    public static func codecName(for algorithm: ReallyMeMulticodecKeyAlgorithm) -> String {
        algorithm.rawValue
    }

    public static func algorithmName(for algorithm: ReallyMeMulticodecKeyAlgorithm) -> String {
        spec(for: algorithm).algorithmName
    }

    public static func prefix(for algorithm: ReallyMeMulticodecKeyAlgorithm) -> [UInt8] {
        spec(for: algorithm).prefix
    }

    public static func expectedPublicKeyLength(for algorithm: ReallyMeMulticodecKeyAlgorithm) -> Int? {
        spec(for: algorithm).expectedPublicKeyLength
    }

    static func spec(for algorithm: ReallyMeMulticodecKeyAlgorithm) -> ReallyMeMulticodecKeySpec {
        switch algorithm {
        case .ed25519PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "Ed25519",
                prefix: [0xed, 0x01],
                expectedPublicKeyLength: 32
            )
        case .x25519PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "X25519",
                prefix: [0xec, 0x01],
                expectedPublicKeyLength: 32
            )
        case .p256PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "P-256",
                prefix: [0x80, 0x24],
                expectedPublicKeyLength: 33
            )
        case .p384PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "P-384",
                prefix: [0x81, 0x24],
                expectedPublicKeyLength: 49
            )
        case .p521PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "P-521",
                prefix: [0x82, 0x24],
                expectedPublicKeyLength: 67
            )
        case .ed448PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "Ed448",
                prefix: [0x83, 0x24],
                expectedPublicKeyLength: 57
            )
        case .rsaPublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "RSA",
                prefix: [0x85, 0x24],
                expectedPublicKeyLength: nil
            )
        case .secp256k1PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "secp256k1",
                prefix: [0xe7, 0x01],
                expectedPublicKeyLength: 33
            )
        case .mlDsa44PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-DSA-44",
                prefix: [0x90, 0x24],
                expectedPublicKeyLength: 1_312
            )
        case .mlDsa65PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-DSA-65",
                prefix: [0x91, 0x24],
                expectedPublicKeyLength: 1_952
            )
        case .mlDsa87PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-DSA-87",
                prefix: [0x92, 0x24],
                expectedPublicKeyLength: 2_592
            )
        case .mlKem512PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-KEM-512",
                prefix: [0x8b, 0x24],
                expectedPublicKeyLength: 800
            )
        case .mlKem768PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-KEM-768",
                prefix: [0x8c, 0x24],
                expectedPublicKeyLength: 1_184
            )
        case .mlKem1024PublicKey:
            ReallyMeMulticodecKeySpec(
                algorithm: algorithm,
                algorithmName: "ML-KEM-1024",
                prefix: [0x8d, 0x24],
                expectedPublicKeyLength: 1_568
            )
        }
    }

    static func lookupPublicKeyPrefix(in bytes: [UInt8]) -> ReallyMeMulticodecKeySpec? {
        for algorithm in ReallyMeMulticodecKeyAlgorithm.allCases {
            let candidate = spec(for: algorithm)
            if bytes.starts(with: candidate.prefix) {
                return candidate
            }
        }
        return nil
    }
}
