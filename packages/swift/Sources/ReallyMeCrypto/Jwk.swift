// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import ReallyMeCodec

public enum ReallyMeJwkAlgorithm: String, Sendable {
    case ed25519 = "Ed25519"
    case x25519 = "X25519"
    case p256 = "P-256"
    case secp256k1 = "secp256k1"
    case mlDsa44 = "ML-DSA-44"
    case mlDsa65 = "ML-DSA-65"
    case mlDsa87 = "ML-DSA-87"
    case mlKem512 = "ML-KEM-512"
    case mlKem768 = "ML-KEM-768"
    case mlKem1024 = "ML-KEM-1024"
    case slhDsaSha2_128s = "SLH-DSA-SHA2-128s"
    case xWing768 = "X-Wing-768"
}

public struct ReallyMeJwkDocument: Equatable, Sendable {
    public let algorithm: ReallyMeJwkAlgorithm
    public let kty: String
    public let alg: String
    public let keyUse: String
    public let crv: String?
    public let x: String?
    public let y: String?
    public let publicKey: String?

    public init(
        algorithm: ReallyMeJwkAlgorithm,
        kty: String,
        alg: String,
        keyUse: String,
        crv: String?,
        x: String?,
        y: String?,
        publicKey: String?
    ) {
        self.algorithm = algorithm
        self.kty = kty
        self.alg = alg
        self.keyUse = keyUse
        self.crv = crv
        self.x = x
        self.y = y
        self.publicKey = publicKey
    }
}

public struct ReallyMeJwkKey: Equatable, Sendable {
    public let algorithm: ReallyMeJwkAlgorithm
    public let publicKey: [UInt8]
    public let jwk: ReallyMeJwkDocument

    public init(
        algorithm: ReallyMeJwkAlgorithm,
        publicKey: [UInt8],
        jwk: ReallyMeJwkDocument
    ) {
        self.algorithm = algorithm
        self.publicKey = publicKey
        self.jwk = jwk
    }
}

public struct ReallyMeJwks: Equatable, Sendable {
    public let keys: [ReallyMeJwkDocument]

    public init(keys: [ReallyMeJwkDocument]) {
        self.keys = keys
    }
}

private struct ReallyMeJwkSpec {
    let alg: String
    let crv: String?
    let kty: String
    let keyUse: String
    let publicKeyLength: Int
}

/// JWK conversion for package consumers.
///
/// Crypto owns key-shape validation and EC point conversion. Codec-specific
/// operations such as base64url and JCS are delegated to `reallyme-codec` so the
/// package lanes do not drift from the Rust codec implementation.
public enum ReallyMeJwk {
    private static let maxJwkJsonBytes = 1_048_576
    private static let maxJwksKeys = 1_024
    private static let privateMemberNames: Set<String> = [
        "d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv", "privateKey", "secretKey",
    ]

    public static func toJwk(
        algorithm: ReallyMeJwkAlgorithm,
        publicKey: [UInt8]
    ) throws -> ReallyMeJwkDocument {
        let spec = try spec(for: algorithm.rawValue)
        guard publicKey.count == spec.publicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }

        if spec.kty == "EC" {
            let uncompressed = try decompressEcPublicKey(algorithm: algorithm, publicKey: publicKey)
            return ReallyMeJwkDocument(
                algorithm: algorithm,
                kty: spec.kty,
                alg: spec.alg,
                keyUse: spec.keyUse,
                crv: spec.crv,
                x: try codecBase64urlEncode(Array(uncompressed[1..<33])),
                y: try codecBase64urlEncode(Array(uncompressed[33..<65])),
                publicKey: nil
            )
        }

        let encodedPublicKey = try codecBase64urlEncode(publicKey)
        return ReallyMeJwkDocument(
            algorithm: algorithm,
            kty: spec.kty,
            alg: spec.alg,
            keyUse: spec.keyUse,
            crv: spec.crv,
            x: spec.kty == "OKP" ? encodedPublicKey : nil,
            y: nil,
            publicKey: spec.kty == "AKP" ? encodedPublicKey : nil
        )
    }

    public static func toJcs(_ jwk: ReallyMeJwkDocument) throws -> String {
        do {
            return try ReallyMeCryptoCodecProvider.requireCodec().canonicalizeJson(jwkJson(jwk))
        } catch {
            throw mapCodecError(error)
        }
    }

    private static func jwkJson(_ jwk: ReallyMeJwkDocument) throws -> String {
        switch jwk.kty {
        case "EC":
            guard jwk.crv != nil, jwk.x != nil, jwk.y != nil else {
                throw ReallyMeCryptoError.invalidInput
            }
        case "OKP":
            guard jwk.crv != nil, jwk.x != nil else {
                throw ReallyMeCryptoError.invalidInput
            }
        case "AKP":
            guard jwk.publicKey != nil else {
                throw ReallyMeCryptoError.invalidInput
            }
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
        let data: Data
        do {
            data = try JSONSerialization.data(
                withJSONObject: object(from: jwk),
                options: [.sortedKeys]
            )
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
        guard let json = String(data: data, encoding: .utf8) else {
            throw ReallyMeCryptoError.invalidInput
        }
        return json
    }

    public static func fromJwkJson(_ data: Data) throws -> ReallyMeJwkKey {
        try fromJwkObject(canonicalJsonObject(data))
    }

    public static func toJwks(_ keys: [ReallyMeJwkDocument]) -> ReallyMeJwks {
        ReallyMeJwks(keys: keys)
    }

    public static func fromJwksJson(_ data: Data) throws -> [ReallyMeJwkKey] {
        let object = try canonicalJsonObject(data)
        guard
            Set(object.keys) == Set(["keys"]),
            let keys = object["keys"] as? [[String: Any]],
            keys.count <= maxJwksKeys
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        return try keys.map { try fromJwkObject($0) }
    }

    public static func publicKeyBytes(from jwk: ReallyMeJwkDocument) throws -> [UInt8] {
        return try fromJwkObject(object(from: jwk)).publicKey
    }

    private static func fromJwkObject(_ object: [String: Any]) throws -> ReallyMeJwkKey {
        guard privateMemberNames.isDisjoint(with: object.keys) else {
            throw ReallyMeCryptoError.invalidInput
        }
        guard let kty = object["kty"] as? String else {
            throw ReallyMeCryptoError.invalidInput
        }
        let algorithmName: String
        if kty == "AKP" {
            guard let alg = object["alg"] as? String else {
                throw ReallyMeCryptoError.invalidInput
            }
            algorithmName = alg
        } else {
            guard let crv = object["crv"] as? String else {
                throw ReallyMeCryptoError.invalidInput
            }
            algorithmName = crv
        }

        let spec = try spec(for: algorithmName)
        let allowedMemberNames: Set<String>
        switch spec.kty {
        case "EC":
            allowedMemberNames = ["alg", "crv", "kty", "use", "x", "y"]
        case "OKP":
            allowedMemberNames = ["alg", "crv", "kty", "use", "x"]
        case "AKP":
            allowedMemberNames = ["alg", "kty", "pub", "use"]
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
        guard Set(object.keys).isSubset(of: allowedMemberNames) else {
            throw ReallyMeCryptoError.invalidInput
        }
        let metadataMatches: Bool
        if spec.kty == "OKP" {
            metadataMatches = optionalStringMemberMatches(object, name: "alg", expected: spec.alg)
                && optionalStringMemberMatches(object, name: "use", expected: spec.keyUse)
        } else {
            metadataMatches = object["alg"] as? String == spec.alg
                && object["use"] as? String == spec.keyUse
        }
        guard
            let algorithm = ReallyMeJwkAlgorithm(rawValue: algorithmName),
            kty == spec.kty,
            metadataMatches
        else {
            throw ReallyMeCryptoError.invalidInput
        }

        let publicKey: [UInt8]
        if spec.kty == "EC" {
            guard
                let encodedX = object["x"] as? String,
                let encodedY = object["y"] as? String
            else {
                throw ReallyMeCryptoError.invalidInput
            }
            publicKey = try compressEcPublicKey(
                algorithm: algorithm,
                x: Array(codecBase64urlDecode(encodedX)),
                y: Array(codecBase64urlDecode(encodedY))
            )
        } else if spec.kty == "AKP" {
            guard let encodedPublicKey = object["pub"] as? String else {
                throw ReallyMeCryptoError.invalidInput
            }
            publicKey = Array(try codecBase64urlDecode(encodedPublicKey))
        } else {
            guard let encodedPublicKey = object["x"] as? String else {
                throw ReallyMeCryptoError.invalidInput
            }
            publicKey = Array(try codecBase64urlDecode(encodedPublicKey))
        }

        guard publicKey.count == spec.publicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let jwk = try toJwk(algorithm: algorithm, publicKey: publicKey)
        return ReallyMeJwkKey(algorithm: algorithm, publicKey: publicKey, jwk: jwk)
    }

    private static func object(from jwk: ReallyMeJwkDocument) -> [String: Any] {
        var object: [String: Any] = [
            "alg": jwk.alg,
            "kty": jwk.kty,
            "use": jwk.keyUse,
        ]
        if let crv = jwk.crv {
            object["crv"] = crv
        }
        if let x = jwk.x {
            object["x"] = x
        }
        if let y = jwk.y {
            object["y"] = y
        }
        if let publicKey = jwk.publicKey {
            object["pub"] = publicKey
        }
        return object
    }

    private static func optionalStringMemberMatches(
        _ object: [String: Any],
        name: String,
        expected: String
    ) -> Bool {
        guard let value = object[name] else {
            return true
        }
        return value as? String == expected
    }

    private static func spec(for algorithmName: String) throws -> ReallyMeJwkSpec {
        switch algorithmName {
        case "Ed25519":
            return ReallyMeJwkSpec(alg: "EdDSA", crv: "Ed25519", kty: "OKP", keyUse: "sig", publicKeyLength: 32)
        case "X25519":
            return ReallyMeJwkSpec(alg: "ECDH-ES", crv: "X25519", kty: "OKP", keyUse: "enc", publicKeyLength: 32)
        case "P-256":
            return ReallyMeJwkSpec(alg: "ES256", crv: "P-256", kty: "EC", keyUse: "sig", publicKeyLength: 33)
        case "secp256k1":
            return ReallyMeJwkSpec(alg: "ES256K", crv: "secp256k1", kty: "EC", keyUse: "sig", publicKeyLength: 33)
        case "ML-DSA-44":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "sig", publicKeyLength: 1_312)
        case "ML-DSA-65":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "sig", publicKeyLength: 1_952)
        case "ML-DSA-87":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "sig", publicKeyLength: 2_592)
        case "ML-KEM-512":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "enc", publicKeyLength: 800)
        case "ML-KEM-768":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "enc", publicKeyLength: 1_184)
        case "ML-KEM-1024":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "enc", publicKeyLength: 1_568)
        case "SLH-DSA-SHA2-128s":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "sig", publicKeyLength: 32)
        case "X-Wing-768":
            return ReallyMeJwkSpec(alg: algorithmName, crv: nil, kty: "AKP", keyUse: "enc", publicKeyLength: 1_216)
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    private static func decompressEcPublicKey(
        algorithm: ReallyMeJwkAlgorithm,
        publicKey: [UInt8]
    ) throws -> [UInt8] {
        switch algorithm {
        case .p256:
            do {
                return Array(try P256.Signing.PublicKey(compressedRepresentation: Data(publicKey)).x963Representation)
            } catch {
                throw ReallyMeCryptoError.invalidInput
            }
        case .secp256k1:
            return try ReallyMeSecp256k1.decompressPublicKey(publicKey: publicKey)
        default:
            throw ReallyMeCryptoError.unsupportedAlgorithm
        }
    }

    private static func compressEcPublicKey(
        algorithm: ReallyMeJwkAlgorithm,
        x: [UInt8],
        y: [UInt8]
    ) throws -> [UInt8] {
        guard x.count == 32, y.count == 32 else {
            throw ReallyMeCryptoError.invalidInput
        }
        let prefix: UInt8
        guard let last = y.last else {
            throw ReallyMeCryptoError.invalidInput
        }
        prefix = (last & 1) == 0 ? 0x02 : 0x03
        let compressed = [prefix] + x
        let uncompressed = try decompressEcPublicKey(algorithm: algorithm, publicKey: compressed)
        guard
            uncompressed.count == 65,
            Array(uncompressed[1..<33]) == x,
            Array(uncompressed[33..<65]) == y
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        return compressed
    }

    private static func canonicalJsonObject(_ data: Data) throws -> [String: Any] {
        guard data.count <= maxJwkJsonBytes, let json = String(data: data, encoding: .utf8) else {
            throw ReallyMeCryptoError.invalidInput
        }
        let canonical: String
        do {
            canonical = try ReallyMeCryptoCodecProvider.requireCodec().canonicalizeJson(json)
        } catch {
            throw mapCodecError(error)
        }
        let decoded: Any
        do {
            decoded = try JSONSerialization.jsonObject(with: Data(canonical.utf8))
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
        guard
            let object = decoded as? [String: Any]
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        return object
    }

    private static func codecBase64urlEncode(_ bytes: [UInt8]) throws -> String {
        do {
            return try ReallyMeCryptoCodecProvider.requireCodec().base64urlEncode(bytes)
        } catch {
            throw mapCodecError(error)
        }
    }

    private static func codecBase64urlDecode(_ encoded: String) throws -> [UInt8] {
        do {
            return try ReallyMeCryptoCodecProvider.requireCodec().base64urlDecode(encoded)
        } catch {
            throw mapCodecError(error)
        }
    }
}
