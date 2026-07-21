// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

final class ReallyMeCryptoRustCAbiTests: XCTestCase {
    // MARK: - P-256 ECDSA (ReallyMe Rust C ABI)

    static let p256EcdsaSecretKey = bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    static let p256EcdsaPublicKey = bytes(
        "027a593180860c4037c83c12749845c8ee1424dd297fadcb895e358255d2c7d2b2"
    )
    static let p256EcdsaMessage = bytes(
        "48656c6c6f2c20502d32353621"
    )
    static let p256EcdsaSignatureDer = bytes(
        "304402204bd4ee72b48883a4d1817e0371c66b6412117183794c6b220fb13590b7f98097"
            + "0220316c6251e714b87c65fd161dd1823e888b1c66d9075ff8cd7ade89d166e935de"
    )
    static func configuredRustCAbiLibrary() throws -> ReallyMeRustCAbiLibrary {
        if ReallyMeRustCAbiLibrary.isBundledProviderAvailable {
            return try ReallyMeRustCAbiLibrary.bundledProvider()
        }
        guard let libraryPath = ProcessInfo.processInfo.environment["REALLYME_CRYPTO_FFI_LIBRARY_PATH"],
              !libraryPath.isEmpty
        else {
            throw XCTSkip("set REALLYME_CRYPTO_FFI_LIBRARY_PATH to a built crypto-ffi dylib")
        }
        return try ReallyMeRustCAbiLibrary(path: libraryPath)
    }

    static func base64UrlBytes(_ encoded: String) throws -> [UInt8] {
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let decoded = Data(base64Encoded: base64) else {
            throw XCTSkip("invalid base64url test fixture")
        }
        return [UInt8](decoded)
    }

    static func loadXWingVectors() throws -> XWingVectors {
        let vectorUrl = try reallyMeVectorURL("x_wing.json")
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(XWingVectors.self, from: data)
    }

    static func loadMlKemVector(_ fileName: String) throws -> MlKemVector {
        let vectorUrl = try reallyMeVectorURL(fileName)
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(MlKemVector.self, from: data)
    }

    static func loadEcdsaCurveVector(_ fileName: String) throws -> EcdsaCurveVector {
        let vectorUrl = try reallyMeVectorURL(fileName)
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(EcdsaCurveVector.self, from: data)
    }

    static func loadAesKwVector(_ fileName: String) throws -> AesKwVector {
        let vectorUrl = try reallyMeVectorURL(fileName)
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(AesKwVector.self, from: data)
    }

    static func loadKmac256Vector() throws -> Kmac256Vector {
        let vectorUrl = try reallyMeVectorURL("kmac256.json")
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(Kmac256Vector.self, from: data)
    }

    static func loadMlDsaVector(_ fileName: String) throws -> MlDsaVector {
        let vectorUrl = try reallyMeVectorURL(fileName)
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(MlDsaVector.self, from: data)
    }

    static func loadSlhDsaVector() throws -> SlhDsaVector {
        let vectorUrl = try reallyMeVectorURL("slh_dsa_sha2_128s.json")
        let data = try Data(contentsOf: vectorUrl)
        return try JSONDecoder().decode(SlhDsaVector.self, from: data)
    }

    static func assertSlhDsaVector(library: ReallyMeRustCAbiLibrary) throws {
        let vector = try loadSlhDsaVector()
        let skSeed = try base64UrlBytes(vector.keygenSkSeed)
        let skPrf = try base64UrlBytes(vector.keygenSkPrf)
        let pkSeed = try base64UrlBytes(vector.keygenPkSeed)
        let secretKey = try base64UrlBytes(vector.secretKey)
        let publicKey = try base64UrlBytes(vector.publicKey)
        let message = try base64UrlBytes(vector.message)
        let expectedSignature = try base64UrlBytes(vector.signature)

        XCTAssertEqual(skSeed.count, 16)
        XCTAssertEqual(skPrf.count, 16)
        XCTAssertEqual(pkSeed.count, 16)
        XCTAssertEqual(secretKey.count, vector.secretKeyLength)
        XCTAssertEqual(publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(expectedSignature.count, vector.signatureLength)

        let derivedKeyPair = try ReallyMeCrypto.deriveSlhDsaSha2_128sKeyPair(
            skSeed: skSeed,
            skPrf: skPrf,
            pkSeed: pkSeed,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, publicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        let signature = try ReallyMeCrypto.sign(
            .slhDsaSha2_128s,
            message: message,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            .slhDsaSha2_128s,
            signature: signature,
            message: message,
            publicKey: publicKey,
            rustCAbiLibrary: library
        )

        var tamperedSignature = signature
        tamperedSignature[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .slhDsaSha2_128s,
                signature: tamperedSignature,
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        var tamperedMessage = message
        tamperedMessage[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .slhDsaSha2_128s,
                signature: signature,
                message: tamperedMessage,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.deriveSlhDsaSha2_128sKeyPair(
                skSeed: Array(skSeed.dropLast()),
                skPrf: skPrf,
                pkSeed: pkSeed,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                .slhDsaSha2_128s,
                message: message,
                secretKey: Array(secretKey.dropLast()),
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                .slhDsaSha2_128s,
                signature: Array(signature.dropLast()),
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        let freshKeyPair = try ReallyMeCrypto.generateKeyPair(.slhDsaSha2_128s, rustCAbiLibrary: library)
        XCTAssertEqual(freshKeyPair.publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(freshKeyPair.secretKey.count, vector.secretKeyLength)
        let freshSignature = try ReallyMeCrypto.sign(
            .slhDsaSha2_128s,
            message: message,
            secretKey: freshKeyPair.secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(freshSignature.count, vector.signatureLength)
        try ReallyMeCrypto.verify(
            .slhDsaSha2_128s,
            signature: freshSignature,
            message: message,
            publicKey: freshKeyPair.publicKey,
            rustCAbiLibrary: library
        )
    }

    static func assertMlDsaVector(
        algorithm: ReallyMeSignatureAlgorithm,
        vectorFileName: String,
        library: ReallyMeRustCAbiLibrary
    ) throws {
        let vector = try loadMlDsaVector(vectorFileName)
        let secretKey = try base64UrlBytes(vector.secretKey)
        let publicKey = try base64UrlBytes(vector.publicKey)
        let message = try base64UrlBytes(vector.message)
        let expectedSignature = try base64UrlBytes(vector.signature)

        XCTAssertEqual(secretKey.count, 32)
        XCTAssertEqual(publicKey.count, vector.publicKeyLength)
        let signature = try ReallyMeCrypto.sign(
            algorithm,
            message: message,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(signature, expectedSignature)
        try ReallyMeCrypto.verify(
            algorithm,
            signature: signature,
            message: message,
            publicKey: publicKey,
            rustCAbiLibrary: library
        )

        var tamperedMessage = message
        tamperedMessage[0] ^= 0x01
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                algorithm,
                signature: signature,
                message: tamperedMessage,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.sign(
                algorithm,
                message: message,
                secretKey: Array(secretKey.dropLast()),
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
        XCTAssertThrowsError(
            try ReallyMeCrypto.verify(
                algorithm,
                signature: Array(signature.dropLast()),
                message: message,
                publicKey: publicKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        let freshKeyPair = try ReallyMeCrypto.generateKeyPair(algorithm, rustCAbiLibrary: library)
        XCTAssertEqual(freshKeyPair.publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(freshKeyPair.secretKey.count, 32)
        let freshSignature = try ReallyMeCrypto.sign(
            algorithm,
            message: message,
            secretKey: freshKeyPair.secretKey,
            rustCAbiLibrary: library
        )
        try ReallyMeCrypto.verify(
            algorithm,
            signature: freshSignature,
            message: message,
            publicKey: freshKeyPair.publicKey,
            rustCAbiLibrary: library
        )
    }

    static func assertMlKemVector(
        algorithm: ReallyMeKemAlgorithm,
        vectorFileName: String,
        library: ReallyMeRustCAbiLibrary
    ) throws {
        let vector = try loadMlKemVector(vectorFileName)
        let secretKey = try base64UrlBytes(vector.secretKey)
        let publicKey = try base64UrlBytes(vector.publicKey)
        let ciphertext = try base64UrlBytes(vector.ciphertext)
        let sharedSecret = try base64UrlBytes(vector.sharedSecret)
        let tamperedCiphertext = try base64UrlBytes(vector.tamperedCiphertext)
        let tamperedSharedSecret = try base64UrlBytes(vector.tamperedSharedSecret)

        XCTAssertEqual(publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: ciphertext,
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            sharedSecret
        )
        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: tamperedCiphertext,
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            tamperedSharedSecret
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: Array(ciphertext.dropLast()),
                secretKey: secretKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }

        let freshKeyPair = try ReallyMeCrypto.generateKemKeyPair(algorithm, rustCAbiLibrary: library)
        XCTAssertEqual(freshKeyPair.publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(freshKeyPair.secretKey.count, 64)
        let freshEncapsulation = try ReallyMeCrypto.encapsulate(
            algorithm,
            publicKey: freshKeyPair.publicKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(freshEncapsulation.sharedSecret.count, 32)
        XCTAssertEqual(freshEncapsulation.ciphertext.count, ciphertext.count)
        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: freshEncapsulation.ciphertext,
                secretKey: freshKeyPair.secretKey,
                rustCAbiLibrary: library
            ),
            freshEncapsulation.sharedSecret
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.encapsulate(
                algorithm,
                publicKey: Array(publicKey.dropLast()),
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    static func assertXWingVector(
        algorithm: ReallyMeKemAlgorithm,
        vector: XWingVector,
        library: ReallyMeRustCAbiLibrary
    ) throws {
        let secretKey = try base64UrlBytes(vector.secretKey)
        let publicKey = try base64UrlBytes(vector.publicKey)
        let ciphertext = try base64UrlBytes(vector.ciphertext)
        let sharedSecret = try base64UrlBytes(vector.sharedSecret)

        XCTAssertEqual(publicKey.count, vector.publicKeyLength)
        XCTAssertEqual(ciphertext.count, vector.ciphertextLength)
        let derivedKeyPair = try ReallyMeCrypto.deriveXWingKeyPair(
            algorithm,
            secretKey: secretKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(derivedKeyPair.publicKey, publicKey)
        XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: ciphertext,
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            sharedSecret
        )

        let encapsulation = try ReallyMeCrypto.encapsulate(
            algorithm,
            publicKey: publicKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: encapsulation.ciphertext,
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            encapsulation.sharedSecret
        )

        var tampered = ciphertext
        tampered[0] ^= 0x01
        XCTAssertNotEqual(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: tampered,
                secretKey: secretKey,
                rustCAbiLibrary: library
            ),
            sharedSecret
        )
        XCTAssertThrowsError(
            try ReallyMeCrypto.decapsulate(
                algorithm,
                ciphertext: Array(tampered.dropLast()),
                secretKey: secretKey,
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
        }
    }

    static func assertHpkeOpenVector(
        suite: ReallyMeHpkeSuite,
        recipientSecretKey: String,
        recipientPublicKey: String,
        encapsulatedKey: String,
        ciphertext: String,
        tamperedCiphertext: String,
        library: ReallyMeRustCAbiLibrary
    ) throws {
        let info = try base64UrlBytes(Self.hpkeInfoBase64Url)
        let aad = try base64UrlBytes(Self.hpkeAadBase64Url)
        let plaintext = try base64UrlBytes(Self.hpkePlaintextBase64Url)
        let secretKey = try base64UrlBytes(recipientSecretKey)
        let publicKey = try base64UrlBytes(recipientPublicKey)
        let enc = try base64UrlBytes(encapsulatedKey)
        let sealedCiphertext = try base64UrlBytes(ciphertext)

        XCTAssertEqual(
            try ReallyMeCrypto.openHpke(
                suite,
                recipientSecretKey: secretKey,
                encapsulatedKey: enc,
                info: info,
                aad: aad,
                ciphertext: sealedCiphertext,
                rustCAbiLibrary: library
            ),
            plaintext
        )

        XCTAssertThrowsError(
            try ReallyMeCrypto.openHpke(
                suite,
                recipientSecretKey: secretKey,
                encapsulatedKey: enc,
                info: info,
                aad: aad,
                ciphertext: try base64UrlBytes(tamperedCiphertext),
                rustCAbiLibrary: library
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
        }

        let freshSealed = try ReallyMeCrypto.sealHpke(
            suite,
            recipientPublicKey: publicKey,
            info: info,
            aad: aad,
            plaintext: plaintext,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(
            try ReallyMeCrypto.openHpke(
                suite,
                recipientSecretKey: secretKey,
                encapsulatedKey: freshSealed.encapsulatedKey,
                info: info,
                aad: aad,
                ciphertext: freshSealed.ciphertext,
                rustCAbiLibrary: library
            ),
            plaintext
        )
    }

    static func bytes(_ hex: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            out.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    static let rsaPublicKeyDerBase64Url =
        "MIIBCgKCAQEAtLGfC3GxzVAbnFDLYwUlIB52PJUl3yVGcY2X-3vFcQsbOhdYKVW7Ug1G0-adGVsz7Sl4CAVZCgDy9LVawN6Wl5TUj8_obkDrtKv9srFmUm0OfYP4REpZq0OBKAs6jf5E5aHqe09edvsO3LOJtVqhHgtFM_xvobGr4TtaPGSoFjssvzJ9YVyK08xDOhCaT4K6ukKlaKBTiOjgVxUtmDRnzct--bNxkhJ88ObqNyJTbp78FWKMsKNfJCTVnKnQIdDMCCQgS6AIXm_d2bPK6FrvDphqfem9ysGQaqPeZjCCoEU9lF9ha_v29bQn6CPxzT7cCYW8V-J_mqhOIwqocTI7jQIDAQAB"

    static let rsaPkcs1Sha1SignatureBase64Url =
        "hA_Xs2jYATVjBo9PtGmi-tr0fVJH57-QmUHvtZp2daMI_xk5XdMu4XYHRhCuP5LpHpjxJr2HvrM1ovdXq8bxfBDQkyR8fQgJcxs9lzCX4e9G5gu-cx1wo-YEoco6OGO6FZRoGHJgiUJ1gp6AbihXQYmzwkP4lJPeZTgTqfCzW9OURB6f-VWbxnWN9ALmIAboMmsMTBcJ4kEVQqK0EH5uRrGqF5R2QONNntmwYLByM3mIwyFGhm5RksGN4Xpz1b140xQLHIg6NdJS9x3okC2PEGyQ0l-1o1ct7yrqsnGcRoDkVLzpXQj_CjBAMQ7Vmmnb0yC11VuzlYBel3RFZM_dpA"

    static let rsaPkcs1Sha256SignatureBase64Url =
        "Re77CuddLv7YajqprynKArLWsc_5tMp5UOAgi1M4cHgj9lKJ14VuI78Lx4if-ngxz4hDxwbRMOh0V50DkRYcd_oyfdzecsqo-SisuGGGer5gWJ8h2_8wyrKuSXroNt2CyPUGv5Jn6K5I9krL6Cx0U7_MyE6HZJNSVH1w6VpxNsf8iNvp-p_eFkt8dEVuBFxsNlGQV3ltFNVg99kBDOiammOuXIrkCf_V67xy3Hc2RkptbmNHTnlC8hw8WBoMH5ds5UcYMuHVgRr8CmXr4YNX9Vel46L7UV69FN5xcJNTLEW0_Ylo9N_Csh8urYUbupfvZ49uWMOzyReMg4tzu90lSw"

    static let rsaPssSha256SignatureBase64Url =
        "bYeyCHaW_4vy7QDQlAtm7fY5CV9XH4Kt0eINKPRd9E1YFrvI2KLaVgG7-T0uGPu8P_t3BV0n_FJJBRxMlSySqFqT_VllgzXuBJ3A7fC_pFyMPK6A3XZ0Y_3rWShvjeZnBf_doMSjoGuWFSaB0K4IOAiyjyoJ3RGea6ikt-5nGPvaiFb6K3YXZTJXavH8AKu3J19V2kTrUGHZ6Lf5RuqWHFyzFsEzNPcp13ezECkVMZHQEwLxt9Li_mWqXDhPF4bpPCUpGljfmsgqo0RBYogEau7YxqaS15-HhLhWTaJYGEcvWBL9burCgU4nlqfEt9gU0m2EDhhUGR38CS86RSiwEw"

    static let rsaPkcs1Sha384SignatureBase64Url =
        "UPPRJw8CyERJsI7PW5_9WbhZmmIe2wie3bt1FuZz_8ShFfgaFXwQfwn_YS4QtkPEAn6q438r05M25U-IYQXaDiisXSocMxRE06nqMvvrCgO6p6O-2_xWW8V8xhDox1aPqWdp54Ba6A0s3dywUe5zQpOAL-xQ8KLIZpIE118xKwhouFMGZBvCNJDDMMVTxIyp-EpThhiE5EFxL5vp9hVx4euaEfgQhw5MXnJmxKW4Pt9sSdMlvoP8aFrW5st9rLfvknJz4EwgIVevM5XYaWsrjZfJOKY5CmCVmvW-evOMjumMRRU9t2OOOf5NHszKzK3qtUvzCbXUz8F1FNFJeZ_GaA"

    static let rsaPkcs1Sha512SignatureBase64Url =
        "MQ0UP3caVxnjq72kvCzRSvEbk2msNM0l76lv84OPjuA7Xu0EAb6H4WjoDnwqCy1aJe0wZQVVXEQyT8ch3AmDsY7_zCYlayZ8147Jno7n7qda8D0d8Q9SWZRK3Ir4HW6Ex5psmZaAhqSMAnku6On8oWIuofGKOOgMVn7AYDeehlh3f5NscqAtrEebrZ47B-d6XDHuyAe4zxsJPbBj0ef1vvRAA6wXnPIJ7Kvmajb8P4N8dCcjwjA7P9VbyZz_fY2HNpyAGAEFkjOO8uo05u30cHn6TLSYTCsKH2PCqkgH_-UEgjgp8IdBl5PzIHYac8wffRQ39G8LMZR07cll8HaPGA"

    static let rsaPssSha1SignatureBase64Url =
        "rM_td9L0bEnDyo8_7wxbYy2R7b-td3ZB69TFvaoFfm3VLBBELVOpYjHzcW3SKoiKkW56qQ8ZhOfCbWabUVvEmi85l0cf1fjX9Uk1n7tLDRjZwQyBGR3LS5JmOI5TpXZCb9d_wzS4F_wo2x_HTix_fkX7aysINa8RBABlkE9SlofwRWpgn7GTGnnc59WPVKuUUfnNEchm683eyUzi78Mfv5sKLgP7odUYMtMsaQsAN25MYrkmfoRKS-RzQKSV0m7NdGawT2JfPVYV-Q5ZwUtgj_n5FmoCqU7N-Rs2OJMojEvbFfMaAdFFDnyK8pblY0Nt-4epH8U6dPriTdtFa2g_Tw"

    static let rsaPssSha384SignatureBase64Url =
        "MEnKhv7atsfMZOREi-0Ta-jDTPNHW6U1lz0_WgIkvWLJ2fohqgy2nwyBBfU-JtSZrVEaPEbIElu15F0NKHyoNUGU1WY_bwZVVSPCKWIHjbrQwK8whZw3H8NCP9G5zRJhzpFtIYBdG6H4oOzIYHSNvk7_-suOgiaTsSg0eg-ZxXypXYCGBp-mE1iJ4hRYnOVv-_Sbje00qbFCGL6WwP7Jxnucp11p4Plli25GBkggZu1gTGEhGRnU2j9NTZKxbT2Q-MTZ3mTuQohsVvUNMfF6r2ns9FEQIrsApAu2bryJcPVZkulkyBmVTW2XopOFXI-MlkQpmekoLB7ZHP6enlefBQ"

    static let rsaPssSha512SignatureBase64Url =
        "rzU-aGeM1kEp6mvkQgaJ9myGNXyGtP6r18iBfZNEXf0viVvOjL_ebVE2nD3MUEtiPbxD7TAH-4JXfD-STG3BaGDjH0uVu5KCgSPjKRcskEZuOSzhmJ485fP5oc8yRnrl9lIy-RD0ItX5NWU6g40otuC7LmsrH2vWB2KoOKeWQFgCQD_KP8mssSWVuhwml-S3egN8-S6cprMbwHvJsn1KDpWn_pp0gM9FWyNoHqivekcgGJKz0iVcLzHUbxI5lhj51djBuw32bNrU7jB8dQwf847J9ZDr4cAz_vbP5oCTdXOibPG2J0joYR4mpbRgeernoZGxIf44p7HJX75J-WxE0Q"

    static let bip340SecretKeyBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM"
    static let bip340PublicKeyBase64Url = "-TCKAZJYwxBJNE-F-J1SKbUxyEWDb5mwhgHxE7zgNvk"
    static let bip340MessageBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    static let bip340AuxRandBase64Url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    static let bip340SignatureBase64Url =
        "6QeDH4CEjRBppTcbQCQQNkvfHF-DB7AITFXxzi3KghUl9mpKheqLceSCp084LSzl6-7o_bIXL0d99JANMQU2wA"

    static let hpkeInfoBase64Url = "cmVhbGx5bWUtaHBrZS1yZmM5MTgwLWluZm8"
    static let hpkeAadBase64Url = "cmVhbGx5bWUtaHBrZS1yZmM5MTgwLWFhZA"
    static let hpkePlaintextBase64Url = "UmVhbGx5TWUgSFBLRSBSRkMgOTE4MCBCYXNlIHZlY3Rvcg"

    static let hpkeP256RecipientSecretKeyBase64Url =
        "IU-LbKKdMxCVR2YScoOv7g0ZQVt8ItQ5UYqwZS-Rw0Q"
    static let hpkeP256RecipientPublicKeyBase64Url =
        "BAf8y0NFCW-WIXJvxOQ3vgz4HEMQgfMo5VSWcjmsVSLuDZcUdT7G939Veqc3FCadWs_rcpS-vc_8Z8FaZREVX4A"
    static let hpkeP256EncapsulatedKeyBase64Url =
        "BJSRrrdjybpDiedf6tztDSyFIeSUNsCRZjv44YCker98G6dK48lq6AW6PleTVk33U6r7e6SNUA8WQQ2B8ltrINI"
    static let hpkeP256CiphertextBase64Url =
        "HXZsW_I424dEnLuaT7C7yPK4__1mo-FpLbROqjYdcgcKRjrWiOGqjTqdDWYKdT7ZA8w"
    static let hpkeP256TamperedCiphertextBase64Url =
        "HHZsW_I424dEnLuaT7C7yPK4__1mo-FpLbROqjYdcgcKRjrWiOGqjTqdDWYKdT7ZA8w"

    static let hpkeX25519RecipientSecretKeyBase64Url =
        "E7QOQ0MpyDlZIqZtb7jFDTs1Jj-OXAbKxiSoZSfTswQ"
    static let hpkeX25519RecipientPublicKeyBase64Url =
        "y77BzmdEAIfQO_2FNuo_f6kiz1KavGZXi2Lzv1qyYUE"
    static let hpkeX25519EncapsulatedKeyBase64Url =
        "g1Ze68IeTepcVf8OImd0iA10zj5zLp0lgvvIjI1a0SY"
    static let hpkeX25519CiphertextBase64Url =
        "_rnNfmP5CviOGjZoJGBZvbFUg3_5bi-7G4V4eZfrQhK1kVmCZM04DpFUnJawDAk8-QQ"
    static let hpkeX25519TamperedCiphertextBase64Url =
        "_7nNfmP5CviOGjZoJGBZvbFUg3_5bi-7G4V4eZfrQhK1kVmCZM04DpFUnJawDAk8-QQ"
}

struct AesKwVector: Decodable {
    let alg: String
    let kek: String
    let keyData: String
    let wrappedKey: String

    enum CodingKeys: String, CodingKey {
        case alg
        case kek
        case keyData = "key_data"
        case wrappedKey = "wrapped_key"
    }
}

struct Kmac256Vector: Decodable {
    let alg: String
    let key: String
    let context: String
    let customization: String
    let outputLength: Int
    let derivedKey: String

    enum CodingKeys: String, CodingKey {
        case alg
        case key
        case context
        case customization
        case outputLength = "output_length"
        case derivedKey = "derived_key"
    }
}

struct XWingVectors: Decodable {
    let xWing768: XWingVector

    private enum CodingKeys: String, CodingKey {
        case xWing768 = "x_wing_768"
    }
}

struct XWingVector: Decodable {
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let encapsSeed: String
    let ciphertext: String
    let ciphertextLength: Int
    let sharedSecret: String

    private enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case encapsSeed = "encaps_seed"
        case ciphertext
        case ciphertextLength = "ciphertext_length"
        case sharedSecret = "shared_secret"
    }
}

struct MlKemVector: Decodable {
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let ciphertext: String
    let sharedSecret: String
    let tamperedCiphertext: String
    let tamperedSharedSecret: String

    private enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case ciphertext
        case sharedSecret = "shared_secret"
        case tamperedCiphertext = "tampered_ciphertext"
        case tamperedSharedSecret = "tampered_shared_secret"
    }
}

struct EcdsaCurveVector: Decodable {
    let secretKey: String
    let publicKeyCompressed: String
    let publicKeyUncompressed: String
    let message: String
    let signatureDer: String

    private enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKeyCompressed = "public_key_compressed"
        case publicKeyUncompressed = "public_key_uncompressed"
        case message
        case signatureDer = "signature_der"
    }
}

struct MlDsaVector: Decodable {
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let message: String
    let signature: String

    private enum CodingKeys: String, CodingKey {
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case message
        case signature
    }
}

struct SlhDsaVector: Decodable {
    let keygenSkSeed: String
    let keygenSkPrf: String
    let keygenPkSeed: String
    let secretKey: String
    let publicKey: String
    let publicKeyLength: Int
    let secretKeyLength: Int
    let message: String
    let signature: String
    let signatureLength: Int

    private enum CodingKeys: String, CodingKey {
        case keygenSkSeed = "keygen_sk_seed"
        case keygenSkPrf = "keygen_sk_prf"
        case keygenPkSeed = "keygen_pk_seed"
        case secretKey = "secret_key"
        case publicKey = "public_key"
        case publicKeyLength = "public_key_length"
        case secretKeyLength = "secret_key_length"
        case message
        case signature
        case signatureLength = "signature_length"
    }
}
