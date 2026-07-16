// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

final class ReallyMeCryptoTests: XCTestCase {
    // MARK: - X25519 (CryptoKit)

    /// Key agreement case from vectors/x25519.json — the same KAT every lane proves.
    static let x25519SecretKey = bytes(
        "13b40e434329c8395922a66d6fb8c50d3b35263f8e5c06cac624a86527d3b304"
    )
    static let x25519PublicKey = bytes(
        "cbbec1ce67440087d03bfd8536ea3f7fa922cf529abc66578b62f3bf5ab26141"
    )
    static let x25519PeerSecretKey = bytes(
        "73806939b0f9e8d2ae4c3d70a4b725933687d2858ca5d08960a9e25450ef50ae"
    )
    static let x25519PeerPublicKey = bytes(
        "4444a8bf80ad7e56fc28dbc826d9f44fc49bd945f3ba2626138f791d7a55180b"
    )
    static let x25519SharedSecret = bytes(
        "e00c4d62a8beeeedc0d7d0aca78e4c94395a063539a8204ce8fc11120e8dbc18"
    )

    // MARK: - P-256 ECDH (CryptoKit)

    static let p256EcdhSecretKey = bytes(
        "214f8b6ca29d3310954766127283afee0d19415b7c22d439518ab0652f91c344"
    )
    static let p256EcdhPublicKey = bytes(
        "0207fccb4345096f9621726fc4e437be0cf81c431081f328e554967239ac5522ee"
    )
    static let p256EcdhPeerSecretKey = bytes(
        "6a1045f2339e8012ab74c628de91075b49ef3218842dbc6013a577c90e4b26d1"
    )
    static let p256EcdhPeerPublicKey = bytes(
        "0258bec98966c3f75836e02cd69aeef19954aab428ba10280652785bfccf9e1121"
    )
    static let p256EcdhSharedSecret = bytes(
        "88e56575ee9a990409e3e406cd82c84ca5d529d2dac781ece3a15eb0b876fe71"
    )

    // MARK: - secp256k1 (Bitcoin Core libsecp256k1 via reallyme/CSecp256k1)

    /// Keypair from vectors/secp256k1.json — the same KAT every lane proves.
    static let vectorSecretKey = bytes(
        "4e390c72a5d15f209963812e37af04bce156489a2f730d8451c63b09f528617d"
    )
    static let vectorPublicKey = bytes(
        "02e1517f97e1877f63fee722a687ddaefc3ec7cce1d27360aeec02091f04e18dd4"
    )

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

    static let aes256GcmKeyBase64Url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    static let aes256GcmNonceBase64Url = "oKGio6Slpqeoqaqr"
    static let aes256GcmAadBase64Url = "cmVhbGx5bWUtY3J5cHRvLXZlY3Rvci1hYWQ"
    static let aes256GcmPlaintextBase64Url =
        "UmVhbGx5TWUgQUVTLTI1Ni1HQ00gY29uZm9ybWFuY2UgdmVjdG9y"
    static let aes256GcmCiphertextWithTagBase64Url =
        "tH0dQSmyT9pCJMKAKkj16F3rGl2y1C0C-mFU6x7FFmTyACKc200hQ-HjxbBMVxDl2Nsc_KOsUQ"

    static let chacha20Poly1305KeyBase64Url = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
    static let chacha20Poly1305NonceBase64Url = "oKGio6Slpqeoqaqr"
    static let chacha20Poly1305AadBase64Url =
        "cmVhbGx5bWUtY3J5cHRvLWNoYWNoYS12ZWN0b3ItYWFk"
    static let chacha20Poly1305PlaintextBase64Url =
        "UmVhbGx5TWUgQ2hhQ2hhMjAtUG9seTEzMDUgY29uZm9ybWFuY2UgdmVjdG9y"
    static let chacha20Poly1305CiphertextWithTagBase64Url =
        "Qjm7Nj2eiPvYGaooqr38rmuSA9awZt2Pvin_CzaZZG0nma6M1z9ITx4vTrjiBaAlakwqodWU2VostKbbVg"

    func testBestEffortMemoryCleanupOverwritesCallerOwnedSwiftBytes() {
        var secret: [UInt8] = [1, 2, 3, 4, 5, 6]
        ReallyMeCryptoMemory.bestEffortClear(&secret)
        XCTAssertEqual(secret, [UInt8](repeating: 0, count: 6))
    }

    func testSecretBearingContainersRedactStringDescriptions() {
        let keyPair = ReallyMeSignatureKeyPair(
            publicKey: [1, 2, 3],
            secretKey: [91, 92, 93]
        )
        XCTAssertTrue(String(describing: keyPair).contains("<redacted>"))
        XCTAssertTrue(String(reflecting: keyPair).contains("<redacted>"))
        XCTAssertFalse(String(describing: keyPair).contains("91"))
        XCTAssertFalse(String(reflecting: keyPair).contains("91"))

        let encapsulation = ReallyMeKemEncapsulation(
            sharedSecret: [81, 82, 83],
            ciphertext: [1, 2, 3]
        )
        XCTAssertTrue(String(describing: encapsulation).contains("<redacted>"))
        XCTAssertTrue(String(reflecting: encapsulation).contains("<redacted>"))
        XCTAssertFalse(String(describing: encapsulation).contains("81"))
        XCTAssertFalse(String(reflecting: encapsulation).contains("81"))
    }
}
