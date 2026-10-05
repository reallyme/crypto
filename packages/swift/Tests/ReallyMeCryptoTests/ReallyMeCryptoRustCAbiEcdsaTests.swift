// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoRustCAbiTests {
  func testP256LowSNormalizationMatchesSwiftAndRustCAbi() throws {
    let highS = Self.bytes(
      "304502206e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7"
        + "022100a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6"
    )
    let lowS = Self.bytes(
      "304402206e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7"
        + "02205c8c885bb6f785dcb92a7c63f248fa34cadb5c6ab952e66b6a8b7f0475fbd08b"
    )
    let swiftNormalized = try ReallyMeP256EcdsaSignature.normalizeDerLowS(highS)
    XCTAssertEqual(swiftNormalized, lowS)
    XCTAssertEqual(try ReallyMeP256EcdsaSignature.normalizeDerLowS(swiftNormalized), lowS)

    let library = try Self.configuredRustCAbiLibrary()
    let provider = try ReallyMeRustCAbiP256Ecdsa(library: library)
    XCTAssertEqual(try provider.normalizeDerSignatureLowS(highS), lowS)
    XCTAssertEqual(try provider.normalizeDerSignatureLowS(lowS), lowS)

    let highJose = Self.bytes(
      "6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7"
        + "a37377a349087a2446d5839c0db705caf20b9e42edc4b819892e4bbe866754c6"
    )
    let lowJose = Self.bytes(
      "6e3038666f0655a681c1636c9191509227335c61527ff220426809a695e07ed7"
        + "5c8c885bb6f785dcb92a7c63f248fa34cadb5c6ab952e66b6a8b7f0475fbd08b"
    )
    XCTAssertEqual(try ReallyMeP256EcdsaSignature.normalizeJoseLowS(highJose), lowJose)
    XCTAssertEqual(try provider.normalizeJoseSignatureLowS(highJose), lowJose)

    let zeroJose = [UInt8](repeating: 0, count: 64)
    let orderJose = Self.bytes(
      "0000000000000000000000000000000000000000000000000000000000000001"
        + "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    )
    for malformed in [zeroJose, orderJose] {
      XCTAssertThrowsError(try ReallyMeP256EcdsaSignature.normalizeJoseLowS(malformed))
      XCTAssertThrowsError(try provider.normalizeJoseSignatureLowS(malformed))
    }

    for malformed in [
      Self.bytes("3006020100020101"),
      Self.bytes("300702020001020101"),
      Self.bytes(
        "3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
      ),
      [UInt8](repeating: 0, count: 73),
    ] {
      XCTAssertThrowsError(try ReallyMeP256EcdsaSignature.normalizeDerLowS(malformed))
      XCTAssertThrowsError(try provider.normalizeDerSignatureLowS(malformed))
    }
  }

  func testRustCAbiP256EcdsaVectorWhenLibraryConfigured() throws {
    let library = try Self.configuredRustCAbiLibrary()

    let signature = try ReallyMeCrypto.sign(
      .ecdsaP256Sha256,
      message: Self.p256EcdsaMessage,
      secretKey: Self.p256EcdsaSecretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(signature, Self.p256EcdsaSignatureDer)
    let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
      .ecdsaP256Sha256,
      secretKey: Self.p256EcdsaSecretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(derivedKeyPair.publicKey, Self.p256EcdsaPublicKey)
    XCTAssertEqual(derivedKeyPair.secretKey, Self.p256EcdsaSecretKey)
    try ReallyMeCrypto.verify(
      .ecdsaP256Sha256,
      signature: signature,
      message: Self.p256EcdsaMessage,
      publicKey: Self.p256EcdsaPublicKey,
      rustCAbiLibrary: library
    )

    var tampered = signature
    tampered[tampered.count - 1] ^= 0x01
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP256Sha256,
        signature: tampered,
        message: Self.p256EcdsaMessage,
        publicKey: Self.p256EcdsaPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }

    XCTAssertThrowsError(
      try ReallyMeCrypto.sign(
        .ecdsaP256Sha256,
        message: Self.p256EcdsaMessage,
        secretKey: [0x01, 0x02],
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP256Sha256,
        signature: [0x30, 0x01],
        message: Self.p256EcdsaMessage,
        publicKey: Self.p256EcdsaPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }

    let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP256Sha256, rustCAbiLibrary: library)
    XCTAssertEqual(keyPair.publicKey.count, 33)
    XCTAssertEqual(keyPair.secretKey.count, 32)
    let freshSignature = try ReallyMeCrypto.sign(
      .ecdsaP256Sha256,
      message: Self.p256EcdsaMessage,
      secretKey: keyPair.secretKey,
      rustCAbiLibrary: library
    )
    try ReallyMeCrypto.verify(
      .ecdsaP256Sha256,
      signature: freshSignature,
      message: Self.p256EcdsaMessage,
      publicKey: keyPair.publicKey,
      rustCAbiLibrary: library
    )
  }

  func testRustCAbiP384EcdsaVectorWhenLibraryConfigured() throws {
    let library = try Self.configuredRustCAbiLibrary()
    let vector = try Self.loadEcdsaCurveVector("p384.json")
    let secretKey = try Self.base64UrlBytes(vector.secretKey)
    let compressedPublicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
    let uncompressedPublicKey = try Self.base64UrlBytes(vector.publicKeyUncompressed)
    let message = try Self.base64UrlBytes(vector.message)
    let expectedSignature = try Self.base64UrlBytes(vector.signatureDer)

    XCTAssertEqual(secretKey.count, 48)
    XCTAssertEqual(compressedPublicKey.count, 49)
    XCTAssertEqual(uncompressedPublicKey.count, 97)

    let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
      .ecdsaP384Sha384,
      secretKey: secretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(derivedKeyPair.publicKey, compressedPublicKey)
    XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

    let signature = try ReallyMeCrypto.sign(
      .ecdsaP384Sha384,
      message: message,
      secretKey: secretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(signature, expectedSignature)
    try ReallyMeCrypto.verify(
      .ecdsaP384Sha384,
      signature: signature,
      message: message,
      publicKey: compressedPublicKey,
      rustCAbiLibrary: library
    )
    try ReallyMeCrypto.verify(
      .ecdsaP384Sha384,
      signature: signature,
      message: message,
      publicKey: uncompressedPublicKey,
      rustCAbiLibrary: library
    )
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP384Sha384,
        signature: signature,
        message: message + [0x00],
        publicKey: compressedPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.sign(
        .ecdsaP384Sha384,
        message: message,
        secretKey: [0x01, 0x02],
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP384Sha384,
        signature: [0x30, 0x01],
        message: message,
        publicKey: compressedPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }

    let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP384Sha384, rustCAbiLibrary: library)
    XCTAssertEqual(keyPair.publicKey.count, 49)
    XCTAssertEqual(keyPair.secretKey.count, 48)
    let freshSignature = try ReallyMeCrypto.sign(
      .ecdsaP384Sha384,
      message: message,
      secretKey: keyPair.secretKey,
      rustCAbiLibrary: library
    )
    try ReallyMeCrypto.verify(
      .ecdsaP384Sha384,
      signature: freshSignature,
      message: message,
      publicKey: keyPair.publicKey,
      rustCAbiLibrary: library
    )
  }

  func testRustCAbiP521EcdsaVectorWhenLibraryConfigured() throws {
    let library = try Self.configuredRustCAbiLibrary()
    let vector = try Self.loadEcdsaCurveVector("p521.json")
    let secretKey = try Self.base64UrlBytes(vector.secretKey)
    let compressedPublicKey = try Self.base64UrlBytes(vector.publicKeyCompressed)
    let uncompressedPublicKey = try Self.base64UrlBytes(vector.publicKeyUncompressed)
    let message = try Self.base64UrlBytes(vector.message)
    let expectedSignature = try Self.base64UrlBytes(vector.signatureDer)

    XCTAssertEqual(secretKey.count, 66)
    XCTAssertEqual(compressedPublicKey.count, 67)
    XCTAssertEqual(uncompressedPublicKey.count, 133)

    let derivedKeyPair = try ReallyMeCrypto.deriveKeyPair(
      .ecdsaP521Sha512,
      secretKey: secretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(derivedKeyPair.publicKey, compressedPublicKey)
    XCTAssertEqual(derivedKeyPair.secretKey, secretKey)

    let signature = try ReallyMeCrypto.sign(
      .ecdsaP521Sha512,
      message: message,
      secretKey: secretKey,
      rustCAbiLibrary: library
    )
    XCTAssertEqual(signature, expectedSignature)
    try ReallyMeCrypto.verify(
      .ecdsaP521Sha512,
      signature: signature,
      message: message,
      publicKey: compressedPublicKey,
      rustCAbiLibrary: library
    )
    try ReallyMeCrypto.verify(
      .ecdsaP521Sha512,
      signature: signature,
      message: message,
      publicKey: uncompressedPublicKey,
      rustCAbiLibrary: library
    )
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP521Sha512,
        signature: signature,
        message: message + [0x00],
        publicKey: compressedPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.sign(
        .ecdsaP521Sha512,
        message: message,
        secretKey: [0x01, 0x02],
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.verify(
        .ecdsaP521Sha512,
        signature: [0x30, 0x01],
        message: message,
        publicKey: compressedPublicKey,
        rustCAbiLibrary: library
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidSignature)
    }

    let keyPair = try ReallyMeCrypto.generateKeyPair(.ecdsaP521Sha512, rustCAbiLibrary: library)
    XCTAssertEqual(keyPair.publicKey.count, 67)
    XCTAssertEqual(keyPair.secretKey.count, 66)
    let freshSignature = try ReallyMeCrypto.sign(
      .ecdsaP521Sha512,
      message: message,
      secretKey: keyPair.secretKey,
      rustCAbiLibrary: library
    )
    try ReallyMeCrypto.verify(
      .ecdsaP521Sha512,
      signature: freshSignature,
      message: message,
      publicKey: keyPair.publicKey,
      rustCAbiLibrary: library
    )
  }
}
