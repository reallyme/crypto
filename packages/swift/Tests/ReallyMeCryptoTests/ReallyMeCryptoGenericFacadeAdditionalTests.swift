// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoTests {
  func testGenericFacadeChaCha20Poly1305KnownAnswerAndTampering() throws {
    let key = try Self.base64UrlBytes(Self.chacha20Poly1305KeyBase64Url)
    let nonce = try Self.base64UrlBytes(Self.chacha20Poly1305NonceBase64Url)
    let aad = try Self.base64UrlBytes(Self.chacha20Poly1305AadBase64Url)
    let plaintext = try Self.base64UrlBytes(Self.chacha20Poly1305PlaintextBase64Url)
    let ciphertext = try Self.base64UrlBytes(Self.chacha20Poly1305CiphertextWithTagBase64Url)

    XCTAssertEqual(
      try ReallyMeCrypto.seal(
        .chacha20Poly1305,
        key: key,
        nonce: nonce,
        aad: aad,
        plaintext: plaintext
      ),
      ciphertext
    )
    XCTAssertEqual(
      try ReallyMeCrypto.open(
        .chacha20Poly1305,
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertext
      ),
      plaintext
    )

    var tampered = ciphertext
    tampered[0] ^= 0x01
    XCTAssertThrowsError(
      try ReallyMeCrypto.open(
        .chacha20Poly1305,
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: tampered
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .authenticationFailed)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.open(
        .chacha20Poly1305,
        key: key,
        nonce: [0x00],
        aad: aad,
        ciphertextWithTag: ciphertext
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
  }

  func testGenericFacadePbkdf2KnownAnswers() throws {
    let password = Array("password".utf8)
    let salt = Array("salt".utf8)

    XCTAssertEqual(
      try ReallyMeCrypto.deriveKey(
        .pbkdf2HmacSha256,
        password: password,
        salt: salt,
        iterations: 100_000,
        outputLength: 32
      ),
      Self.bytes("0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5")
    )
    XCTAssertEqual(
      try ReallyMeCrypto.deriveKey(
        .pbkdf2HmacSha512,
        password: password,
        salt: salt,
        iterations: 100_000,
        outputLength: 64
      ),
      Self.bytes(
        "f5d17022c96af46c0a1dc49a58bbe654a28e98104883e4af4de974cda2c74122"
          + "dd082f4105a93fc80692ca4eb1a784cfeda81bfaa33f5192cc9143d818bd7581"
      )
    )
  }

  func testGenericFacadePbkdf2RejectsInvalidInputsAndUnsupportedKdf() {
    let salt = Array("salt".utf8)
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveKey(
        .pbkdf2HmacSha256,
        password: [],
        salt: salt,
        iterations: 100_000,
        outputLength: 32
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveKey(
        .pbkdf2HmacSha256,
        password: Array("password".utf8),
        salt: [],
        iterations: 100_000,
        outputLength: 32
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveKey(
        .pbkdf2HmacSha256,
        password: Array("password".utf8),
        salt: salt,
        iterations: 0,
        outputLength: 32
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveKey(
        .hkdfSha256,
        password: Array("password".utf8),
        salt: salt,
        iterations: 1,
        outputLength: 32
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
  }

  func testGenericFacadeHkdfKnownAnswer() throws {
    let inputKeyMaterial = Self.bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    let salt = Self.bytes("000102030405060708090a0b0c")
    let info = Self.bytes("f0f1f2f3f4f5f6f7f8f9")

    XCTAssertEqual(
      try ReallyMeCrypto.deriveHkdf(
        .hkdfSha256,
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputLength: 42
      ),
      Self.bytes(
        "3cb25f25faacd57a90434f64d0362f2a"
          + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          + "34007208d5b887185865"
      )
    )
    XCTAssertEqual(
      try ReallyMeCrypto.deriveHkdf(
        .hkdfSha384,
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputLength: 42
      ),
      Self.bytes(
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7"
          + "48b6457763e4f0204fc5"
      )
    )
  }

  func testGenericFacadeHkdfRejectsInvalidInputsAndUnsupportedKdf() {
    let salt = Self.bytes("000102030405060708090a0b0c")
    let info = Self.bytes("f0f1f2f3f4f5f6f7f8f9")

    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveHkdf(
        .hkdfSha256,
        inputKeyMaterial: [],
        salt: salt,
        info: info,
        outputLength: 42
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveHkdf(
        .hkdfSha256,
        inputKeyMaterial: Self.bytes("0b"),
        salt: salt,
        info: info,
        outputLength: 0
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveHkdf(
        .pbkdf2HmacSha256,
        inputKeyMaterial: Self.bytes("0b"),
        salt: salt,
        info: info,
        outputLength: 42
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
  }

  func testGenericFacadeJwaConcatKdfMatchesSharedVector() throws {
    let data = try Data(contentsOf: reallyMeVectorURL("concat_kdf.json"))
    let vector = try JSONDecoder().decode(ConcatKdfVector.self, from: data)
    let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)
    let algorithmId = try Self.base64UrlBytes(vector.algorithmId)
    let partyUInfo = try Self.base64UrlBytes(vector.partyUInfo)
    let partyVInfo = try Self.base64UrlBytes(vector.partyVInfo)
    let derivedKey = try Self.base64UrlBytes(vector.derivedKey)

    XCTAssertEqual(
      try ReallyMeJwaConcatKdf.deriveSha256(
        sharedSecret: sharedSecret,
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: vector.outputLen
      ),
      derivedKey
    )
    XCTAssertEqual(
      try ReallyMeCrypto.deriveJwaConcatKdfSha256(
        .jwaConcatKdfSha256,
        sharedSecret: sharedSecret,
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: vector.outputLen
      ),
      derivedKey
    )
  }

  func testGenericFacadeJwaConcatKdfRejectsInvalidInputsAndUnsupportedKdf() throws {
    let data = try Data(contentsOf: reallyMeVectorURL("concat_kdf.json"))
    let vector = try JSONDecoder().decode(ConcatKdfVector.self, from: data)
    let sharedSecret = try Self.base64UrlBytes(vector.sharedSecret)
    let algorithmId = try Self.base64UrlBytes(vector.algorithmId)
    let partyUInfo = try Self.base64UrlBytes(vector.partyUInfo)
    let partyVInfo = try Self.base64UrlBytes(vector.partyVInfo)

    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveJwaConcatKdfSha256(
        .jwaConcatKdfSha256,
        sharedSecret: [],
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: vector.outputLen
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveJwaConcatKdfSha256(
        .jwaConcatKdfSha256,
        sharedSecret: sharedSecret,
        algorithmId: [],
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: vector.outputLen
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveJwaConcatKdfSha256(
        .jwaConcatKdfSha256,
        sharedSecret: sharedSecret,
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: 0
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.deriveJwaConcatKdfSha256(
        .hkdfSha256,
        sharedSecret: sharedSecret,
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: vector.outputLen
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
  }

  func testGenericFacadeRemainingFamiliesReturnTypedUnsupportedAlgorithm() {
    let empty = [UInt8]()

    XCTAssertThrowsError(
      try ReallyMeCrypto.seal(.aes256GcmSiv, key: empty, nonce: empty, aad: empty, plaintext: empty)
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.wrapKey(.aes256Kw, wrappingKey: empty, keyToWrap: empty)
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
    XCTAssertThrowsError(try ReallyMeCrypto.generateKemKeyPair(.mlKem768)) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
    XCTAssertThrowsError(
      try ReallyMeCrypto.sealHpke(
        .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
        recipientPublicKey: empty,
        info: empty,
        aad: empty,
        plaintext: empty
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
    }
  }

  func testGenericFacadeSupportedAlgorithmSetsAreExplicit() {
    XCTAssertEqual(
      Set(ReallyMeHashAlgorithm.allCases),
      [.sha2_256, .sha2_384, .sha2_512, .sha3_224, .sha3_256, .sha3_384, .sha3_512]
    )
    XCTAssertEqual(
      Set(ReallyMeMacAlgorithm.allCases),
      [.hmacSha256, .hmacSha384, .hmacSha512]
    )
    XCTAssertEqual(
      Set(ReallyMeKeyAgreementAlgorithm.allCases),
      [.x25519, .p256Ecdh, .p384Ecdh, .p521Ecdh]
    )
  }

  func testGenericFacadeUnsupportedSignaturesAreExhaustive() {
    let empty = [UInt8]()
    let supported: Set<ReallyMeSignatureAlgorithm> = [.ecdsaSecp256k1Sha256]

    for algorithm in ReallyMeSignatureAlgorithm.allCases where !supported.contains(algorithm) {
      XCTAssertThrowsError(try ReallyMeCrypto.generateKeyPair(algorithm), algorithm.rawValue) {
        error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.sign(algorithm, message: empty, secretKey: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.verify(algorithm, signature: empty, message: empty, publicKey: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }
  }

  func testGenericFacadeUnsupportedReservedFamiliesAreExhaustive() {
    let empty = [UInt8]()
    let unsupportedAeadAlgorithms: Set<ReallyMeAeadAlgorithm> = [
      .aes256GcmSiv,
      .xchacha20Poly1305,
    ]

    for algorithm in ReallyMeAeadAlgorithm.allCases
    where unsupportedAeadAlgorithms.contains(algorithm) {
      XCTAssertThrowsError(
        try ReallyMeCrypto.seal(algorithm, key: empty, nonce: empty, aad: empty, plaintext: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.open(
          algorithm, key: empty, nonce: empty, aad: empty, ciphertextWithTag: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }

    for algorithm in ReallyMeKemAlgorithm.allCases {
      XCTAssertThrowsError(try ReallyMeCrypto.generateKemKeyPair(algorithm), algorithm.rawValue) {
        error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.encapsulate(algorithm, publicKey: empty), algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.decapsulate(algorithm, ciphertext: empty, secretKey: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }

    for algorithm in ReallyMeKeyWrapAlgorithm.allCases {
      XCTAssertThrowsError(
        try ReallyMeCrypto.wrapKey(algorithm, wrappingKey: empty, keyToWrap: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.unwrapKey(algorithm, wrappingKey: empty, wrappedKey: empty),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }

    for suite in ReallyMeHpkeSuite.allCases {
      XCTAssertThrowsError(
        try ReallyMeCrypto.sealHpke(
          suite,
          recipientPublicKey: empty,
          info: empty,
          aad: empty,
          plaintext: empty
        ),
        suite.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
      XCTAssertThrowsError(
        try ReallyMeCrypto.openHpke(
          suite,
          recipientSecretKey: empty,
          encapsulatedKey: empty,
          info: empty,
          aad: empty,
          ciphertext: empty
        ),
        suite.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }
  }

  func testGenericFacadeUnsupportedKdfRoutesAreExhaustive() {
    let empty = [UInt8]()
    let deriveKeySupported: Set<ReallyMeKdfAlgorithm> = [.pbkdf2HmacSha256, .pbkdf2HmacSha512]
    let deriveHkdfSupported: Set<ReallyMeKdfAlgorithm> = [.hkdfSha256, .hkdfSha384]
    let deriveJwaConcatSupported: Set<ReallyMeKdfAlgorithm> = [.jwaConcatKdfSha256]

    for algorithm in ReallyMeKdfAlgorithm.allCases where !deriveKeySupported.contains(algorithm) {
      XCTAssertThrowsError(
        try ReallyMeCrypto.deriveKey(
          algorithm,
          password: empty,
          salt: empty,
          iterations: 1,
          outputLength: 1
        ),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }

    for algorithm in ReallyMeKdfAlgorithm.allCases where !deriveHkdfSupported.contains(algorithm) {
      XCTAssertThrowsError(
        try ReallyMeCrypto.deriveHkdf(
          algorithm,
          inputKeyMaterial: empty,
          salt: empty,
          info: empty,
          outputLength: 1
        ),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }

    for algorithm in ReallyMeKdfAlgorithm.allCases
    where !deriveJwaConcatSupported.contains(algorithm) {
      XCTAssertThrowsError(
        try ReallyMeCrypto.deriveJwaConcatKdfSha256(
          algorithm,
          sharedSecret: empty,
          algorithmId: empty,
          partyUInfo: empty,
          partyVInfo: empty,
          outputLength: 1
        ),
        algorithm.rawValue
      ) { error in
        XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
      }
    }
  }

  func testMissingRustAbiLibraryReturnsTypedError() {
    XCTAssertThrowsError(try ReallyMeRustCAbiLibrary(path: "/tmp/reallyme-crypto-missing.dylib")) {
      error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .dynamicLibraryNotFound)
    }
  }

  func testRustAbiLibraryRejectsRelativePath() {
    XCTAssertThrowsError(try ReallyMeRustCAbiLibrary(path: "libcrypto_ffi.dylib")) { error in
      XCTAssertEqual(error as? ReallyMeCryptoError, .invalidInput)
    }
  }
}
