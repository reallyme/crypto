// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Secp256k1ABI
import Security
import SwiftProviderProbes
import XCTest

final class VectorConformanceTests: XCTestCase {
  private static let expectedVectors = [
    "p256.json",
    "p384.json",
    "p521.json",
    "ed25519.json",
    "secp256k1.json",
    "bip340_schnorr.json",
    "rsa.json",
    "x25519.json",
    "ml_dsa_44.json",
    "ml_dsa_65.json",
    "ml_dsa_87.json",
    "slh_dsa_sha2_128s.json",
    "mlkem512.json",
    "mlkem768.json",
    "mlkem1024.json",
    "x_wing.json",
    "hpke.json",
    "aes128gcm.json",
    "aes192gcm.json",
    "aes256gcm.json",
    "aes256gcmsiv.json",
    "aes128kw.json",
    "aes192kw.json",
    "aes256kw.json",
    "argon2id.json",
    "kmac256.json",
    "chacha20poly1305.json",
    "hkdf.json",
    "hkdf_sha384.json",
    "concat_kdf.json",
    "hmac.json",
    "pbkdf2.json",
    "hashes.json",
    "operation_response.json",
    "jwk.json",
  ]

  func testManifestListsEverySharedVector() throws {
    let manifest: Manifest = try loadVector("manifest.json")
    XCTAssertEqual(manifest.vectors, Self.expectedVectors)
  }

  func testCryptoKitP256Vector() throws {
    let vector: P256Vector = try loadVector("p256.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
    let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
    let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
    let peerCompressedPublicKey = try Data(base64Url: vector.peerPublicKeyCompressed)
    let peerUncompressedPublicKey = try Data(base64Url: vector.peerPublicKeyUncompressed)
    let sharedSecret = try Data(base64Url: vector.sharedSecret)

    let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: secretKey)
    let peerPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: peerSecretKey)
    let peerPublicKey = try P256.KeyAgreement.PublicKey(
      compressedRepresentation: peerCompressedPublicKey)
    let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
    XCTAssertEqual(peerPrivateKey.publicKey.compressedRepresentation, peerCompressedPublicKey)
    XCTAssertEqual(peerPrivateKey.publicKey.x963Representation, peerUncompressedPublicKey)
    XCTAssertEqual(
      try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey).rawBytes, sharedSecret)
    XCTAssertEqual(
      try peerPrivateKey.sharedSecretFromKeyAgreement(with: publicKey).rawBytes, sharedSecret)
  }

  func testCryptoKitP384Vector() throws {
    let vector: Sec1EcdsaVector = try loadVector("p384.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
    let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
    let message = try Data(base64Url: vector.message)
    let signature = try P384.Signing.ECDSASignature(
      derRepresentation: try Data(base64Url: vector.signatureDer)
    )

    let privateKey = try P384.Signing.PrivateKey(rawRepresentation: secretKey)
    let publicKey = try P384.Signing.PublicKey(compressedRepresentation: compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
    XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
  }

  func testCryptoKitP521Vector() throws {
    let vector: Sec1EcdsaVector = try loadVector("p521.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
    let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
    let message = try Data(base64Url: vector.message)
    let signature = try P521.Signing.ECDSASignature(
      derRepresentation: try Data(base64Url: vector.signatureDer)
    )

    let privateKey = try P521.Signing.PrivateKey(rawRepresentation: secretKey)
    let publicKey = try P521.Signing.PublicKey(compressedRepresentation: compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.compressedRepresentation, compressedPublicKey)
    XCTAssertEqual(privateKey.publicKey.x963Representation, uncompressedPublicKey)
    XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
  }

  func testCryptoKitEd25519Vector() throws {
    let vector: Ed25519Vector = try loadVector("ed25519.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let publicKey = try Data(base64Url: vector.publicKey)
    let message = try Data(base64Url: vector.message)
    let signature = try Data(base64Url: vector.signature)

    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: secretKey)
    let verificationKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
    let generatedSignature = try privateKey.signature(for: message)
    XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey)
    XCTAssertTrue(verificationKey.isValidSignature(signature, for: message))
    XCTAssertTrue(verificationKey.isValidSignature(generatedSignature, for: message))
  }

  func testSecurityFrameworkRsaVector() throws {
    let vector: RsaVector = try loadVector("rsa.json")
    let publicKeyDer = try Data(base64Url: vector.publicKeyDer)
    let message = try Data(base64Url: vector.message)
    let pkcs1Sha1Signature = try Data(base64Url: vector.pkcs1v15Sha1Signature)
    let pkcs1Sha256Signature = try Data(base64Url: vector.pkcs1v15Sha256Signature)
    let pssSha256Signature = try Data(base64Url: vector.pssSha256Mgf1Sha256Signature)

    XCTAssertEqual(vector.keyFormat, "PKCS1-DER-RSAPublicKey")
    XCTAssertEqual(vector.pssSha256Mgf1Sha256SaltLen, 32)
    XCTAssertEqual(pkcs1Sha1Signature.count, 256)
    XCTAssertEqual(pkcs1Sha256Signature.count, 256)
    XCTAssertEqual(pssSha256Signature.count, 256)

    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: 2048,
    ]
    let publicKey = try XCTUnwrap(
      SecKeyCreateWithData(publicKeyDer as CFData, attributes as CFDictionary, nil)
    )

    XCTAssertTrue(
      SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePKCS1v15SHA1,
        message as CFData,
        pkcs1Sha1Signature as CFData,
        nil
      )
    )
    XCTAssertTrue(
      SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        message as CFData,
        pkcs1Sha256Signature as CFData,
        nil
      )
    )
    XCTAssertTrue(
      SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePSSSHA256,
        message as CFData,
        pssSha256Signature as CFData,
        nil
      )
    )

    var tampered = pssSha256Signature
    tampered[0] ^= 0x01
    XCTAssertFalse(
      SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePSSSHA256,
        message as CFData,
        tampered as CFData,
        nil
      )
    )
  }

  func testCryptoKitX25519Vector() throws {
    let vector: X25519Vector = try loadVector("x25519.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let publicKey = try Data(base64Url: vector.publicKey)
    let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
    let peerPublicKey = try Data(base64Url: vector.peerPublicKey)
    let sharedSecret = try Data(base64Url: vector.sharedSecret)

    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secretKey)
    let peerPrivateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: peerSecretKey)
    let peerPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
    let localPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
    XCTAssertEqual(privateKey.publicKey.rawRepresentation, publicKey)
    XCTAssertEqual(peerPrivateKey.publicKey.rawRepresentation, peerPublicKey)
    XCTAssertEqual(
      try privateKey.sharedSecretFromKeyAgreement(with: peerPublic).rawBytes,
      sharedSecret
    )
    XCTAssertEqual(
      try peerPrivateKey.sharedSecretFromKeyAgreement(with: localPublic).rawBytes,
      sharedSecret
    )
  }

  func testCryptoKitHpkeVector() throws {
    guard #available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *) else {
      throw XCTSkip("CryptoKit HPKE requires macOS 14 / iOS 17 or newer")
    }

    let vectors: HpkeVectors = try loadVector("hpke.json")
    try openP256HpkeCase(vectors.p256Sha256Aes256Gcm)
    try openX25519HpkeCase(vectors.x25519Sha256ChaCha20Poly1305)
  }

  func testCryptoKitAes256GcmVector() throws {
    let vector: Aes256GcmVector = try loadVector("aes256gcm.json")
    let key = SymmetricKey(data: try Data(base64Url: vector.key))
    let nonceData = try Data(base64Url: vector.nonce)
    _ = try AES.GCM.Nonce(data: nonceData)
    let aad = try Data(base64Url: vector.aad)
    let plaintext = try Data(base64Url: vector.plaintext)
    let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

    let sealedBox = try AES.GCM.SealedBox(combined: nonceData + ciphertextWithTag)
    let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: aad)
    XCTAssertEqual(decrypted, plaintext)
    let generated = try AES.GCM.seal(
      plaintext,
      using: key,
      nonce: AES.GCM.Nonce(data: nonceData),
      authenticating: aad
    )
    let generatedCombined = try XCTUnwrap(generated.combined)
    XCTAssertEqual(generatedCombined.dropFirst(nonceData.count), ciphertextWithTag)
  }

  func testRustFfiAesKwVectors() throws {
    let ffi = try RustCryptoFfi()
    try assertAesKwVector(
      vectorName: "aes128kw.json",
      expectedAlgorithm: "AES-128-KW",
      wrap: ffi.aes128KwWrap,
      unwrap: ffi.aes128KwUnwrap
    )
    try assertAesKwVector(
      vectorName: "aes192kw.json",
      expectedAlgorithm: "AES-192-KW",
      wrap: ffi.aes192KwWrap,
      unwrap: ffi.aes192KwUnwrap
    )
    try assertAesKwVector(
      vectorName: "aes256kw.json",
      expectedAlgorithm: "AES-256-KW",
      wrap: ffi.aes256KwWrap,
      unwrap: ffi.aes256KwUnwrap
    )
  }

  private func assertAesKwVector(
    vectorName: String,
    expectedAlgorithm: String,
    wrap: ([UInt8], [UInt8]) throws -> Data,
    unwrap: ([UInt8], [UInt8]) throws -> Data
  ) throws {
    let vector: AesKwVector = try loadVector(vectorName)
    let kek = [UInt8](try Data(base64Url: vector.kek))
    let keyData = [UInt8](try Data(base64Url: vector.keyData))
    let wrappedKey = try Data(base64Url: vector.wrappedKey)

    XCTAssertEqual(vector.alg, expectedAlgorithm)
    XCTAssertEqual(try wrap(kek, keyData), wrappedKey)
    XCTAssertEqual(try unwrap(kek, [UInt8](wrappedKey)), Data(keyData))

    var tampered = [UInt8](wrappedKey)
    tampered[0] ^= 0x01
    XCTAssertThrowsError(try unwrap(kek, tampered))
  }

  func testRustFfiKmac256Vector() throws {
    let vector: Kmac256Vector = try loadVector("kmac256.json")
    let ffi = try RustCryptoFfi()
    let key = [UInt8](try Data(base64Url: vector.key))
    let context = [UInt8](try Data(base64Url: vector.context))
    let customization = [UInt8](try Data(base64Url: vector.customization))
    let derivedKey = try Data(base64Url: vector.derivedKey)

    XCTAssertEqual(vector.alg, "KMAC256")
    XCTAssertEqual(vector.outputLength, derivedKey.count)
    XCTAssertEqual(
      try ffi.kmac256(
        key: key,
        context: context,
        customization: customization,
        outputLength: vector.outputLength
      ),
      derivedKey
    )
  }

  func testCryptoKitChaCha20Poly1305Vector() throws {
    let vectors: ChaCha20Poly1305Vectors = try loadVector("chacha20poly1305.json")
    let vector = vectors.chacha20Poly1305
    let key = SymmetricKey(data: try Data(base64Url: vector.key))
    let nonceData = try Data(base64Url: vector.nonce)
    let aad = try Data(base64Url: vector.aad)
    let plaintext = try Data(base64Url: vector.plaintext)
    let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

    let sealedBox = try ChaChaPoly.SealedBox(combined: nonceData + ciphertextWithTag)
    let decrypted = try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
    XCTAssertEqual(decrypted, plaintext)

    let generated = try ChaChaPoly.seal(
      plaintext,
      using: key,
      nonce: ChaChaPoly.Nonce(data: nonceData),
      authenticating: aad
    )
    XCTAssertEqual(generated.combined.dropFirst(nonceData.count), ciphertextWithTag)
  }

  func testCryptoKitSha2Vector() throws {
    let vector: HashVector = try loadVector("hashes.json")
    let message = try Data(base64Url: vector.message)

    XCTAssertEqual(Data(SHA256.hash(data: message)), try Data(base64Url: vector.sha2_256))
    XCTAssertEqual(Data(SHA384.hash(data: message)), try Data(base64Url: vector.sha2_384))
    XCTAssertEqual(Data(SHA512.hash(data: message)), try Data(base64Url: vector.sha2_512))
  }

  func testCryptoKitHmacVector() throws {
    let vectors: HmacVectors = try loadVector("hmac.json")

    let sha256Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha256.key))
    let sha256Message = try Data(base64Url: vectors.hmacSha256.message)
    let sha256Tag = Data(HMAC<SHA256>.authenticationCode(for: sha256Message, using: sha256Key))
    XCTAssertEqual(sha256Tag, try Data(base64Url: vectors.hmacSha256.tag))

    let sha384Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha384.key))
    let sha384Message = try Data(base64Url: vectors.hmacSha384.message)
    let sha384Tag = Data(HMAC<SHA384>.authenticationCode(for: sha384Message, using: sha384Key))
    XCTAssertEqual(sha384Tag, try Data(base64Url: vectors.hmacSha384.tag))

    let sha512Key = SymmetricKey(data: try Data(base64Url: vectors.hmacSha512.key))
    let sha512Message = try Data(base64Url: vectors.hmacSha512.message)
    let sha512Tag = Data(HMAC<SHA512>.authenticationCode(for: sha512Message, using: sha512Key))
    XCTAssertEqual(sha512Tag, try Data(base64Url: vectors.hmacSha512.tag))
  }

  func testCryptoKitHkdfVectors() throws {
    try assertHkdfVector(
      "hkdf.json", hash: SHA256.self, algorithm: "HKDF-SHA256", hashName: "SHA-256")
    try assertHkdfVector(
      "hkdf_sha384.json", hash: SHA384.self, algorithm: "HKDF-SHA384", hashName: "SHA-384")
  }

  private func assertHkdfVector<H: HashFunction>(
    _ name: String,
    hash: H.Type,
    algorithm: String,
    hashName: String
  ) throws {
    let vector: HkdfVector = try loadVector(name)
    let ikm = SymmetricKey(data: try Data(base64Url: vector.ikm))
    let salt = try Data(base64Url: vector.salt)
    let info = try Data(base64Url: vector.info)
    let expected = try Data(base64Url: vector.okm)
    XCTAssertEqual(vector.alg, algorithm)
    XCTAssertEqual(vector.hash, hashName)
    XCTAssertEqual(vector.outputLen, expected.count)
    let derived = HKDF<H>.deriveKey(
      inputKeyMaterial: ikm,
      salt: salt,
      info: info,
      outputByteCount: vector.outputLen
    )
    XCTAssertEqual(derived.withUnsafeBytes { Data($0) }, expected)
  }

  func testRustFfiPbkdf2Vector() throws {
    let vectors: Pbkdf2Vectors = try loadVector("pbkdf2.json")
    let ffi = try RustCryptoFfi()
    try assertPbkdf2Case(vectors.pbkdf2HmacSha256, expectedLength: 32) {
      try ffi.pbkdf2HmacSha256(
        password: $0,
        salt: $1,
        iterations: $2,
        outputLength: $3
      )
    }
    try assertPbkdf2Case(vectors.pbkdf2HmacSha512, expectedLength: 64) {
      try ffi.pbkdf2HmacSha512(
        password: $0,
        salt: $1,
        iterations: $2,
        outputLength: $3
      )
    }
  }

  private func assertPbkdf2Case(
    _ vector: Pbkdf2Vector,
    expectedLength: Int,
    derive: ([UInt8], [UInt8], UInt32, Int) throws -> Data
  ) throws {
    let password = [UInt8](try Data(base64Url: vector.password))
    let salt = [UInt8](try Data(base64Url: vector.salt))
    let derivedKey = try Data(base64Url: vector.derivedKey)
    guard let iterations = UInt32(exactly: vector.iterations) else {
      throw VectorError.invalidField
    }

    XCTAssertEqual(vector.outputLen, expectedLength)
    XCTAssertEqual(derivedKey.count, expectedLength)
    XCTAssertEqual(try derive(password, salt, iterations, vector.outputLen), derivedKey)
  }

  func testRustFfiSha3Vector() throws {
    let vector: HashVector = try loadVector("hashes.json")
    let ffi = try RustCryptoFfi()
    let message = try Data(base64Url: vector.message)
    XCTAssertEqual(
      try ffi.sha3_224Digest(message),
      try Data(base64Url: vector.sha3_224)
    )
    XCTAssertEqual(
      try ffi.sha3Digest(message),
      try Data(base64Url: vector.sha3_256)
    )
    XCTAssertEqual(
      try ffi.sha3_384Digest(message),
      try Data(base64Url: vector.sha3_384)
    )
    XCTAssertEqual(
      try ffi.sha3_512Digest(message),
      try Data(base64Url: vector.sha3_512)
    )
  }

  func testLibsecp256k1AbiRoundTrip() throws {
    var publicKey = [UInt8](repeating: 0, count: 33)
    var secretKey = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(secp256k1_generate_keypair(&publicKey, &secretKey), 0)

    let message = Data("reallyme swift secp256k1 conformance".utf8)
    var signature = [UInt8](repeating: 0, count: 64)
    let signStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
      try message.withUnsafeBytes { messageBytes in
        guard
          let secretPointer = secretBytes.baseAddress,
          let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
        else {
          throw VectorError.emptyBuffer
        }
        return secp256k1_sign(
          secretPointer,
          messagePointer,
          message.count,
          &signature
        )
      }
    }
    XCTAssertEqual(signStatus, 0)

    var valid: Int32 = 0
    let verifyStatus = try signature.withUnsafeBufferPointer { signatureBytes in
      try message.withUnsafeBytes { messageBytes in
        try publicKey.withUnsafeBufferPointer { publicBytes in
          guard
            let signaturePointer = signatureBytes.baseAddress,
            let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress,
            let publicPointer = publicBytes.baseAddress
          else {
            throw VectorError.emptyBuffer
          }
          return secp256k1_verify(
            signaturePointer,
            messagePointer,
            message.count,
            publicPointer,
            &valid
          )
        }
      }
    }
    XCTAssertEqual(verifyStatus, 0)
    XCTAssertEqual(valid, 1)
  }

  func testLibsecp256k1Bip340Vector() throws {
    let vector: Bip340SchnorrVector = try loadVector("bip340_schnorr.json")
    let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
    let publicKey = [UInt8](try Data(base64Url: vector.publicKeyXonly))
    let message = [UInt8](try Data(base64Url: vector.message))
    let auxRand = [UInt8](try Data(base64Url: vector.auxRand))
    let expectedSignature = [UInt8](try Data(base64Url: vector.signature))

    var derivedPublicKey = [UInt8](repeating: 0, count: 32)
    let deriveStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
      guard let secretPointer = secretBytes.baseAddress else {
        throw VectorError.emptyBuffer
      }
      return bip340_schnorr_derive_public_key(secretPointer, &derivedPublicKey)
    }
    XCTAssertEqual(deriveStatus, 0)
    XCTAssertEqual(derivedPublicKey, publicKey)

    var signature = [UInt8](repeating: 0, count: 64)
    let signStatus = try secretKey.withUnsafeBufferPointer { secretBytes in
      try message.withUnsafeBufferPointer { messageBytes in
        try auxRand.withUnsafeBufferPointer { auxBytes in
          guard
            let secretPointer = secretBytes.baseAddress,
            let messagePointer = messageBytes.baseAddress,
            let auxPointer = auxBytes.baseAddress
          else {
            throw VectorError.emptyBuffer
          }
          return bip340_schnorr_sign(
            secretPointer,
            messagePointer,
            auxPointer,
            &signature
          )
        }
      }
    }
    XCTAssertEqual(signStatus, 0)
    XCTAssertEqual(signature, expectedSignature)

    var valid: Int32 = 0
    let verifyStatus = try expectedSignature.withUnsafeBufferPointer { signatureBytes in
      try message.withUnsafeBufferPointer { messageBytes in
        try publicKey.withUnsafeBufferPointer { publicKeyBytes in
          guard
            let signaturePointer = signatureBytes.baseAddress,
            let messagePointer = messageBytes.baseAddress,
            let publicKeyPointer = publicKeyBytes.baseAddress
          else {
            throw VectorError.emptyBuffer
          }
          return bip340_schnorr_verify(
            signaturePointer,
            messagePointer,
            publicKeyPointer,
            &valid
          )
        }
      }
    }
    XCTAssertEqual(verifyStatus, 0)
    XCTAssertEqual(valid, 1)

    var tampered = expectedSignature
    tampered[0] ^= 0x01
    let tamperStatus = try tampered.withUnsafeBufferPointer { signatureBytes in
      try message.withUnsafeBufferPointer { messageBytes in
        try publicKey.withUnsafeBufferPointer { publicKeyBytes in
          guard
            let signaturePointer = signatureBytes.baseAddress,
            let messagePointer = messageBytes.baseAddress,
            let publicKeyPointer = publicKeyBytes.baseAddress
          else {
            throw VectorError.emptyBuffer
          }
          return bip340_schnorr_verify(
            signaturePointer,
            messagePointer,
            publicKeyPointer,
            &valid
          )
        }
      }
    }
    XCTAssertEqual(tamperStatus, 0)
    XCTAssertEqual(valid, 0)
  }

  func testRustFfiMlDsaKnownAnswers() throws {
    // Cross-implementation KAT through the compiled native library that
    // iOS links: deterministic signing must reproduce the committed
    // signature, the committed signature must verify, and a tampered
    // signature must be rejected.
    let ffi = try RustCryptoFfi()
    try assertMlDsaKnownAnswer(
      ffi: ffi,
      vectorName: "ml_dsa_44.json",
      sign: ffi.mlDsa44Sign,
      verify: ffi.mlDsa44Verify
    )
    try assertMlDsaKnownAnswer(
      ffi: ffi,
      vectorName: "ml_dsa_65.json",
      sign: ffi.mlDsa65Sign,
      verify: ffi.mlDsa65Verify
    )
    try assertMlDsaKnownAnswer(
      ffi: ffi,
      vectorName: "ml_dsa_87.json",
      sign: ffi.mlDsa87Sign,
      verify: ffi.mlDsa87Verify
    )
  }

  private func assertMlDsaKnownAnswer(
    ffi _: RustCryptoFfi,
    vectorName: String,
    sign: ([UInt8], Data) throws -> Data,
    verify: ([UInt8], Data, [UInt8]) throws -> Void
  ) throws {
    let vector: MlDsaVector = try loadVector(vectorName)
    let secretSeed = [UInt8](try Data(base64Url: vector.secretKey))
    let publicKey = [UInt8](try Data(base64Url: vector.publicKey))
    let message = try Data(base64Url: vector.message)
    let expectedSignature = try Data(base64Url: vector.signature)

    let signature = try sign(secretSeed, message)
    XCTAssertEqual(
      signature, expectedSignature, "\(vectorName): signature must match the committed KAT")

    try verify(publicKey, message, [UInt8](expectedSignature))

    var tampered = [UInt8](expectedSignature)
    tampered[0] ^= 0x01
    XCTAssertThrowsError(
      try verify(publicKey, message, tampered),
      "\(vectorName): tampered signature must be rejected"
    )
  }

  func testRustFfiMlKemKnownAnswer() throws {
    let ffi = try RustCryptoFfi()
    try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem512.json") {
      try ffi.mlKem512Decapsulate(ciphertext: $0, secretKey: $1)
    }
    try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem768.json") {
      try ffi.mlKem768Decapsulate(ciphertext: $0, secretKey: $1)
    }
    try assertMlKemKnownAnswer(ffi: ffi, vectorName: "mlkem1024.json") {
      try ffi.mlKem1024Decapsulate(ciphertext: $0, secretKey: $1)
    }
  }

  func testRustFfiXWingKnownAnswer() throws {
    let ffi = try RustCryptoFfi()
    let vectors: XWingVectors = try loadVector("x_wing.json")
    try assertXWingKnownAnswer(
      vector: vectors.xWing768,
      publicKeyLength: 1_216,
      ciphertextLength: 1_120,
      derivePublicKey: ffi.xWing768PublicKey,
      encapsulateDerand: ffi.xWing768EncapsulateDerand,
      decapsulate: ffi.xWing768Decapsulate
    )
  }

  private func assertXWingKnownAnswer(
    vector: XWingVector,
    publicKeyLength: Int,
    ciphertextLength: Int,
    derivePublicKey: ([UInt8]) throws -> Data,
    encapsulateDerand: ([UInt8], [UInt8]) throws -> (Data, Data),
    decapsulate: ([UInt8], [UInt8]) throws -> Data
  ) throws {
    let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
    let publicKey = [UInt8](try Data(base64Url: vector.publicKey))
    let encapsSeed = [UInt8](try Data(base64Url: vector.encapsSeed))
    let ciphertext = [UInt8](try Data(base64Url: vector.ciphertext))
    let sharedSecret = try Data(base64Url: vector.sharedSecret)

    XCTAssertEqual(vector.secretKeyFormat, "x-wing-seed")
    XCTAssertEqual(publicKey.count, publicKeyLength)
    XCTAssertEqual(ciphertext.count, ciphertextLength)
    XCTAssertEqual(encapsSeed.count, 64)
    XCTAssertEqual(sharedSecret.count, 32)
    XCTAssertEqual(try derivePublicKey(secretKey), Data(publicKey))

    let (derivedCiphertext, derivedSharedSecret) = try encapsulateDerand(publicKey, encapsSeed)
    XCTAssertEqual(derivedCiphertext, Data(ciphertext))
    XCTAssertEqual(derivedSharedSecret, sharedSecret)
    XCTAssertEqual(try decapsulate(ciphertext, secretKey), sharedSecret)
  }

  /// Decapsulates the committed ciphertext to the committed shared secret,
  /// and the tampered ciphertext to the committed implicit-rejection
  /// secret — the same FIPS 203 behavior the Rust and noble oracles show —
  /// exercised through the native library iOS links.
  private func assertMlKemKnownAnswer(
    ffi: RustCryptoFfi,
    vectorName: String,
    decapsulate: ([UInt8], [UInt8]) throws -> Data
  ) throws {
    let vector: MlKemVector = try loadVector(vectorName)
    let secretKey = [UInt8](try Data(base64Url: vector.secretKey))
    let ciphertext = [UInt8](try Data(base64Url: vector.ciphertext))
    let sharedSecret = try Data(base64Url: vector.sharedSecret)
    let tamperedCiphertext = [UInt8](try Data(base64Url: vector.tamperedCiphertext))
    let tamperedSharedSecret = try Data(base64Url: vector.tamperedSharedSecret)

    XCTAssertEqual(
      try decapsulate(ciphertext, secretKey),
      sharedSecret,
      "\(vectorName): decapsulation must reproduce the committed shared secret"
    )

    let rejected = try decapsulate(tamperedCiphertext, secretKey)
    XCTAssertEqual(
      rejected,
      tamperedSharedSecret,
      "\(vectorName): implicit rejection must reproduce the committed pseudorandom secret"
    )
    XCTAssertNotEqual(
      rejected,
      sharedSecret,
      "\(vectorName): implicit rejection must not reveal the real shared secret"
    )
  }

}
