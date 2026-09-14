// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Secp256k1ABI
import Security
import SwiftProviderProbes
import XCTest

extension VectorConformanceTests {
  func testLatestSwiftProviderPackagesCompile() {
    XCTAssertEqual(
      SwiftProviderProbe.compiledProviderNames,
      ["SwiftKyber", "SwiftDilithium", "BigInt", "Digest"]
    )
  }

  func testAllVectorShapesAreLoadedAndValidated() throws {
    try validateP256Shape()
    try validateSec1EcdsaShape(
      "p384.json", secretKeyLength: 48, compressedLength: 49, uncompressedLength: 97)
    try validateSec1EcdsaShape(
      "p521.json", secretKeyLength: 66, compressedLength: 67, uncompressedLength: 133)
    try validateEd25519Shape()
    try validateSecp256k1Shape()
    try validateBip340SchnorrShape()
    try validateRsaShape()
    try validateX25519Shape()
    try validateMlDsaShape("ml_dsa_44.json", publicKeyLength: 1_312, signatureLength: 2_420)
    try validateMlDsaShape("ml_dsa_65.json", publicKeyLength: 1_952, signatureLength: 3_309)
    try validateMlDsaShape("ml_dsa_87.json", publicKeyLength: 2_592, signatureLength: 4_627)
    try validateSlhDsaShape()
    try validateMlKemShape("mlkem512.json", publicKeyLength: 800, secretKeyLength: 64)
    try validateMlKemShape("mlkem768.json", publicKeyLength: 1_184, secretKeyLength: 64)
    try validateMlKemShape("mlkem1024.json", publicKeyLength: 1_568, secretKeyLength: 64)
    try validateXWingShape()
    try validateHpkeShape()
    try validateAes256GcmShape()
    try validateAesKwShape(
      "aes128kw.json",
      expectedAlgorithm: "AES-128-KW",
      kekLength: 16,
      keyDataLength: 16
    )
    try validateAesKwShape(
      "aes192kw.json",
      expectedAlgorithm: "AES-192-KW",
      kekLength: 24,
      keyDataLength: 16
    )
    try validateAesKwShape(
      "aes256kw.json",
      expectedAlgorithm: "AES-256-KW",
      kekLength: 32,
      keyDataLength: 32
    )
    try validateChaCha20Poly1305Shape()
    try validateHmacShape()
    try validatePbkdf2Shape()
    try validateKmac256Shape()
    try validateHashShape()
    try validateJwkShape()
  }

  func testSwiftNativeLaneDeclaresExecutableCoverage() throws {
    let manifest: Manifest = try loadVector("manifest.json")
    let swiftLane = try XCTUnwrap(manifest.runtimeLanes.first { $0.name == "swift-native" })

    XCTAssertEqual(swiftLane.status, "executable")
    XCTAssertEqual(
      swiftLane.algorithms,
      [
        "P-256",
        "P-384",
        "P-521",
        "Ed25519",
        "secp256k1",
        "BIP-340-Schnorr",
        "RSA",
        "X25519",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128s",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "X-Wing-768",
        "HPKE-P256-SHA256-AES256GCM",
        "HPKE-X25519-SHA256-CHACHA20POLY1305",
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM",
        "AES-128-KW",
        "AES-192-KW",
        "AES-256-KW",
        "ChaCha20-Poly1305",
        "HMAC-SHA-256",
        "HMAC-SHA-384",
        "HMAC-SHA-512",
        "HKDF-SHA256",
        "HKDF-SHA384",
        "JWA-CONCAT-KDF-SHA256",
        "KMAC256",
        "PBKDF2-HMAC-SHA-256",
        "PBKDF2-HMAC-SHA-512",
        "SHA2-256",
        "SHA2-384",
        "SHA2-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "JWK",
        "JWK-Multikey",
      ]
    )
    XCTAssertTrue(swiftLane.notes.contains { $0.contains("CryptoKit") })
    XCTAssertTrue(swiftLane.notes.contains { $0.contains("libsecp256k1") })
    XCTAssertTrue(swiftLane.notes.contains { $0.contains("SwiftKyber 3.5.0") })
    XCTAssertTrue(swiftLane.notes.contains { $0.contains("SwiftDilithium 3.6.0") })
    XCTAssertTrue(swiftLane.notes.contains { $0.contains("ReallyMe Rust C ABI") })
  }

  func validateP256Shape() throws {
    let vector: P256Vector = try loadVector("p256.json")
    let secretKey = try Data(base64Url: vector.secretKey)
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
    let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)
    let peerSecretKey = try Data(base64Url: vector.peerSecretKey)
    let peerCompressedPublicKey = try Data(base64Url: vector.peerPublicKeyCompressed)
    let peerUncompressedPublicKey = try Data(base64Url: vector.peerPublicKeyUncompressed)
    let sharedSecret = try Data(base64Url: vector.sharedSecret)

    XCTAssertEqual(secretKey.count, 32)
    XCTAssertEqual(compressedPublicKey.count, 33)
    XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
    XCTAssertEqual(uncompressedPublicKey.count, 65)
    XCTAssertEqual(uncompressedPublicKey.first, 0x04)
    XCTAssertEqual(peerSecretKey.count, 32)
    XCTAssertEqual(peerCompressedPublicKey.count, 33)
    XCTAssertTrue(peerCompressedPublicKey.first == 0x02 || peerCompressedPublicKey.first == 0x03)
    XCTAssertEqual(peerUncompressedPublicKey.count, 65)
    XCTAssertEqual(peerUncompressedPublicKey.first, 0x04)
    XCTAssertEqual(sharedSecret.count, 32)
  }

  func validateSec1EcdsaShape(
    _ vectorName: String,
    secretKeyLength: Int,
    compressedLength: Int,
    uncompressedLength: Int
  ) throws {
    let vector: Sec1EcdsaVector = try loadVector(vectorName)
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)
    let uncompressedPublicKey = try Data(base64Url: vector.publicKeyUncompressed)

    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, secretKeyLength)
    XCTAssertEqual(compressedPublicKey.count, compressedLength)
    XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
    XCTAssertEqual(uncompressedPublicKey.count, uncompressedLength)
    XCTAssertEqual(uncompressedPublicKey.first, 0x04)
    XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
    XCTAssertFalse(try Data(base64Url: vector.signatureDer).isEmpty)
  }

  func validateEd25519Shape() throws {
    let vector: Ed25519Vector = try loadVector("ed25519.json")
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
    XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.signature).count, 64)
  }

  func validateSecp256k1Shape() throws {
    let vector: Secp256k1Vector = try loadVector("secp256k1.json")
    let compressedPublicKey = try Data(base64Url: vector.publicKeyCompressed)

    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(compressedPublicKey.count, 33)
    XCTAssertTrue(compressedPublicKey.first == 0x02 || compressedPublicKey.first == 0x03)
  }

  func validateBip340SchnorrShape() throws {
    let vector: Bip340SchnorrVector = try loadVector("bip340_schnorr.json")

    XCTAssertEqual(vector.publicKeyFormat, "x-only")
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.publicKeyXonly).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.message).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.auxRand).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.signature).count, 64)
  }

  func validateRsaShape() throws {
    let vector: RsaVector = try loadVector("rsa.json")

    XCTAssertEqual(vector.keyFormat, "PKCS1-DER-RSAPublicKey")
    XCTAssertEqual(try Data(base64Url: vector.publicKeyDer).first, 0x30)
    XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.pkcs1v15Sha1Signature).count, 256)
    XCTAssertEqual(try Data(base64Url: vector.pkcs1v15Sha256Signature).count, 256)
    XCTAssertEqual(vector.pssSha256Mgf1Sha256SaltLen, 32)
    XCTAssertEqual(try Data(base64Url: vector.pssSha256Mgf1Sha256Signature).count, 256)
  }

  func validateX25519Shape() throws {
    let vector: X25519Vector = try loadVector("x25519.json")
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.peerSecretKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.peerPublicKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.sharedSecret).count, 32)
  }

  func validateMlDsaShape(
    _ vectorName: String,
    publicKeyLength: Int,
    signatureLength: Int
  ) throws {
    let vector: MlDsaVector = try loadVector(vectorName)
    let publicKey = try Data(base64Url: vector.publicKey)

    XCTAssertEqual(vector.secretKeyFormat, "fips-204-seed")
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(publicKey.count, publicKeyLength)
    XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
    XCTAssertEqual(try Data(base64Url: vector.signature).count, signatureLength)
  }

  func validateSlhDsaShape() throws {
    let vector: SlhDsaVector = try loadVector("slh_dsa_sha2_128s.json")

    XCTAssertEqual(vector.secretKeyFormat, "fips-205-serialized-secret-key")
    XCTAssertEqual(try Data(base64Url: vector.publicKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 64)
    XCTAssertEqual(try Data(base64Url: vector.keygenSkSeed).count, 16)
    XCTAssertEqual(try Data(base64Url: vector.keygenSkPrf).count, 16)
    XCTAssertEqual(try Data(base64Url: vector.keygenPkSeed).count, 16)
    XCTAssertEqual(try Data(base64Url: vector.signature).count, 7_856)
    XCTAssertEqual(vector.publicKeyLength, 32)
    XCTAssertEqual(vector.secretKeyLength, 64)
    XCTAssertEqual(vector.signatureLength, 7_856)
  }

  func validateMlKemShape(
    _ vectorName: String,
    publicKeyLength: Int,
    secretKeyLength: Int
  ) throws {
    let vector: MlKemVector = try loadVector(vectorName)

    XCTAssertEqual(vector.secretKeyFormat, "fips-203-seed")
    XCTAssertEqual(try Data(base64Url: vector.publicKey).count, publicKeyLength)
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, secretKeyLength)
    XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
  }

  func validateXWingShape() throws {
    let vectors: XWingVectors = try loadVector("x_wing.json")
    try validateXWingCase(vectors.xWing768, publicKeyLength: 1_216, ciphertextLength: 1_120)
  }

  func validateXWingCase(
    _ vector: XWingVector,
    publicKeyLength: Int,
    ciphertextLength: Int
  ) throws {
    XCTAssertEqual(vector.secretKeyFormat, "x-wing-seed")
    XCTAssertEqual(try Data(base64Url: vector.secretKey).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.publicKey).count, publicKeyLength)
    XCTAssertEqual(vector.publicKeyLength, publicKeyLength)
    XCTAssertEqual(try Data(base64Url: vector.encapsSeed).count, 64)
    XCTAssertEqual(try Data(base64Url: vector.ciphertext).count, ciphertextLength)
    XCTAssertEqual(vector.ciphertextLength, ciphertextLength)
    XCTAssertEqual(try Data(base64Url: vector.sharedSecret).count, 32)
  }

  @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
  func openP256HpkeCase(_ vector: HpkeVector) throws {
    let privateKey = try P256.KeyAgreement.PrivateKey(
      rawRepresentation: try Data(base64Url: vector.recipientSecretKey)
    )
    let publicKey = try P256.KeyAgreement.PublicKey(
      try Data(base64Url: vector.recipientPublicKey),
      kem: .P256_HKDF_SHA256
    )
    XCTAssertEqual(
      privateKey.publicKey.x963Representation, try Data(base64Url: vector.recipientPublicKey))
    XCTAssertEqual(
      try publicKey.hpkeRepresentation(kem: .P256_HKDF_SHA256),
      try Data(base64Url: vector.recipientPublicKey))

    try openHpkeCase(
      vector,
      privateKey: privateKey,
      ciphersuite: .P256_SHA256_AES_GCM_256
    )
  }

  @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
  func openX25519HpkeCase(_ vector: HpkeVector) throws {
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(
      rawRepresentation: try Data(base64Url: vector.recipientSecretKey)
    )
    let publicKey = try Curve25519.KeyAgreement.PublicKey(
      try Data(base64Url: vector.recipientPublicKey),
      kem: .Curve25519_HKDF_SHA256
    )
    XCTAssertEqual(
      privateKey.publicKey.rawRepresentation, try Data(base64Url: vector.recipientPublicKey))
    XCTAssertEqual(
      try publicKey.hpkeRepresentation(kem: .Curve25519_HKDF_SHA256),
      try Data(base64Url: vector.recipientPublicKey))

    try openHpkeCase(
      vector,
      privateKey: privateKey,
      ciphersuite: .Curve25519_SHA256_ChachaPoly
    )
  }

  @available(macOS 14.0, iOS 17.0, tvOS 17.0, watchOS 10.0, *)
  func openHpkeCase<PrivateKey: HPKEDiffieHellmanPrivateKey>(
    _ vector: HpkeVector,
    privateKey: PrivateKey,
    ciphersuite: HPKE.Ciphersuite
  ) throws {
    var recipient = try HPKE.Recipient(
      privateKey: privateKey,
      ciphersuite: ciphersuite,
      info: try Data(base64Url: vector.info),
      encapsulatedKey: try Data(base64Url: vector.encapsulatedKey)
    )
    let opened = try recipient.open(
      try Data(base64Url: vector.ciphertext),
      authenticating: try Data(base64Url: vector.aad)
    )
    XCTAssertEqual(opened, try Data(base64Url: vector.plaintext))

    var tamperedRecipient = try HPKE.Recipient(
      privateKey: privateKey,
      ciphersuite: ciphersuite,
      info: try Data(base64Url: vector.info),
      encapsulatedKey: try Data(base64Url: vector.encapsulatedKey)
    )
    XCTAssertThrowsError(
      try tamperedRecipient.open(
        try Data(base64Url: vector.tamperedCiphertext),
        authenticating: try Data(base64Url: vector.aad)
      )
    )
  }

  func validateHpkeShape() throws {
    let vectors: HpkeVectors = try loadVector("hpke.json")
    try validateHpkeCase(
      vectors.p256Sha256Aes256Gcm,
      kemId: 0x0010,
      kdfId: 0x0001,
      aeadId: 0x0002,
      secretKeyLength: 32,
      publicKeyLength: 65,
      encapsulatedKeyLength: 65
    )
    try validateHpkeCase(
      vectors.x25519Sha256ChaCha20Poly1305,
      kemId: 0x0020,
      kdfId: 0x0001,
      aeadId: 0x0003,
      secretKeyLength: 32,
      publicKeyLength: 32,
      encapsulatedKeyLength: 32
    )
  }

  func validateHpkeCase(
    _ vector: HpkeVector,
    kemId: Int,
    kdfId: Int,
    aeadId: Int,
    secretKeyLength: Int,
    publicKeyLength: Int,
    encapsulatedKeyLength: Int
  ) throws {
    let plaintext = try Data(base64Url: vector.plaintext)
    let ciphertext = try Data(base64Url: vector.ciphertext)

    XCTAssertEqual(vector.mode, "base")
    XCTAssertEqual(vector.kemId, kemId)
    XCTAssertEqual(vector.kdfId, kdfId)
    XCTAssertEqual(vector.aeadId, aeadId)
    XCTAssertEqual(try Data(base64Url: vector.recipientSecretKey).count, secretKeyLength)
    XCTAssertEqual(try Data(base64Url: vector.recipientPublicKey).count, publicKeyLength)
    XCTAssertEqual(try Data(base64Url: vector.encapsSeed).count, 32)
    XCTAssertFalse(try Data(base64Url: vector.info).isEmpty)
    XCTAssertFalse(try Data(base64Url: vector.aad).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.encapsulatedKey).count, encapsulatedKeyLength)
    XCTAssertEqual(ciphertext.count, plaintext.count + 16)
    XCTAssertEqual(try Data(base64Url: vector.tamperedCiphertext).count, ciphertext.count)
  }

  func validateAes256GcmShape() throws {
    let vector: Aes256GcmVector = try loadVector("aes256gcm.json")
    let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

    XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.nonce).count, 12)
    XCTAssertGreaterThanOrEqual(ciphertextWithTag.count, 16)
  }

  func validateAesKwShape(
    _ vectorName: String,
    expectedAlgorithm: String,
    kekLength: Int,
    keyDataLength: Int
  ) throws {
    let vector: AesKwVector = try loadVector(vectorName)

    XCTAssertEqual(vector.alg, expectedAlgorithm)
    XCTAssertEqual(try Data(base64Url: vector.kek).count, kekLength)
    XCTAssertEqual(try Data(base64Url: vector.keyData).count, keyDataLength)
    XCTAssertEqual(try Data(base64Url: vector.wrappedKey).count, keyDataLength + 8)
  }

  func validateKmac256Shape() throws {
    let vector: Kmac256Vector = try loadVector("kmac256.json")

    XCTAssertEqual(vector.alg, "KMAC256")
    XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
    XCTAssertFalse(try Data(base64Url: vector.context).isEmpty)
    XCTAssertFalse(try Data(base64Url: vector.customization).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.derivedKey).count, vector.outputLength)
  }

  func validateChaCha20Poly1305Shape() throws {
    let vectors: ChaCha20Poly1305Vectors = try loadVector("chacha20poly1305.json")
    try validateChaCha20Poly1305Case(vectors.chacha20Poly1305, nonceLength: 12)
    try validateChaCha20Poly1305Case(vectors.xChaCha20Poly1305, nonceLength: 24)
  }

  func validateChaCha20Poly1305Case(
    _ vector: ChaCha20Poly1305Vector,
    nonceLength: Int
  ) throws {
    let ciphertextWithTag = try Data(base64Url: vector.ciphertextWithTag)

    XCTAssertEqual(try Data(base64Url: vector.key).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.nonce).count, nonceLength)
    XCTAssertGreaterThanOrEqual(ciphertextWithTag.count, 16)
  }

  func validateHashShape() throws {
    let vector: HashVector = try loadVector("hashes.json")
    XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.sha2_256).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.sha2_384).count, 48)
    XCTAssertEqual(try Data(base64Url: vector.sha2_512).count, 64)
    XCTAssertEqual(try Data(base64Url: vector.sha3_224).count, 28)
    XCTAssertEqual(try Data(base64Url: vector.sha3_256).count, 32)
    XCTAssertEqual(try Data(base64Url: vector.sha3_384).count, 48)
    XCTAssertEqual(try Data(base64Url: vector.sha3_512).count, 64)
  }

  func validateHmacShape() throws {
    let vectors: HmacVectors = try loadVector("hmac.json")
    try validateHmacCase(vectors.hmacSha256, tagLength: 32)
    try validateHmacCase(vectors.hmacSha384, tagLength: 48)
    try validateHmacCase(vectors.hmacSha512, tagLength: 64)
  }

  func validateHmacCase(_ vector: HmacVector, tagLength: Int) throws {
    XCTAssertFalse(try Data(base64Url: vector.key).isEmpty)
    XCTAssertFalse(try Data(base64Url: vector.message).isEmpty)
    XCTAssertEqual(try Data(base64Url: vector.tag).count, tagLength)
  }

  func validatePbkdf2Shape() throws {
    let vectors: Pbkdf2Vectors = try loadVector("pbkdf2.json")
    try validatePbkdf2Case(vectors.pbkdf2HmacSha256, alg: "PBKDF2-HMAC-SHA-256", outputLength: 32)
    try validatePbkdf2Case(vectors.pbkdf2HmacSha512, alg: "PBKDF2-HMAC-SHA-512", outputLength: 64)
  }

  func validatePbkdf2Case(_ vector: Pbkdf2Vector, alg: String, outputLength: Int) throws {
    XCTAssertEqual(vector.alg, alg)
    XCTAssertFalse(try Data(base64Url: vector.password).isEmpty)
    XCTAssertFalse(try Data(base64Url: vector.salt).isEmpty)
    XCTAssertGreaterThanOrEqual(vector.iterations, 1)
    XCTAssertEqual(vector.outputLen, outputLength)
    XCTAssertEqual(try Data(base64Url: vector.derivedKey).count, outputLength)
  }

}
