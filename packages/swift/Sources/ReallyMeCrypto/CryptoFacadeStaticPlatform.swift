// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extension ReallyMeCrypto {
  public static func generateSecureEnclaveSigningKeyPair(
    _ algorithm: ReallyMeSignatureAlgorithm,
    tag: [UInt8],
    accessControl: ReallyMeSecureEnclaveAccessControl = .userPresence,
    overwriteExisting: Bool = false
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureHandleKeyPair {
    switch algorithm {
    case .ecdsaP256Sha256:
      return try ReallyMeP256SecureEnclaveEcdsa.generateKeyPair(
        tag: tag,
        accessControl: accessControl,
        overwriteExisting: overwriteExisting
      )
    case .ed25519,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveSecureEnclaveSigningPublicKey(
    _ algorithm: ReallyMeSignatureAlgorithm,
    privateKeyHandle: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .ecdsaP256Sha256:
      return try ReallyMeP256SecureEnclaveEcdsa.derivePublicKey(
        privateKeyHandle: privateKeyHandle
      )
    case .ed25519,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func signWithPrivateKeyHandle(
    _ algorithm: ReallyMeSignatureAlgorithm,
    message: [UInt8],
    privateKeyHandle: [UInt8],
    authenticationPrompt: String? = nil
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .ecdsaP256Sha256:
      return try ReallyMeP256SecureEnclaveEcdsa.sign(
        message: message,
        privateKeyHandle: privateKeyHandle,
        authenticationPrompt: authenticationPrompt
      )
    case .ed25519,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func verifySecureEnclaveSignature(
    _ algorithm: ReallyMeSignatureAlgorithm,
    signature: [UInt8],
    message: [UInt8],
    publicKey: [UInt8]
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .ecdsaP256Sha256:
      try ReallyMeP256SecureEnclaveEcdsa.verify(
        signature: signature,
        message: message,
        publicKey: publicKey
      )
    case .ed25519,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deleteSecureEnclaveSigningKey(
    _ algorithm: ReallyMeSignatureAlgorithm,
    privateKeyHandle: [UInt8]
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .ecdsaP256Sha256:
      try ReallyMeP256SecureEnclaveEcdsa.deleteKey(privateKeyHandle: privateKeyHandle)
    case .ed25519,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveSharedSecret(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    publicKey: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .x25519:
      return try ReallyMeX25519.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
    case .p256Ecdh:
      return try ReallyMeP256Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
    case .p384Ecdh:
      return try ReallyMeP384Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
    case .p521Ecdh:
      return try ReallyMeP521Ecdh.deriveSharedSecret(publicKey: publicKey, secretKey: secretKey)
    }
  }

  public static func generateSecureEnclaveKeyAgreementKeyPair(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    tag: [UInt8],
    overwriteExisting: Bool = false
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementHandleKeyPair {
    switch algorithm {
    case .p256Ecdh:
      return try ReallyMeP256SecureEnclaveEcdh.generateKeyPair(
        tag: tag,
        overwriteExisting: overwriteExisting
      )
    case .x25519, .p384Ecdh, .p521Ecdh:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveSharedSecretWithPrivateKeyHandle(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    publicKey: [UInt8],
    privateKeyHandle: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .p256Ecdh:
      return try ReallyMeP256SecureEnclaveEcdh.deriveSharedSecret(
        publicKey: publicKey,
        privateKeyHandle: privateKeyHandle
      )
    case .x25519, .p384Ecdh, .p521Ecdh:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deleteSecureEnclaveKeyAgreementKey(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    privateKeyHandle: [UInt8]
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .p256Ecdh:
      try ReallyMeP256SecureEnclaveEcdh.deleteKey(privateKeyHandle: privateKeyHandle)
    case .x25519, .p384Ecdh, .p521Ecdh:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveKeyAgreementKeyPair(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementKeyPair {
    switch algorithm {
    case .x25519:
      let keyPair = try ReallyMeX25519.deriveKeyPair(secretKey: secretKey)
      return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    case .p256Ecdh:
      let keyPair = try ReallyMeP256Ecdh.deriveKeyPair(secretKey: secretKey)
      return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    case .p384Ecdh:
      let keyPair = try ReallyMeP384Ecdh.deriveKeyPair(secretKey: secretKey)
      return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    case .p521Ecdh:
      let keyPair = try ReallyMeP521Ecdh.deriveKeyPair(secretKey: secretKey)
      return ReallyMeKeyAgreementKeyPair(publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
    }
  }

  public static func generateKemKeyPair(_ algorithm: ReallyMeKemAlgorithm)
    throws(ReallyMeCryptoError)
    -> ReallyMeKemKeyPair
  {
    switch algorithm {
    case .mlKem512, .mlKem768, .mlKem1024, .xWing768:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func encapsulate(
    _ algorithm: ReallyMeKemAlgorithm,
    publicKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKemEncapsulation {
    switch algorithm {
    case .mlKem512, .mlKem768, .mlKem1024, .xWing768:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func decapsulate(
    _ algorithm: ReallyMeKemAlgorithm,
    ciphertext: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .mlKem512, .mlKem768, .mlKem1024, .xWing768:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func sealHpke(
    _ suite: ReallyMeHpkeSuite,
    recipientPublicKey: [UInt8],
    info: [UInt8],
    aad: [UInt8],
    plaintext: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeHpkeSealedMessage {
    switch suite {
    case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
      .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func openHpke(
    _ suite: ReallyMeHpkeSuite,
    recipientSecretKey: [UInt8],
    encapsulatedKey: [UInt8],
    info: [UInt8],
    aad: [UInt8],
    ciphertext: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch suite {
    case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm,
      .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

}
