// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extension ReallyMeCrypto {
  public static func hash(_ algorithm: ReallyMeHashAlgorithm, _ bytes: [UInt8])
    throws(ReallyMeCryptoError) -> [UInt8]
  {
    switch algorithm {
    case .sha2_256:
      return ReallyMeDigest.sha256(bytes)
    case .sha2_384:
      return ReallyMeDigest.sha384(bytes)
    case .sha2_512:
      return ReallyMeDigest.sha512(bytes)
    case .sha3_224:
      return ReallyMeDigest.sha3_224(bytes)
    case .sha3_256:
      return ReallyMeDigest.sha3_256(bytes)
    case .sha3_384:
      return ReallyMeDigest.sha3_384(bytes)
    case .sha3_512:
      return ReallyMeDigest.sha3_512(bytes)
    }
  }

  public static func seal(
    _ algorithm: ReallyMeAeadAlgorithm,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8],
    plaintext: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Gcm:
      return try ReallyMeAesGcm.sealAes128Gcm(
        key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    case .aes192Gcm:
      return try ReallyMeAesGcm.sealAes192Gcm(
        key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    case .aes256Gcm:
      return try ReallyMeAesGcm.seal(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    case .chacha20Poly1305:
      return try ReallyMeChaCha20Poly1305.seal(
        key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    case .aes256GcmSiv, .xchacha20Poly1305:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func open(
    _ algorithm: ReallyMeAeadAlgorithm,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8],
    ciphertextWithTag: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Gcm:
      return try ReallyMeAesGcm.openAes128Gcm(
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag
      )
    case .aes192Gcm:
      return try ReallyMeAesGcm.openAes192Gcm(
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag
      )
    case .aes256Gcm:
      return try ReallyMeAesGcm.open(
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag
      )
    case .chacha20Poly1305:
      return try ReallyMeChaCha20Poly1305.open(
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag
      )
    case .aes256GcmSiv, .xchacha20Poly1305:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func authenticate(
    _ algorithm: ReallyMeMacAlgorithm,
    key: [UInt8],
    message: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .hmacSha256:
      return try ReallyMeHmac.authenticateSha256(key: key, message: message)
    case .hmacSha384:
      return try ReallyMeHmac.authenticateSha384(key: key, message: message)
    case .hmacSha512:
      return try ReallyMeHmac.authenticateSha512(key: key, message: message)
    }
  }

  public static func verifyMac(
    _ algorithm: ReallyMeMacAlgorithm,
    tag: [UInt8],
    key: [UInt8],
    message: [UInt8]
  ) throws(ReallyMeCryptoError) -> Bool {
    switch algorithm {
    case .hmacSha256:
      return try ReallyMeHmac.verifySha256(tag: tag, key: key, message: message)
    case .hmacSha384:
      return try ReallyMeHmac.verifySha384(tag: tag, key: key, message: message)
    case .hmacSha512:
      return try ReallyMeHmac.verifySha512(tag: tag, key: key, message: message)
    }
  }

  public static func deriveKey(
    _ algorithm: ReallyMeKdfAlgorithm,
    password: [UInt8],
    salt: [UInt8],
    iterations: UInt32,
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .pbkdf2HmacSha256:
      return try ReallyMePbkdf2.deriveHmacSha256(
        password: password,
        salt: salt,
        iterations: iterations,
        outputLength: outputLength
      )
    case .pbkdf2HmacSha512:
      return try ReallyMePbkdf2.deriveHmacSha512(
        password: password,
        salt: salt,
        iterations: iterations,
        outputLength: outputLength
      )
    case .hkdfSha256, .hkdfSha384, .argon2id, .kmac256, .jwaConcatKdfSha256:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveHkdf(
    _ algorithm: ReallyMeKdfAlgorithm,
    inputKeyMaterial: [UInt8],
    salt: [UInt8],
    info: [UInt8],
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .hkdfSha256:
      return try ReallyMeHkdf.deriveSha256(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputLength: outputLength
      )
    case .hkdfSha384:
      return try ReallyMeHkdf.deriveSha384(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputLength: outputLength
      )
    case .argon2id, .kmac256, .pbkdf2HmacSha256, .pbkdf2HmacSha512, .jwaConcatKdfSha256:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func deriveJwaConcatKdfSha256(
    _ algorithm: ReallyMeKdfAlgorithm,
    sharedSecret: [UInt8],
    algorithmId: [UInt8],
    partyUInfo: [UInt8],
    partyVInfo: [UInt8],
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .jwaConcatKdfSha256:
      return try ReallyMeJwaConcatKdf.deriveSha256(
        sharedSecret: sharedSecret,
        algorithmId: algorithmId,
        partyUInfo: partyUInfo,
        partyVInfo: partyVInfo,
        outputLength: outputLength
      )
    case .argon2id, .hkdfSha256, .hkdfSha384, .kmac256, .pbkdf2HmacSha256, .pbkdf2HmacSha512:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func wrapKey(
    _ algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: [UInt8],
    keyToWrap: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Kw, .aes192Kw, .aes256Kw:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func unwrapKey(
    _ algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: [UInt8],
    wrappedKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Kw, .aes192Kw, .aes256Kw:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func generateKeyPair(
    _ algorithm: ReallyMeSignatureAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      let keyPair = try ReallyMeSecp256k1.generateKeyPair()
      return ReallyMeSignatureKeyPair(
        publicKey: keyPair.publicKey,
        secretKey: keyPair.secretKey
      )
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
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

  public static func sign(
    _ algorithm: ReallyMeSignatureAlgorithm,
    message: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      return try ReallyMeSecp256k1.sign(message: message, secretKey: secretKey)
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
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

  public static func verify(
    _ algorithm: ReallyMeSignatureAlgorithm,
    signature: [UInt8],
    message: [UInt8],
    publicKey: [UInt8]
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      try ReallyMeSecp256k1.verify(
        signature: signature,
        message: message,
        publicKey: publicKey
      )
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
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

}
