// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extension ReallyMeCrypto {
  public func hash(_ algorithm: ReallyMeHashAlgorithm, _ bytes: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    try Self.hash(algorithm, bytes)
  }

  public func seal(
    _ algorithm: ReallyMeAeadAlgorithm,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8],
    plaintext: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Gcm, .aes192Gcm, .aes256Gcm, .chacha20Poly1305:
      return try Self.seal(algorithm, key: key, nonce: nonce, aad: aad, plaintext: plaintext)
    case .aes256GcmSiv, .xchacha20Poly1305:
      return try Self.seal(
        algorithm,
        key: key,
        nonce: nonce,
        aad: aad,
        plaintext: plaintext,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    }
  }

  public func open(
    _ algorithm: ReallyMeAeadAlgorithm,
    key: [UInt8],
    nonce: [UInt8],
    aad: [UInt8],
    ciphertextWithTag: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .aes128Gcm, .aes192Gcm, .aes256Gcm, .chacha20Poly1305:
      return try Self.open(
        algorithm,
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag
      )
    case .aes256GcmSiv, .xchacha20Poly1305:
      return try Self.open(
        algorithm,
        key: key,
        nonce: nonce,
        aad: aad,
        ciphertextWithTag: ciphertextWithTag,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    }
  }

  public func authenticate(
    _ algorithm: ReallyMeMacAlgorithm,
    key: [UInt8],
    message: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.authenticate(algorithm, key: key, message: message)
  }

  public func verifyMac(
    _ algorithm: ReallyMeMacAlgorithm,
    tag: [UInt8],
    key: [UInt8],
    message: [UInt8]
  ) throws(ReallyMeCryptoError) -> Bool {
    try Self.verifyMac(algorithm, tag: tag, key: key, message: message)
  }

  public func deriveKey(
    _ algorithm: ReallyMeKdfAlgorithm,
    password: [UInt8],
    salt: [UInt8],
    iterations: UInt32,
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .argon2id:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    case .pbkdf2HmacSha256, .pbkdf2HmacSha512:
      return try Self.deriveKey(
        algorithm,
        password: password,
        salt: salt,
        iterations: iterations,
        outputLength: outputLength
      )
    case .hkdfSha256, .hkdfSha384, .kmac256, .jwaConcatKdfSha256:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public func deriveArgon2idKey(
    kdfVersion: UInt32,
    secret: [UInt8],
    salt: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.deriveArgon2idKey(
      kdfVersion: kdfVersion,
      secret: secret,
      salt: salt,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func deriveKmac256(
    _ algorithm: ReallyMeKdfAlgorithm,
    key: [UInt8],
    context: [UInt8],
    customization: [UInt8],
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.deriveKmac256(
      algorithm,
      key: key,
      context: context,
      customization: customization,
      outputLength: outputLength,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func deriveHkdf(
    _ algorithm: ReallyMeKdfAlgorithm,
    inputKeyMaterial: [UInt8],
    salt: [UInt8],
    info: [UInt8],
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.deriveHkdf(
      algorithm,
      inputKeyMaterial: inputKeyMaterial,
      salt: salt,
      info: info,
      outputLength: outputLength
    )
  }

  public func deriveJwaConcatKdfSha256(
    _ algorithm: ReallyMeKdfAlgorithm,
    sharedSecret: [UInt8],
    algorithmId: [UInt8],
    partyUInfo: [UInt8],
    partyVInfo: [UInt8],
    outputLength: Int
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.deriveJwaConcatKdfSha256(
      algorithm,
      sharedSecret: sharedSecret,
      algorithmId: algorithmId,
      partyUInfo: partyUInfo,
      partyVInfo: partyVInfo,
      outputLength: outputLength
    )
  }

  public func wrapKey(
    _ algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: [UInt8],
    keyToWrap: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.wrapKey(
      algorithm,
      wrappingKey: wrappingKey,
      keyToWrap: keyToWrap,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func unwrapKey(
    _ algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: [UInt8],
    wrappedKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.unwrapKey(
      algorithm,
      wrappingKey: wrappingKey,
      wrappedKey: wrappedKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func generateKeyPair(
    _ algorithm: ReallyMeSignatureAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      return try Self.generateKeyPair(algorithm)
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      return try Self.generateKeyPair(algorithm, rustCAbiLibrary: requireRustCAbiLibrary())
    case .bip340SchnorrSecp256k1Sha256,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public func deriveKeyPair(
    _ algorithm: ReallyMeSignatureAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      let keyPair = try ReallyMeSecp256k1.deriveKeyPair(secretKey: secretKey)
      return ReallyMeSignatureKeyPair(
        publicKey: keyPair.publicKey,
        secretKey: keyPair.secretKey
      )
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .bip340SchnorrSecp256k1Sha256,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87:
      return try Self.deriveKeyPair(
        algorithm, secretKey: secretKey, rustCAbiLibrary: requireRustCAbiLibrary())
    case .slhDsaSha2_128s,
      .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public func deriveMlDsaKeyPair(
    _ algorithm: ReallyMeSignatureAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    try Self.deriveMlDsaKeyPair(
      algorithm,
      secretKey: secretKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func deriveSlhDsaSha2_128sKeyPair(
    skSeed: [UInt8],
    skPrf: [UInt8],
    pkSeed: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    try Self.deriveSlhDsaSha2_128sKeyPair(
      skSeed: skSeed,
      skPrf: skPrf,
      pkSeed: pkSeed,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

}
