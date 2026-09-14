// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extension ReallyMeCrypto {
  public func sign(
    _ algorithm: ReallyMeSignatureAlgorithm,
    message: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      return try Self.sign(algorithm, message: message, secretKey: secretKey)
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      return try Self.sign(
        algorithm,
        message: message,
        secretKey: secretKey,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
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

  public func deriveBip340SchnorrPublicKey(secretKey: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    try Self.deriveBip340SchnorrPublicKey(
      secretKey: secretKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func sign(
    _ algorithm: ReallyMeSignatureAlgorithm,
    message32: [UInt8],
    secretKey: [UInt8],
    auxRand32: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    switch algorithm {
    case .bip340SchnorrSecp256k1Sha256:
      return try Self.sign(
        algorithm,
        message32: message32,
        secretKey: secretKey,
        auxRand32: auxRand32,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
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

  public func verify(
    _ algorithm: ReallyMeSignatureAlgorithm,
    signature: [UInt8],
    message: [UInt8],
    publicKey: [UInt8]
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .ecdsaSecp256k1Sha256:
      try Self.verify(algorithm, signature: signature, message: message, publicKey: publicKey)
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .bip340SchnorrSecp256k1Sha256,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      try Self.verify(
        algorithm,
        signature: signature,
        message: message,
        publicKey: publicKey,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    case .rsaPkcs1v15Sha1,
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

  public func verify(
    _ algorithm: ReallyMeSignatureAlgorithm,
    signature: [UInt8],
    message: [UInt8],
    publicKeyDer: [UInt8],
    publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding
  ) throws(ReallyMeCryptoError) {
    switch algorithm {
    case .rsaPkcs1v15Sha1,
      .rsaPkcs1v15Sha256,
      .rsaPkcs1v15Sha384,
      .rsaPkcs1v15Sha512,
      .rsaPssSha1Mgf1Sha1,
      .rsaPssSha256Mgf1Sha256,
      .rsaPssSha384Mgf1Sha384,
      .rsaPssSha512Mgf1Sha512:
      try Self.verify(
        algorithm,
        signature: signature,
        message: message,
        publicKeyDer: publicKeyDer,
        publicKeyEncoding: publicKeyEncoding,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    case .ed25519,
      .ecdsaP256Sha256,
      .ecdsaP384Sha384,
      .ecdsaP521Sha512,
      .ecdsaSecp256k1Sha256,
      .bip340SchnorrSecp256k1Sha256,
      .mlDsa44,
      .mlDsa65,
      .mlDsa87,
      .slhDsaSha2_128s:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public func deriveSharedSecret(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    publicKey: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.deriveSharedSecret(algorithm, publicKey: publicKey, secretKey: secretKey)
  }

  public func deriveKeyAgreementKeyPair(
    _ algorithm: ReallyMeKeyAgreementAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementKeyPair {
    try Self.deriveKeyAgreementKeyPair(algorithm, secretKey: secretKey)
  }

  public func generateKemKeyPair(_ algorithm: ReallyMeKemAlgorithm) throws(ReallyMeCryptoError)
    -> ReallyMeKemKeyPair
  {
    try Self.generateKemKeyPair(algorithm, rustCAbiLibrary: requireRustCAbiLibrary())
  }

  public func deriveXWingKeyPair(
    _ algorithm: ReallyMeKemAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKemKeyPair {
    try Self.deriveXWingKeyPair(
      algorithm,
      secretKey: secretKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func deriveMlKemKeyPair(
    _ algorithm: ReallyMeKemAlgorithm,
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKemKeyPair {
    try Self.deriveMlKemKeyPair(
      algorithm,
      secretKey: secretKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func encapsulate(
    _ algorithm: ReallyMeKemAlgorithm,
    publicKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeKemEncapsulation {
    switch algorithm {
    case .xWing768:
      return try Self.encapsulate(
        algorithm,
        publicKey: publicKey,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    case .mlKem512, .mlKem768, .mlKem1024:
      return try Self.encapsulate(
        algorithm,
        publicKey: publicKey,
        rustCAbiLibrary: requireRustCAbiLibrary()
      )
    }
  }

  public func decapsulate(
    _ algorithm: ReallyMeKemAlgorithm,
    ciphertext: [UInt8],
    secretKey: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.decapsulate(
      algorithm,
      ciphertext: ciphertext,
      secretKey: secretKey,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func sealHpke(
    _ suite: ReallyMeHpkeSuite,
    recipientPublicKey: [UInt8],
    info: [UInt8],
    aad: [UInt8],
    plaintext: [UInt8]
  ) throws(ReallyMeCryptoError) -> ReallyMeHpkeSealedMessage {
    try Self.sealHpke(
      suite,
      recipientPublicKey: recipientPublicKey,
      info: info,
      aad: aad,
      plaintext: plaintext,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

  public func openHpke(
    _ suite: ReallyMeHpkeSuite,
    recipientSecretKey: [UInt8],
    encapsulatedKey: [UInt8],
    info: [UInt8],
    aad: [UInt8],
    ciphertext: [UInt8]
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try Self.openHpke(
      suite,
      recipientSecretKey: recipientSecretKey,
      encapsulatedKey: encapsulatedKey,
      info: info,
      aad: aad,
      ciphertext: ciphertext,
      rustCAbiLibrary: requireRustCAbiLibrary()
    )
  }

}
