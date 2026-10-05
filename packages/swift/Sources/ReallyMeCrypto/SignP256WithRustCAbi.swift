// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

private let rustCAbiP256SecretKeyLength = 32
private let rustCAbiP256CompressedPublicKeyLength = 33
private let rustCAbiP256UncompressedPublicKeyLength = 65
private let rustCAbiP256SignatureDerMaxLength = 72

private typealias P256GenerateKeyPairFunction =
  @convention(c) (
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
  ) -> Int32

private typealias P256GenerateKeyPairFromSecretKeyFunction =
  @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
  ) -> Int32

private typealias P256SignDerPrehashFunction =
  @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt>?
  ) -> Int32

private typealias P256VerifyDerPrehashFunction =
  @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int,
    UnsafePointer<UInt8>?,
    Int
  ) -> Int32

private typealias P256NormalizeEcdsaDerLowSFunction =
  @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt>?
  ) -> Int32

private typealias P256NormalizeEcdsaJoseLowSFunction =
  @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int
  ) -> Int32

/// P-256 ECDSA operations backed by the ReallyMe Rust C ABI.
///
/// CryptoKit P-256 ECDSA is appropriate for Apple-native verification, but it
/// does not give this package a byte-stable deterministic signing contract.
/// The explicit Rust ABI provider is the route that reproduces the repository's
/// DER/SHA-256 cross-lane vectors exactly.
public struct ReallyMeRustCAbiP256Ecdsa: Sendable {
  private let library: ReallyMeRustCAbiLibrary
  private let generateKeyPairFunction: P256GenerateKeyPairFunction
  private let generateKeyPairFromSecretKeyFunction: P256GenerateKeyPairFromSecretKeyFunction
  private let signFunction: P256SignDerPrehashFunction
  private let verifyFunction: P256VerifyDerPrehashFunction
  private let normalizeFunction: P256NormalizeEcdsaDerLowSFunction
  private let normalizeJoseFunction: P256NormalizeEcdsaJoseLowSFunction

  public init(library: ReallyMeRustCAbiLibrary) throws(ReallyMeCryptoError) {
    self.library = library
    generateKeyPairFunction = try library.loadFunction(
      "rm_crypto_p256_generate_keypair",
      as: P256GenerateKeyPairFunction.self
    )
    generateKeyPairFromSecretKeyFunction = try library.loadFunction(
      "rm_crypto_p256_generate_keypair_from_secret_key",
      as: P256GenerateKeyPairFromSecretKeyFunction.self
    )
    signFunction = try library.loadFunction(
      "rm_crypto_p256_sign_der_prehash",
      as: P256SignDerPrehashFunction.self
    )
    verifyFunction = try library.loadFunction(
      "rm_crypto_p256_verify_der_prehash",
      as: P256VerifyDerPrehashFunction.self
    )
    normalizeFunction = try library.loadFunction(
      "rm_crypto_p256_normalize_ecdsa_der_low_s",
      as: P256NormalizeEcdsaDerLowSFunction.self
    )
    normalizeJoseFunction = try library.loadFunction(
      "rm_crypto_p256_normalize_ecdsa_jose_low_s",
      as: P256NormalizeEcdsaJoseLowSFunction.self
    )
  }

  public func generateKeyPair() throws(ReallyMeCryptoError) -> ReallyMeSignatureKeyPair {
    var publicKey = [UInt8](repeating: 0, count: rustCAbiP256CompressedPublicKeyLength)
    var secretKey = [UInt8](repeating: 0, count: rustCAbiP256SecretKeyLength)
    let publicKeyCapacity = publicKey.count
    let secretKeyCapacity = secretKey.count

    let status = publicKey.withUnsafeMutableBufferPointer { publicBuffer in
      secretKey.withUnsafeMutableBufferPointer { secretBuffer in
        generateKeyPairFunction(
          publicBuffer.baseAddress,
          publicKeyCapacity,
          secretBuffer.baseAddress,
          secretKeyCapacity
        )
      }
    }

    do {
      try ReallyMeRustCAbiStatus.throwIfError(status)
    } catch {
      ReallyMeCryptoMemory.bestEffortClear(&secretKey)
      throw error
    }
    return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: secretKey)
  }

  public func deriveKeyPair(secretKey: [UInt8]) throws(ReallyMeCryptoError)
    -> ReallyMeSignatureKeyPair
  {
    guard secretKey.count == rustCAbiP256SecretKeyLength else {
      throw ReallyMeCryptoError.invalidInput
    }

    var publicKey = [UInt8](repeating: 0, count: rustCAbiP256CompressedPublicKeyLength)
    var returnedSecretKey = [UInt8](repeating: 0, count: rustCAbiP256SecretKeyLength)
    let publicKeyCapacity = publicKey.count
    let secretKeyCapacity = returnedSecretKey.count

    let status = secretKey.withUnsafeBufferPointer { secretBuffer in
      publicKey.withUnsafeMutableBufferPointer { publicBuffer in
        returnedSecretKey.withUnsafeMutableBufferPointer { returnedSecretBuffer in
          generateKeyPairFromSecretKeyFunction(
            secretBuffer.baseAddress,
            secretKey.count,
            publicBuffer.baseAddress,
            publicKeyCapacity,
            returnedSecretBuffer.baseAddress,
            secretKeyCapacity
          )
        }
      }
    }

    do {
      try ReallyMeRustCAbiStatus.throwIfError(status)
    } catch {
      ReallyMeCryptoMemory.bestEffortClear(&returnedSecretKey)
      throw error
    }
    return ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: returnedSecretKey)
  }

  public func sign(message: [UInt8], secretKey: [UInt8]) throws(ReallyMeCryptoError) -> [UInt8] {
    guard secretKey.count == rustCAbiP256SecretKeyLength else {
      throw ReallyMeCryptoError.invalidInput
    }

    var signature = [UInt8](repeating: 0, count: rustCAbiP256SignatureDerMaxLength)
    var signatureLength: UInt = 0
    let signatureCapacity = signature.count
    let status = secretKey.withUnsafeBufferPointer { secretBuffer in
      message.withUnsafeBufferPointer { messageBuffer in
        signature.withUnsafeMutableBufferPointer { signatureBuffer in
          signFunction(
            secretBuffer.baseAddress,
            secretKey.count,
            messageBuffer.baseAddress,
            message.count,
            signatureBuffer.baseAddress,
            signatureCapacity,
            &signatureLength
          )
        }
      }
    }

    try ReallyMeRustCAbiStatus.throwIfError(status)
    guard let length = Int(exactly: signatureLength),
      length > 0,
      length <= rustCAbiP256SignatureDerMaxLength
    else {
      throw ReallyMeCryptoError.providerFailure
    }
    return Array(signature.prefix(length))
  }

  public func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8])
    throws(ReallyMeCryptoError)
  {
    guard
      publicKey.count == rustCAbiP256CompressedPublicKeyLength
        || publicKey.count == rustCAbiP256UncompressedPublicKeyLength
    else {
      throw ReallyMeCryptoError.invalidInput
    }

    let status = signature.withUnsafeBufferPointer { signatureBuffer in
      message.withUnsafeBufferPointer { messageBuffer in
        publicKey.withUnsafeBufferPointer { publicKeyBuffer in
          verifyFunction(
            signatureBuffer.baseAddress,
            signature.count,
            messageBuffer.baseAddress,
            message.count,
            publicKeyBuffer.baseAddress,
            publicKey.count
          )
        }
      }
    }

    try ReallyMeRustCAbiStatus.throwIfError(status)
  }

  /// Returns the canonical low-S representation of a canonical DER signature.
  ///
  /// This validates the representation but does not verify authenticity
  /// against a message or public key.
  public func normalizeDerSignatureLowS(_ signature: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    var normalized = [UInt8](repeating: 0, count: rustCAbiP256SignatureDerMaxLength)
    var normalizedLength: UInt = 0
    let normalizedCapacity = normalized.count
    let status = signature.withUnsafeBufferPointer { signatureBuffer in
      normalized.withUnsafeMutableBufferPointer { normalizedBuffer in
        normalizeFunction(
          signatureBuffer.baseAddress,
          signature.count,
          normalizedBuffer.baseAddress,
          normalizedCapacity,
          &normalizedLength
        )
      }
    }

    try ReallyMeRustCAbiStatus.throwIfError(status)
    guard let length = Int(exactly: normalizedLength),
      length > 0,
      length <= rustCAbiP256SignatureDerMaxLength
    else {
      throw ReallyMeCryptoError.providerFailure
    }
    return Array(normalized.prefix(length))
  }

  /// Returns the canonical low-S form of an exact 64-byte JOSE `r || s`
  /// signature without transcoding through DER.
  public func normalizeJoseSignatureLowS(_ signature: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    guard signature.count == 64 else {
      throw ReallyMeCryptoError.invalidInput
    }
    var normalized = [UInt8](repeating: 0, count: 64)
    let normalizedCapacity = normalized.count
    let status = signature.withUnsafeBufferPointer { signatureBuffer in
      normalized.withUnsafeMutableBufferPointer { normalizedBuffer in
        normalizeJoseFunction(
          signatureBuffer.baseAddress,
          signature.count,
          normalizedBuffer.baseAddress,
          normalizedCapacity
        )
      }
    }
    try ReallyMeRustCAbiStatus.throwIfError(status)
    return normalized
  }
}
