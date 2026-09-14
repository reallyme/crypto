// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#endif

/// Runtime handle for the ReallyMe Rust C ABI provider.
///
/// Release SwiftPM packages link the bundled `ReallyMeCryptoFFI` binary target
/// and resolve symbols directly. The path-based initializer is retained for
/// local Rust development and tests against freshly built dynamic libraries;
/// it accepts only absolute paths so resolution never depends on a mutable
/// process working directory.
public final class ReallyMeRustCAbiLibrary: Sendable {
  // Store the immutable process-local handle address as a Sendable scalar.
  // Pointer reconstruction is confined to the Darwin loader calls below, so
  // callers cannot observe or mutate the raw handle across isolation domains.
  private let handleAddress: UInt?
  private let usesLinkedSymbols: Bool

  public static var isBundledProviderAvailable: Bool {
    #if REALLYME_CRYPTO_LINKED_FFI
      return true
    #else
      return false
    #endif
  }

  public static func bundledProvider() throws(ReallyMeCryptoError) -> ReallyMeRustCAbiLibrary {
    #if REALLYME_CRYPTO_LINKED_FFI
      return ReallyMeRustCAbiLibrary(linkedSymbols: ())
    #else
      throw ReallyMeCryptoError.providerFailure
    #endif
  }

  #if REALLYME_CRYPTO_LINKED_FFI
    private init(linkedSymbols _: Void) {
      handleAddress = nil
      usesLinkedSymbols = true
    }
  #endif

  public init(path: String) throws(ReallyMeCryptoError) {
    #if canImport(Darwin)
      guard (path as NSString).isAbsolutePath else {
        throw ReallyMeCryptoError.invalidInput
      }
      guard FileManager.default.fileExists(atPath: path) else {
        throw ReallyMeCryptoError.dynamicLibraryNotFound
      }
      guard let loadedHandle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
        throw ReallyMeCryptoError.dynamicLibraryLoadFailed
      }
      handleAddress = UInt(bitPattern: loadedHandle)
      usesLinkedSymbols = false
    #else
      _ = path
      throw ReallyMeCryptoError.unsupportedPlatform
    #endif
  }

  deinit {
    #if canImport(Darwin)
      if let handleAddress, let handle = UnsafeMutableRawPointer(bitPattern: handleAddress) {
        dlclose(handle)
      }
    #endif
  }

  func loadFunction<Function>(_ symbol: StaticString, as type: Function.Type)
    throws(ReallyMeCryptoError) -> Function
  {
    #if REALLYME_CRYPTO_LINKED_FFI
      if usesLinkedSymbols {
        return try loadLinkedFunction(symbol, as: type)
      }
    #endif
    #if canImport(Darwin)
      guard let handleAddress, let handle = UnsafeMutableRawPointer(bitPattern: handleAddress)
      else {
        throw ReallyMeCryptoError.providerFailure
      }
      guard let rawSymbol = dlsym(handle, symbol.description) else {
        throw ReallyMeCryptoError.symbolNotFound
      }
      return unsafeBitCast(rawSymbol, to: Function.self)
    #else
      _ = symbol
      _ = type
      throw ReallyMeCryptoError.unsupportedPlatform
    #endif
  }

  #if REALLYME_CRYPTO_LINKED_FFI
    private func linked<Concrete, Function>(
      _ function: Concrete,
      as requestedType: Function.Type
    ) throws(ReallyMeCryptoError) -> Function {
      // A symbol name and a generic caller-selected function type are not a
      // sufficient ABI contract. Reject mismatched metatypes before the one
      // unavoidable cast so an internal adapter cannot invoke undefined
      // behavior by pairing a valid symbol with the wrong signature.
      guard ObjectIdentifier(requestedType) == ObjectIdentifier(Concrete.self) else {
        throw ReallyMeCryptoError.providerFailure
      }
      return unsafeBitCast(function, to: Function.self)
    }

    private func loadLinkedFunction<Function>(_ symbol: StaticString, as type: Function.Type)
      throws(ReallyMeCryptoError)
      -> Function
    {
      guard let linkedSymbol = LinkedRustCAbiSymbol(symbol) else {
        throw ReallyMeCryptoError.symbolNotFound
      }
      switch linkedSymbol {
      case .processOperationResponse:
        return try linked(
          rmCryptoProcessOperationResponseLinked as LinkedOperationResponseFunction, as: type)
      case .processOperationResponseJson:
        return try linked(
          rmCryptoProcessOperationResponseJsonLinked as LinkedOperationResponseFunction, as: type)
      case .aes192GcmEncrypt:
        return try linked(rmCryptoAes192GcmEncryptLinked as LinkedAeadFunction, as: type)
      case .aes192GcmDecrypt:
        return try linked(rmCryptoAes192GcmDecryptLinked as LinkedAeadFunction, as: type)
      case .aes256GcmSivEncrypt:
        return try linked(rmCryptoAes256GcmSivEncryptLinked as LinkedAeadFunction, as: type)
      case .aes256GcmSivDecrypt:
        return try linked(rmCryptoAes256GcmSivDecryptLinked as LinkedAeadFunction, as: type)
      case .xchacha20Poly1305Encrypt:
        return try linked(rmCryptoXChaCha20Poly1305EncryptLinked as LinkedAeadFunction, as: type)
      case .xchacha20Poly1305Decrypt:
        return try linked(rmCryptoXChaCha20Poly1305DecryptLinked as LinkedAeadFunction, as: type)
      case .argon2idDeriveKey:
        return try linked(rmCryptoArgon2idDeriveKeyLinked as LinkedArgon2idFunction, as: type)
      case .kmac256Derive:
        return try linked(rmCryptoKmac256DeriveLinked as LinkedKmac256Function, as: type)
      case .ed25519GenerateKeypair:
        return try linked(
          rmCryptoEd25519GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .ed25519GenerateKeypairFromSeed:
        return try linked(
          rmCryptoEd25519GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .ed25519Sign:
        return try linked(rmCryptoEd25519SignLinked as LinkedSignFunction, as: type)
      case .ed25519Verify:
        return try linked(rmCryptoEd25519VerifyLinked as LinkedVerifyFunction, as: type)
      case .p256GenerateKeypair:
        return try linked(
          rmCryptoP256GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .p256GenerateKeypairFromSecretKey:
        return try linked(
          rmCryptoP256GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
      case .p256SignDerPrehash:
        return try linked(rmCryptoP256SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
      case .p256VerifyDerPrehash:
        return try linked(rmCryptoP256VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
      case .p384GenerateKeypair:
        return try linked(
          rmCryptoP384GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .p384GenerateKeypairFromSecretKey:
        return try linked(
          rmCryptoP384GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
      case .p384SignDerPrehash:
        return try linked(rmCryptoP384SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
      case .p384VerifyDerPrehash:
        return try linked(rmCryptoP384VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
      case .p521GenerateKeypair:
        return try linked(
          rmCryptoP521GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .p521GenerateKeypairFromSecretKey:
        return try linked(
          rmCryptoP521GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
      case .p521SignDerPrehash:
        return try linked(rmCryptoP521SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
      case .p521VerifyDerPrehash:
        return try linked(rmCryptoP521VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
      case .bip340SchnorrDerivePublicKey:
        return try linked(
          rmCryptoBip340SchnorrDerivePublicKeyLinked as LinkedBip340SchnorrDerivePublicKeyFunction,
          as: type)
      case .bip340SchnorrSign:
        return try linked(rmCryptoBip340SchnorrSignLinked as LinkedBip340SignFunction, as: type)
      case .bip340SchnorrVerify:
        return try linked(rmCryptoBip340SchnorrVerifyLinked as LinkedVerifyFunction, as: type)
      case .aes128KwWrapKey:
        return try linked(rmCryptoAes128KwWrapKeyLinked as LinkedAesKwFunction, as: type)
      case .aes128KwUnwrapKey:
        return try linked(rmCryptoAes128KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
      case .aes192KwWrapKey:
        return try linked(rmCryptoAes192KwWrapKeyLinked as LinkedAesKwFunction, as: type)
      case .aes192KwUnwrapKey:
        return try linked(rmCryptoAes192KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
      case .aes256KwWrapKey:
        return try linked(rmCryptoAes256KwWrapKeyLinked as LinkedAesKwFunction, as: type)
      case .aes256KwUnwrapKey:
        return try linked(rmCryptoAes256KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
      case .hpkeSealBase:
        return try linked(rmCryptoHpkeSealBaseLinked as LinkedHpkeSealFunction, as: type)
      case .hpkeOpenBase:
        return try linked(rmCryptoHpkeOpenBaseLinked as LinkedHpkeOpenFunction, as: type)
      case .rsaVerifyPkcs1v15:
        return try linked(
          rmCryptoRsaVerifyPkcs1v15Linked as LinkedRsaPkcs1v15VerifyFunction, as: type)
      case .rsaVerifyPss:
        return try linked(rmCryptoRsaVerifyPssLinked as LinkedRsaPssVerifyFunction, as: type)
      case .mlDsa44GenerateKeypair:
        return try linked(
          rmCryptoMlDsa44GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlDsa44GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlDsa44GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlDsa44Sign:
        return try linked(rmCryptoMlDsa44SignLinked as LinkedSignFunction, as: type)
      case .mlDsa44Verify:
        return try linked(rmCryptoMlDsa44VerifyLinked as LinkedVerifyFunction, as: type)
      case .mlDsa65GenerateKeypair:
        return try linked(
          rmCryptoMlDsa65GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlDsa65GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlDsa65GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlDsa65Sign:
        return try linked(rmCryptoMlDsa65SignLinked as LinkedSignFunction, as: type)
      case .mlDsa65Verify:
        return try linked(rmCryptoMlDsa65VerifyLinked as LinkedVerifyFunction, as: type)
      case .mlDsa87GenerateKeypair:
        return try linked(
          rmCryptoMlDsa87GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlDsa87GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlDsa87GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlDsa87Sign:
        return try linked(rmCryptoMlDsa87SignLinked as LinkedSignFunction, as: type)
      case .mlDsa87Verify:
        return try linked(rmCryptoMlDsa87VerifyLinked as LinkedVerifyFunction, as: type)
      case .slhDsaSha2128sGenerateKeypair:
        return try linked(
          rmCryptoSlhDsaSha2128sGenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .slhDsaSha2128sDeriveKeypair:
        return try linked(
          rmCryptoSlhDsaSha2128sDeriveKeypairLinked as LinkedSlhDsaDeriveKeyPairFunction, as: type)
      case .slhDsaSha2128sSign:
        return try linked(rmCryptoSlhDsaSha2128sSignLinked as LinkedSignFunction, as: type)
      case .slhDsaSha2128sVerify:
        return try linked(rmCryptoSlhDsaSha2128sVerifyLinked as LinkedVerifyFunction, as: type)
      case .mlKem512GenerateKeypair:
        return try linked(
          rmCryptoMlKem512GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlKem512GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlKem512GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlKem512Encapsulate:
        return try linked(
          rmCryptoMlKem512EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
      case .mlKem512Decapsulate:
        return try linked(rmCryptoMlKem512DecapsulateLinked as LinkedSignFunction, as: type)
      case .mlKem768GenerateKeypair:
        return try linked(
          rmCryptoMlKem768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlKem768GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlKem768GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlKem768Encapsulate:
        return try linked(
          rmCryptoMlKem768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
      case .mlKem768Decapsulate:
        return try linked(rmCryptoMlKem768DecapsulateLinked as LinkedSignFunction, as: type)
      case .mlKem1024GenerateKeypair:
        return try linked(
          rmCryptoMlKem1024GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .mlKem1024GenerateKeypairFromSeed:
        return try linked(
          rmCryptoMlKem1024GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
      case .mlKem1024Encapsulate:
        return try linked(
          rmCryptoMlKem1024EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
      case .mlKem1024Decapsulate:
        return try linked(rmCryptoMlKem1024DecapsulateLinked as LinkedSignFunction, as: type)
      case .xWing768GenerateKeypair:
        return try linked(
          rmCryptoXWing768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
      case .xWing768GenerateKeypairDerand:
        return try linked(
          rmCryptoXWing768GenerateKeypairDerandLinked as LinkedXWingDeriveKeyPairFunction, as: type)
      case .xWing768Encapsulate:
        return try linked(
          rmCryptoXWing768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
      case .xWing768Decapsulate:
        return try linked(rmCryptoXWing768DecapsulateLinked as LinkedSignFunction, as: type)
      }
    }
  #endif
}
