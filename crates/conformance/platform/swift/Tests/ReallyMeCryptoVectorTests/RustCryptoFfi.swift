// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#endif

typealias RustHashFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias AesKwFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<Int>
  ) -> Int32

typealias Pbkdf2Function =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UInt32,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias KmacFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias KeypairFunction =
  @convention(c) (
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias DerivePublicKeyFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias SignFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias VerifyFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int
  ) -> Int32

typealias EncapsulateFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias EncapsulateDerandFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

typealias DecapsulateFunction =
  @convention(c) (
    UnsafePointer<UInt8>,
    Int,
    UnsafePointer<UInt8>,
    Int,
    UnsafeMutablePointer<UInt8>,
    Int
  ) -> Int32

enum RustCryptoFfiError: Error {
  case repositoryRootNotFound
  case unsupportedPlatform
  case dynamicLibraryNotFound
  case dynamicLibraryLoadFailed
  case symbolNotFound
  case cargoBuildFailed
  case emptyBuffer
  case callFailed
  case invalidVerificationResult
}

final class RustCryptoFfi {
  static let ok: Int32 = 0
  static let sharedSecretLength = 32

  let handle: UnsafeMutableRawPointer
  let sha3_224: RustHashFunction
  let sha3_256: RustHashFunction
  let sha3_384: RustHashFunction
  let sha3_512: RustHashFunction
  let aes128KwWrapKey: AesKwFunction
  let aes128KwUnwrapKey: AesKwFunction
  let aes192KwWrapKey: AesKwFunction
  let aes192KwUnwrapKey: AesKwFunction
  let aes256KwWrapKey: AesKwFunction
  let aes256KwUnwrapKey: AesKwFunction
  let pbkdf2HmacSha256DeriveKey: Pbkdf2Function
  let pbkdf2HmacSha512DeriveKey: Pbkdf2Function
  let kmac256DeriveKey: KmacFunction
  let mlDsa44GenerateKeypair: KeypairFunction
  let mlDsa44Sign: SignFunction
  let mlDsa44Verify: VerifyFunction
  let mlDsa65GenerateKeypair: KeypairFunction
  let mlDsa65Sign: SignFunction
  let mlDsa65Verify: VerifyFunction
  let mlDsa87GenerateKeypair: KeypairFunction
  let mlDsa87Sign: SignFunction
  let mlDsa87Verify: VerifyFunction
  let mlKem512GenerateKeypair: KeypairFunction
  let mlKem512Encapsulate: EncapsulateFunction
  let mlKem512Decapsulate: DecapsulateFunction
  let mlKem768GenerateKeypair: KeypairFunction
  let mlKem768Encapsulate: EncapsulateFunction
  let mlKem768Decapsulate: DecapsulateFunction
  let mlKem1024GenerateKeypair: KeypairFunction
  let mlKem1024Encapsulate: EncapsulateFunction
  let mlKem1024Decapsulate: DecapsulateFunction
  let xWing768DerivePublicKeyFn: DerivePublicKeyFunction
  let xWing768EncapsulateDerandFn: EncapsulateDerandFunction
  let xWing768DecapsulateFn: DecapsulateFunction

  init() throws {
    let repositoryRoot = try Self.repositoryRoot()
    try Self.buildLibrary(at: repositoryRoot)

    let library = try Self.libraryURL(in: repositoryRoot)
    guard FileManager.default.fileExists(atPath: library.path) else {
      throw RustCryptoFfiError.dynamicLibraryNotFound
    }
    guard let loadedHandle = dlopen(library.path, RTLD_NOW | RTLD_LOCAL) else {
      throw RustCryptoFfiError.dynamicLibraryLoadFailed
    }

    handle = loadedHandle
    sha3_224 = try Self.loadSymbol("rm_crypto_sha3_224_digest", from: loadedHandle)
    sha3_256 = try Self.loadSymbol("rm_crypto_sha3_256_digest", from: loadedHandle)
    sha3_384 = try Self.loadSymbol("rm_crypto_sha3_384_digest", from: loadedHandle)
    sha3_512 = try Self.loadSymbol("rm_crypto_sha3_512_digest", from: loadedHandle)
    aes128KwWrapKey = try Self.loadSymbol("rm_crypto_aes128_kw_wrap_key", from: loadedHandle)
    aes128KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes128_kw_unwrap_key", from: loadedHandle)
    aes192KwWrapKey = try Self.loadSymbol("rm_crypto_aes192_kw_wrap_key", from: loadedHandle)
    aes192KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes192_kw_unwrap_key", from: loadedHandle)
    aes256KwWrapKey = try Self.loadSymbol("rm_crypto_aes256_kw_wrap_key", from: loadedHandle)
    aes256KwUnwrapKey = try Self.loadSymbol("rm_crypto_aes256_kw_unwrap_key", from: loadedHandle)
    pbkdf2HmacSha256DeriveKey = try Self.loadSymbol(
      "rm_crypto_pbkdf2_hmac_sha256_derive_key", from: loadedHandle)
    pbkdf2HmacSha512DeriveKey = try Self.loadSymbol(
      "rm_crypto_pbkdf2_hmac_sha512_derive_key", from: loadedHandle)
    kmac256DeriveKey = try Self.loadSymbol("rm_crypto_kmac256_derive", from: loadedHandle)
    mlDsa44GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_dsa_44_generate_keypair", from: loadedHandle)
    mlDsa44Sign = try Self.loadSymbol("rm_crypto_ml_dsa_44_sign", from: loadedHandle)
    mlDsa44Verify = try Self.loadSymbol("rm_crypto_ml_dsa_44_verify", from: loadedHandle)
    mlDsa65GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_dsa_65_generate_keypair", from: loadedHandle)
    mlDsa65Sign = try Self.loadSymbol("rm_crypto_ml_dsa_65_sign", from: loadedHandle)
    mlDsa65Verify = try Self.loadSymbol("rm_crypto_ml_dsa_65_verify", from: loadedHandle)
    mlDsa87GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_dsa_87_generate_keypair", from: loadedHandle)
    mlDsa87Sign = try Self.loadSymbol("rm_crypto_ml_dsa_87_sign", from: loadedHandle)
    mlDsa87Verify = try Self.loadSymbol("rm_crypto_ml_dsa_87_verify", from: loadedHandle)
    mlKem512GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_kem_512_generate_keypair", from: loadedHandle)
    mlKem512Encapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_512_encapsulate", from: loadedHandle)
    mlKem512Decapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_512_decapsulate", from: loadedHandle)
    mlKem768GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_kem_768_generate_keypair", from: loadedHandle)
    mlKem768Encapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_768_encapsulate", from: loadedHandle)
    mlKem768Decapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_768_decapsulate", from: loadedHandle)
    mlKem1024GenerateKeypair = try Self.loadSymbol(
      "rm_crypto_ml_kem_1024_generate_keypair", from: loadedHandle)
    mlKem1024Encapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_1024_encapsulate", from: loadedHandle)
    mlKem1024Decapsulate = try Self.loadSymbol(
      "rm_crypto_ml_kem_1024_decapsulate", from: loadedHandle)
    xWing768DerivePublicKeyFn = try Self.loadSymbol(
      "rm_crypto_x_wing_768_generate_keypair_derand", from: loadedHandle)
    xWing768EncapsulateDerandFn = try Self.loadSymbol(
      "rm_crypto_x_wing_768_encapsulate_derand", from: loadedHandle)
    xWing768DecapsulateFn = try Self.loadSymbol(
      "rm_crypto_x_wing_768_decapsulate", from: loadedHandle)
  }

  deinit {
    dlclose(handle)
  }

  func sha3Digest(_ message: Data) throws -> Data {
    try callHash(sha3_256, message: message, digestLength: 32)
  }

  func sha3_224Digest(_ message: Data) throws -> Data {
    try callHash(sha3_224, message: message, digestLength: 28)
  }

  func sha3_384Digest(_ message: Data) throws -> Data {
    try callHash(sha3_384, message: message, digestLength: 48)
  }

  func sha3_512Digest(_ message: Data) throws -> Data {
    try callHash(sha3_512, message: message, digestLength: 64)
  }

  func callHash(_ function: RustHashFunction, message: Data, digestLength: Int) throws -> Data {
    var digest = [UInt8](repeating: 0, count: digestLength)
    let outputLength = digest.count
    let status = try message.withUnsafeBytes { messageBytes in
      guard let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress else {
        throw RustCryptoFfiError.emptyBuffer
      }
      return try digest.withUnsafeMutableBufferPointer { digestBytes in
        let digestPointer = try Self.mutableBaseAddress(digestBytes)
        return function(
          messagePointer,
          message.count,
          digestPointer,
          outputLength
        )
      }
    }
    try Self.requireOk(status)
    return Data(digest)
  }

  func aes128KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
    try aesKwWrap(aes128KwWrapKey, kek: kek, keyData: keyData)
  }

  func aes128KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
    try aesKwUnwrap(aes128KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
  }

  func aes192KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
    try aesKwWrap(aes192KwWrapKey, kek: kek, keyData: keyData)
  }

  func aes192KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
    try aesKwUnwrap(aes192KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
  }

  func aes256KwWrap(kek: [UInt8], keyData: [UInt8]) throws -> Data {
    try aesKwWrap(aes256KwWrapKey, kek: kek, keyData: keyData)
  }

  func aes256KwUnwrap(kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
    try aesKwUnwrap(aes256KwUnwrapKey, kek: kek, wrappedKey: wrappedKey)
  }

  func aesKwWrap(_ function: AesKwFunction, kek: [UInt8], keyData: [UInt8]) throws -> Data {
    let outputLengthResult = keyData.count.addingReportingOverflow(8)
    guard !outputLengthResult.overflow else {
      throw RustCryptoFfiError.callFailed
    }
    let outputLength = outputLengthResult.partialValue
    return try callAesKw(function, kek: kek, input: keyData, outputLength: outputLength)
  }

  func aesKwUnwrap(_ function: AesKwFunction, kek: [UInt8], wrappedKey: [UInt8]) throws -> Data {
    guard wrappedKey.count >= 8 else {
      throw RustCryptoFfiError.callFailed
    }
    return try callAesKw(function, kek: kek, input: wrappedKey, outputLength: wrappedKey.count - 8)
  }

  func callAesKw(
    _ function: AesKwFunction,
    kek: [UInt8],
    input: [UInt8],
    outputLength: Int
  ) throws -> Data {
    var output = [UInt8](repeating: 0, count: outputLength)
    var writtenLength = 0
    let status = try kek.withUnsafeBufferPointer { kekBytes in
      try input.withUnsafeBufferPointer { inputBytes in
        try output.withUnsafeMutableBufferPointer { outputBytes in
          let kekPointer = try Self.baseAddress(kekBytes)
          let inputPointer = try Self.baseAddress(inputBytes)
          let outputPointer = try Self.mutableBaseAddress(outputBytes)
          return function(
            kekPointer,
            kek.count,
            inputPointer,
            input.count,
            outputPointer,
            outputLength,
            &writtenLength
          )
        }
      }
    }
    try Self.requireOk(status)
    guard writtenLength <= output.count else {
      throw RustCryptoFfiError.callFailed
    }
    return Data(output.prefix(writtenLength))
  }

  func pbkdf2HmacSha256(password: [UInt8], salt: [UInt8], iterations: UInt32, outputLength: Int)
    throws -> Data
  {
    try callPbkdf2(
      pbkdf2HmacSha256DeriveKey,
      password: password,
      salt: salt,
      iterations: iterations,
      outputLength: outputLength
    )
  }

  func pbkdf2HmacSha512(password: [UInt8], salt: [UInt8], iterations: UInt32, outputLength: Int)
    throws -> Data
  {
    try callPbkdf2(
      pbkdf2HmacSha512DeriveKey,
      password: password,
      salt: salt,
      iterations: iterations,
      outputLength: outputLength
    )
  }

  func callPbkdf2(
    _ function: Pbkdf2Function,
    password: [UInt8],
    salt: [UInt8],
    iterations: UInt32,
    outputLength: Int
  ) throws -> Data {
    guard outputLength > 0 else {
      throw RustCryptoFfiError.callFailed
    }
    var output = [UInt8](repeating: 0, count: outputLength)
    let status = try password.withUnsafeBufferPointer { passwordBytes in
      try salt.withUnsafeBufferPointer { saltBytes in
        try output.withUnsafeMutableBufferPointer { outputBytes in
          let passwordPointer = try Self.baseAddress(passwordBytes)
          let saltPointer = try Self.baseAddress(saltBytes)
          let outputPointer = try Self.mutableBaseAddress(outputBytes)
          return function(
            passwordPointer,
            password.count,
            saltPointer,
            salt.count,
            iterations,
            outputPointer,
            outputLength
          )
        }
      }
    }
    try Self.requireOk(status)
    return Data(output)
  }

  func kmac256(key: [UInt8], context: [UInt8], customization: [UInt8], outputLength: Int) throws
    -> Data
  {
    guard outputLength > 0 else {
      throw RustCryptoFfiError.callFailed
    }
    var output = [UInt8](repeating: 0, count: outputLength)
    let status = try key.withUnsafeBufferPointer { keyBytes in
      try context.withUnsafeBufferPointer { contextBytes in
        try customization.withUnsafeBufferPointer { customizationBytes in
          try output.withUnsafeMutableBufferPointer { outputBytes in
            let keyPointer = try Self.baseAddress(keyBytes)
            let contextPointer = try Self.baseAddress(contextBytes)
            let customizationPointer = try Self.baseAddress(customizationBytes)
            let outputPointer = try Self.mutableBaseAddress(outputBytes)
            return kmac256DeriveKey(
              keyPointer,
              key.count,
              contextPointer,
              context.count,
              customizationPointer,
              customization.count,
              outputPointer,
              outputLength
            )
          }
        }
      }
    }
    try Self.requireOk(status)
    return Data(output)
  }

}
