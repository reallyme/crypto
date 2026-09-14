// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if canImport(Darwin)
  import Darwin
#endif

extension RustCryptoFfi {
  func mlDsa87RoundTrip(message: Data) throws -> Bool {
    var publicKey = [UInt8](repeating: 0, count: 2_592)
    var secretSeed = [UInt8](repeating: 0, count: 32)
    try callKeypair(mlDsa87GenerateKeypair, publicKey: &publicKey, secretKey: &secretSeed)

    var signature = [UInt8](repeating: 0, count: 4_627)
    let signatureLength = signature.count
    let signStatus = try secretSeed.withUnsafeBufferPointer { secretBytes in
      try message.withUnsafeBytes { messageBytes in
        guard
          let secretPointer = secretBytes.baseAddress,
          let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
        else {
          throw RustCryptoFfiError.emptyBuffer
        }
        return try signature.withUnsafeMutableBufferPointer { signatureBytes in
          let signaturePointer = try Self.mutableBaseAddress(signatureBytes)
          return mlDsa87Sign(
            secretPointer,
            secretSeed.count,
            messagePointer,
            message.count,
            signaturePointer,
            signatureLength
          )
        }
      }
    }
    try Self.requireOk(signStatus)

    try verify(
      mlDsa87Verify,
      publicKey: publicKey,
      message: message,
      signature: signature
    )
    return true
  }

  /// Deterministically signs `message` with a committed ML-DSA seed
  /// and returns the raw signature, so the caller can compare it against
  /// the committed known-answer signature byte-for-byte.
  func mlDsa44Sign(secretSeed: [UInt8], message: Data) throws -> Data {
    try mlDsaSign(mlDsa44Sign, secretSeed: secretSeed, message: message, signatureLength: 2_420)
  }

  func mlDsa65Sign(secretSeed: [UInt8], message: Data) throws -> Data {
    try mlDsaSign(mlDsa65Sign, secretSeed: secretSeed, message: message, signatureLength: 3_309)
  }

  func mlDsa87Sign(secretSeed: [UInt8], message: Data) throws -> Data {
    try mlDsaSign(mlDsa87Sign, secretSeed: secretSeed, message: message, signatureLength: 4_627)
  }

  func mlDsaSign(
    _ sign: SignFunction,
    secretSeed: [UInt8],
    message: Data,
    signatureLength: Int
  ) throws -> Data {
    var signature = [UInt8](repeating: 0, count: signatureLength)
    let signatureLength = signature.count
    let status = try secretSeed.withUnsafeBufferPointer { secretBytes in
      try message.withUnsafeBytes { messageBytes in
        guard
          let secretPointer = secretBytes.baseAddress,
          let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress
        else {
          throw RustCryptoFfiError.emptyBuffer
        }
        return try signature.withUnsafeMutableBufferPointer { signatureBytes in
          let signaturePointer = try Self.mutableBaseAddress(signatureBytes)
          return sign(
            secretPointer,
            secretSeed.count,
            messagePointer,
            message.count,
            signaturePointer,
            signatureLength
          )
        }
      }
    }
    try Self.requireOk(status)
    return Data(signature)
  }

  /// Verifies a detached ML-DSA signature. Invalid signatures fail by status.
  func mlDsa44Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
    try verify(mlDsa44Verify, publicKey: publicKey, message: message, signature: signature)
  }

  func mlDsa65Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
    try verify(mlDsa65Verify, publicKey: publicKey, message: message, signature: signature)
  }

  func mlDsa87Verify(publicKey: [UInt8], message: Data, signature: [UInt8]) throws {
    try verify(mlDsa87Verify, publicKey: publicKey, message: message, signature: signature)
  }

  /// Decapsulates a committed ML-KEM ciphertext with the committed
  /// secret seed and returns the resulting shared secret. Used to check
  /// both the valid known-answer secret and the implicit-rejection secret
  /// for a tampered ciphertext.
  func mlKem512Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
    try decapsulateSharedSecret(mlKem512Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
  }

  func mlKem768Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
    try decapsulateSharedSecret(mlKem768Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
  }

  /// ML-KEM-1024 counterpart of `mlKem768Decapsulate`.
  func mlKem1024Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
    try decapsulateSharedSecret(mlKem1024Decapsulate, ciphertext: ciphertext, secretKey: secretKey)
  }

  func decapsulateSharedSecret(
    _ decapsulate: DecapsulateFunction,
    ciphertext: [UInt8],
    secretKey: [UInt8]
  ) throws -> Data {
    var sharedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
    let sharedSecretLength = sharedSecret.count
    let status = try ciphertext.withUnsafeBufferPointer { ciphertextBytes in
      try secretKey.withUnsafeBufferPointer { secretBytes in
        try sharedSecret.withUnsafeMutableBufferPointer { sharedBytes in
          let ciphertextPointer = try Self.baseAddress(ciphertextBytes)
          let secretPointer = try Self.baseAddress(secretBytes)
          let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
          return decapsulate(
            ciphertextPointer,
            ciphertext.count,
            secretPointer,
            secretKey.count,
            sharedPointer,
            sharedSecretLength
          )
        }
      }
    }
    try Self.requireOk(status)
    return Data(sharedSecret)
  }

  func mlKem512RoundTrip() throws -> Bool {
    try mlKemRoundTrip(
      generateKeypair: mlKem512GenerateKeypair,
      encapsulate: mlKem512Encapsulate,
      decapsulate: mlKem512Decapsulate,
      publicKeyLength: 800,
      secretKeyLength: 64,
      ciphertextLength: 768
    )
  }

  func mlKem768RoundTrip() throws -> Bool {
    try mlKemRoundTrip(
      generateKeypair: mlKem768GenerateKeypair,
      encapsulate: mlKem768Encapsulate,
      decapsulate: mlKem768Decapsulate,
      publicKeyLength: 1_184,
      secretKeyLength: 64,
      ciphertextLength: 1_088
    )
  }

  func mlKem1024RoundTrip() throws -> Bool {
    try mlKemRoundTrip(
      generateKeypair: mlKem1024GenerateKeypair,
      encapsulate: mlKem1024Encapsulate,
      decapsulate: mlKem1024Decapsulate,
      publicKeyLength: 1_568,
      secretKeyLength: 64,
      ciphertextLength: 1_568
    )
  }

  func xWing768PublicKey(secretKey: [UInt8]) throws -> Data {
    try derivePublicKey(xWing768DerivePublicKeyFn, secretKey: secretKey, publicKeyLength: 1_216)
  }

  func xWing768EncapsulateDerand(publicKey: [UInt8], seed: [UInt8]) throws -> (Data, Data) {
    try encapsulateDerand(
      xWing768EncapsulateDerandFn,
      publicKey: publicKey,
      seed: seed,
      ciphertextLength: 1_120
    )
  }

  func xWing768Decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> Data {
    try decapsulateSharedSecret(xWing768DecapsulateFn, ciphertext: ciphertext, secretKey: secretKey)
  }

  func derivePublicKey(
    _ function: DerivePublicKeyFunction,
    secretKey: [UInt8],
    publicKeyLength: Int
  ) throws -> Data {
    var publicKey = [UInt8](repeating: 0, count: publicKeyLength)
    let status = try secretKey.withUnsafeBufferPointer { secretBytes in
      try publicKey.withUnsafeMutableBufferPointer { publicBytes in
        let secretPointer = try Self.baseAddress(secretBytes)
        let publicPointer = try Self.mutableBaseAddress(publicBytes)
        return function(secretPointer, secretKey.count, publicPointer, publicKeyLength)
      }
    }
    try Self.requireOk(status)
    return Data(publicKey)
  }

  func encapsulateDerand(
    _ function: EncapsulateDerandFunction,
    publicKey: [UInt8],
    seed: [UInt8],
    ciphertextLength: Int
  ) throws -> (Data, Data) {
    var ciphertext = [UInt8](repeating: 0, count: ciphertextLength)
    var sharedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
    let status = try publicKey.withUnsafeBufferPointer { publicBytes in
      try seed.withUnsafeBufferPointer { seedBytes in
        try ciphertext.withUnsafeMutableBufferPointer { ciphertextBytes in
          try sharedSecret.withUnsafeMutableBufferPointer { sharedBytes in
            let publicPointer = try Self.baseAddress(publicBytes)
            let seedPointer = try Self.baseAddress(seedBytes)
            let ciphertextPointer = try Self.mutableBaseAddress(ciphertextBytes)
            let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
            return function(
              publicPointer,
              publicKey.count,
              seedPointer,
              seed.count,
              ciphertextPointer,
              ciphertextLength,
              sharedPointer,
              Self.sharedSecretLength
            )
          }
        }
      }
    }
    try Self.requireOk(status)
    return (Data(ciphertext), Data(sharedSecret))
  }

  func mlKemRoundTrip(
    generateKeypair: KeypairFunction,
    encapsulate: EncapsulateFunction,
    decapsulate: DecapsulateFunction,
    publicKeyLength: Int,
    secretKeyLength: Int,
    ciphertextLength: Int
  ) throws -> Bool {
    var publicKey = [UInt8](repeating: 0, count: publicKeyLength)
    var secretKey = [UInt8](repeating: 0, count: secretKeyLength)
    try callKeypair(generateKeypair, publicKey: &publicKey, secretKey: &secretKey)

    var ciphertext = [UInt8](repeating: 0, count: ciphertextLength)
    var encapsulatedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
    let encapsulatedSecretLength = encapsulatedSecret.count
    let encapsulateStatus = try publicKey.withUnsafeBufferPointer { publicBytes in
      try ciphertext.withUnsafeMutableBufferPointer { ciphertextBytes in
        try encapsulatedSecret.withUnsafeMutableBufferPointer { secretBytes in
          let publicPointer = try Self.baseAddress(publicBytes)
          let ciphertextPointer = try Self.mutableBaseAddress(ciphertextBytes)
          let secretPointer = try Self.mutableBaseAddress(secretBytes)
          return encapsulate(
            publicPointer,
            publicKey.count,
            ciphertextPointer,
            ciphertextLength,
            secretPointer,
            encapsulatedSecretLength
          )
        }
      }
    }
    try Self.requireOk(encapsulateStatus)

    var decapsulatedSecret = [UInt8](repeating: 0, count: Self.sharedSecretLength)
    let decapsulatedSecretLength = decapsulatedSecret.count
    let decapsulateStatus = try ciphertext.withUnsafeBufferPointer { ciphertextBytes in
      try secretKey.withUnsafeBufferPointer { secretBytes in
        try decapsulatedSecret.withUnsafeMutableBufferPointer { sharedBytes in
          let ciphertextPointer = try Self.baseAddress(ciphertextBytes)
          let secretPointer = try Self.baseAddress(secretBytes)
          let sharedPointer = try Self.mutableBaseAddress(sharedBytes)
          return decapsulate(
            ciphertextPointer,
            ciphertextLength,
            secretPointer,
            secretKeyLength,
            sharedPointer,
            decapsulatedSecretLength
          )
        }
      }
    }
    try Self.requireOk(decapsulateStatus)
    return encapsulatedSecret == decapsulatedSecret
  }

  func callKeypair(
    _ function: KeypairFunction,
    publicKey: inout [UInt8],
    secretKey: inout [UInt8]
  ) throws {
    let publicKeyLength = publicKey.count
    let secretKeyLength = secretKey.count
    let status = try publicKey.withUnsafeMutableBufferPointer { publicBytes in
      try secretKey.withUnsafeMutableBufferPointer { secretBytes in
        let publicPointer = try Self.mutableBaseAddress(publicBytes)
        let secretPointer = try Self.mutableBaseAddress(secretBytes)
        return function(
          publicPointer,
          publicKeyLength,
          secretPointer,
          secretKeyLength
        )
      }
    }
    try Self.requireOk(status)
  }

  func verify(
    _ function: VerifyFunction,
    publicKey: [UInt8],
    message: Data,
    signature: [UInt8]
  ) throws {
    let status = try publicKey.withUnsafeBufferPointer { publicBytes in
      try message.withUnsafeBytes { messageBytes in
        try signature.withUnsafeBufferPointer { signatureBytes in
          guard
            let publicPointer = publicBytes.baseAddress,
            let messagePointer = messageBytes.bindMemory(to: UInt8.self).baseAddress,
            let signaturePointer = signatureBytes.baseAddress
          else {
            throw RustCryptoFfiError.emptyBuffer
          }
          return function(
            publicPointer,
            publicKey.count,
            messagePointer,
            message.count,
            signaturePointer,
            signature.count
          )
        }
      }
    }
    try Self.requireOk(status)
  }

  static func repositoryRoot() throws -> URL {
    var cursor = URL(fileURLWithPath: #filePath)
    while cursor.path != "/" {
      let manifest = cursor.appendingPathComponent("Cargo.toml")
      let ffiCrate =
        cursor
        .appendingPathComponent("crates")
        .appendingPathComponent("ffi")
      if FileManager.default.fileExists(atPath: manifest.path)
        && FileManager.default.fileExists(atPath: ffiCrate.path)
      {
        return cursor
      }
      cursor.deleteLastPathComponent()
    }
    throw RustCryptoFfiError.repositoryRootNotFound
  }

  static func buildLibrary(at repositoryRoot: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    // The X-Wing known-answer test intentionally consumes the deterministic
    // encapsulation entry point. That symbol is excluded from production
    // artifacts and exists only in the conformance-only `test-vectors` lane.
    process.arguments = [
      "cargo", "build", "-p", "crypto-ffi", "--features", "test-vectors",
    ]
    process.currentDirectoryURL = repositoryRoot

    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
      throw RustCryptoFfiError.cargoBuildFailed
    }
  }

  static func libraryURL(in repositoryRoot: URL) throws -> URL {
    #if os(macOS)
      return
        repositoryRoot
        .appendingPathComponent("target")
        .appendingPathComponent("debug")
        .appendingPathComponent("libcrypto_ffi.dylib")
    #elseif os(Linux)
      return
        repositoryRoot
        .appendingPathComponent("target")
        .appendingPathComponent("debug")
        .appendingPathComponent("libcrypto_ffi.so")
    #else
      throw RustCryptoFfiError.unsupportedPlatform
    #endif
  }

  static func loadSymbol<T>(
    _ name: String,
    from handle: UnsafeMutableRawPointer
  ) throws -> T {
    guard let symbol = dlsym(handle, name) else {
      throw RustCryptoFfiError.symbolNotFound
    }
    return unsafeBitCast(symbol, to: T.self)
  }

  static func requireOk(_ status: Int32) throws {
    guard status == ok else {
      throw RustCryptoFfiError.callFailed
    }
  }

  static func baseAddress(
    _ buffer: UnsafeBufferPointer<UInt8>
  ) throws -> UnsafePointer<UInt8> {
    guard let baseAddress = buffer.baseAddress else {
      throw RustCryptoFfiError.emptyBuffer
    }
    return baseAddress
  }

  static func mutableBaseAddress(
    _ buffer: UnsafeMutableBufferPointer<UInt8>
  ) throws -> UnsafeMutablePointer<UInt8> {
    guard let baseAddress = buffer.baseAddress else {
      throw RustCryptoFfiError.emptyBuffer
    }
    return baseAddress
  }
}
