// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Public/secret keypair returned by generic package facade key generation.
public struct ReallyMeSignatureKeyPair: Sendable, CustomStringConvertible,
  CustomDebugStringConvertible
{
  public let publicKey: [UInt8]
  public let secretKey: [UInt8]

  public init(publicKey: [UInt8], secretKey: [UInt8]) {
    self.publicKey = publicKey
    self.secretKey = secretKey
  }

  public var description: String {
    "ReallyMeSignatureKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
  }

  public var debugDescription: String { description }
}

public struct ReallyMeKemKeyPair: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  public let publicKey: [UInt8]
  public let secretKey: [UInt8]

  public init(publicKey: [UInt8], secretKey: [UInt8]) {
    self.publicKey = publicKey
    self.secretKey = secretKey
  }

  public var description: String {
    "ReallyMeKemKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
  }

  public var debugDescription: String { description }
}

public struct ReallyMeKeyAgreementKeyPair: Sendable, CustomStringConvertible,
  CustomDebugStringConvertible
{
  public let publicKey: [UInt8]
  public let secretKey: [UInt8]

  public init(publicKey: [UInt8], secretKey: [UInt8]) {
    self.publicKey = publicKey
    self.secretKey = secretKey
  }

  public var description: String {
    "ReallyMeKeyAgreementKeyPair(publicKeyLength: \(publicKey.count), secretKey: <redacted>)"
  }

  public var debugDescription: String { description }
}

public struct ReallyMeKemEncapsulation: Sendable, CustomStringConvertible,
  CustomDebugStringConvertible
{
  public let sharedSecret: [UInt8]
  public let ciphertext: [UInt8]

  public init(sharedSecret: [UInt8], ciphertext: [UInt8]) {
    self.sharedSecret = sharedSecret
    self.ciphertext = ciphertext
  }

  public var description: String {
    "ReallyMeKemEncapsulation(sharedSecret: <redacted>, ciphertextLength: \(ciphertext.count))"
  }

  public var debugDescription: String { description }
}

public struct ReallyMeHpkeSealedMessage: Sendable {
  public let encapsulatedKey: [UInt8]
  public let ciphertext: [UInt8]

  public init(encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
  }
}

public enum ReallyMeRustCAbiProviderDiagnostic: Equatable, Sendable {
  case bundledProviderNotLinked
  case bundledProviderLoadFailed
}

/// Provider configuration for the Swift facade.
///
/// Apple-native providers are always available through the package's normal
/// platform APIs. Release SwiftPM packages also ship and link the Rust C ABI
/// provider; local source-tree development can still pass an explicitly loaded
/// dynamic library when testing a freshly built `crypto-ffi`.
public struct ReallyMeCryptoProviders: Sendable {
  public let rustCAbiLibrary: ReallyMeRustCAbiLibrary?
  public let rustCAbiDiagnostic: ReallyMeRustCAbiProviderDiagnostic?

  public init(
    rustCAbiLibrary: ReallyMeRustCAbiLibrary? = nil,
    rustCAbiDiagnostic: ReallyMeRustCAbiProviderDiagnostic? = nil
  ) {
    self.rustCAbiLibrary = rustCAbiLibrary
    self.rustCAbiDiagnostic = rustCAbiDiagnostic
  }

  public static var `default`: ReallyMeCryptoProviders {
    #if REALLYME_CRYPTO_LINKED_FFI
      do {
        return ReallyMeCryptoProviders(
          rustCAbiLibrary: try ReallyMeRustCAbiLibrary.bundledProvider())
      } catch {
        return ReallyMeCryptoProviders(rustCAbiDiagnostic: .bundledProviderLoadFailed)
      }
    #else
      return ReallyMeCryptoProviders(rustCAbiDiagnostic: .bundledProviderNotLinked)
    #endif
  }
}

/// Generic package facade. Algorithm-specific types remain available for
/// callers that want direct provider access; this facade gives consumers a
/// stable typed route and rejects algorithm/operation combinations that the
/// selected method does not define.
public struct ReallyMeCrypto: Sendable {
  public let providers: ReallyMeCryptoProviders

  public init(providers: ReallyMeCryptoProviders = .default) {
    self.providers = providers
  }

  func requireRustCAbiLibrary() throws(ReallyMeCryptoError) -> ReallyMeRustCAbiLibrary {
    guard let library = providers.rustCAbiLibrary else {
      throw ReallyMeCryptoError.providerFailure
    }
    return library
  }
}
