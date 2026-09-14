// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import LocalAuthentication
import Security

public struct ReallyMeKeyAgreementHandleKeyPair: Sendable {
  public let publicKey: [UInt8]
  public let privateKeyHandle: [UInt8]
}

/// Installation-local reference to an existing or newly generated Secure Enclave key.
///
/// The reference is deliberately not `Codable`, printable, or a private-key handle. It lets a
/// higher-level protocol retain its established Keychain application-tag namespace while
/// ReallyMe Crypto remains the sole owner of Security.framework key creation and use.
public struct ReallyMeP256SecureEnclaveEcdhKeyReference: Sendable {
  public static let minimumApplicationTagLength = 1
  public static let maximumApplicationTagLength = 512

  fileprivate let applicationTag: [UInt8]

  public init(applicationTag: [UInt8]) throws(ReallyMeCryptoError) {
    guard
      (Self.minimumApplicationTagLength...Self.maximumApplicationTagLength).contains(
        applicationTag.count)
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    self.applicationTag = applicationTag
  }
}

/// Closed Secure Enclave access profiles for non-exportable P-256 ECDH keys.
///
/// Protocol owners choose the profile; ReallyMe Crypto maps it to one exact
/// Security.framework construction so SDKs do not reproduce key policy or ECDH.
public enum ReallyMeSecureEnclaveEcdhAccessPolicy: Sendable {
  /// Background-capable key use while the device is unlocked.
  case backgroundWhenUnlocked
  /// Current-biometric authorization for every operation, invalidated when
  /// biometric enrollment changes, with a configured device passcode required.
  case biometryCurrentSetWhenPasscodeSet

  fileprivate var accessibility: CFString {
    switch self {
    case .backgroundWhenUnlocked:
      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case .biometryCurrentSetWhenPasscodeSet:
      return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    }
  }

  fileprivate var accessControlFlags: SecAccessControlCreateFlags {
    switch self {
    case .backgroundWhenUnlocked:
      return [.privateKeyUsage]
    case .biometryCurrentSetWhenPasscodeSet:
      return [.privateKeyUsage, .biometryCurrentSet]
    }
  }
}

/// P-256 ECDH with the private key held by Secure Enclave / Keychain.
///
/// The byte-oriented ECDH APIs accept raw private keys. This type exists for
/// the different residency model used by applications: private material is
/// generated as a permanent Secure Enclave key and callers receive only a
/// small handle (`SE:` + application tag). JWE/JOSE code can use the handle to
/// derive an ECDH shared secret without exporting the private key.
///
/// The default profile supports background receive/decryption while unlocked.
/// Protocols that require an irrecoverable, explicitly local authority select
/// the passcode-and-current-biometric profile and provide the authenticated
/// `LAContext` for each ECDH operation. Secure Enclave residency alone never
/// implies user authentication.
public enum ReallyMeP256SecureEnclaveEcdh {
  public static let handlePrefix = Array("SE:".utf8)
  public static let minTagLength = 1
  public static let maxTagLength = 256
  public static let compressedPublicKeyLength = ReallyMeP256Ecdh.compressedPublicKeyLength
  public static let sharedSecretLength = ReallyMeP256Ecdh.sharedSecretLength
  internal static let storageTagPrefix =
    Array("me.really.crypto.secure-enclave.ecdh.v1:".utf8)
  private static let lifecycleLock = NSLock()

  public static func encodePrivateKeyHandle(tag: [UInt8]) throws(ReallyMeCryptoError) -> [UInt8] {
    try validateTag(tag)
    return handlePrefix + tag
  }

  public static func decodePrivateKeyHandle(_ privateKeyHandle: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    guard privateKeyHandle.count > handlePrefix.count,
      privateKeyHandle.starts(with: handlePrefix)
    else {
      throw ReallyMeCryptoError.invalidInput
    }
    let tag = Array(privateKeyHandle.dropFirst(handlePrefix.count))
    try validateTag(tag)
    return tag
  }

  public static func generateKeyPair(
    tag: [UInt8],
    accessPolicy: ReallyMeSecureEnclaveEcdhAccessPolicy = .backgroundWhenUnlocked,
    overwriteExisting: Bool = false
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementHandleKeyPair {
    try validateTag(tag)
    guard supportsSecureEnclaveKeyAgreement else {
      throw ReallyMeCryptoError.unsupportedPlatform
    }
    lifecycleLock.lock()
    defer { lifecycleLock.unlock() }
    if overwriteExisting {
      try deleteKey(tag: tag)
    } else if try privateKeyExists(tag: tag) {
      throw ReallyMeCryptoError.invalidInput
    }
    let publicKey = try generateKeyLocked(
      applicationTag: storageTag(for: tag),
      accessPolicy: accessPolicy
    )
    return ReallyMeKeyAgreementHandleKeyPair(
      publicKey: publicKey,
      privateKeyHandle: try encodePrivateKeyHandle(tag: tag)
    )
  }

  /// Generates a key under a caller-owned, installation-local application tag.
  ///
  /// This API exists for protocol adapters that already persisted opaque local references before
  /// delegating platform cryptography to ReallyMe Crypto. Only the public key leaves the provider.
  public static func generateKey(
    reference: ReallyMeP256SecureEnclaveEcdhKeyReference,
    accessPolicy: ReallyMeSecureEnclaveEcdhAccessPolicy = .backgroundWhenUnlocked,
    overwriteExisting: Bool = false
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    guard supportsSecureEnclaveKeyAgreement else {
      throw ReallyMeCryptoError.unsupportedPlatform
    }
    lifecycleLock.lock()
    defer { lifecycleLock.unlock() }
    if overwriteExisting {
      try deleteKey(applicationTag: reference.applicationTag)
    } else if try privateKeyExists(applicationTag: reference.applicationTag) {
      throw ReallyMeCryptoError.invalidInput
    }

    return try generateKeyLocked(
      applicationTag: reference.applicationTag,
      accessPolicy: accessPolicy
    )
  }

  private static func generateKeyLocked(
    applicationTag: [UInt8],
    accessPolicy: ReallyMeSecureEnclaveEcdhAccessPolicy
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    let privateKey = try createPrivateKey(
      applicationTag: applicationTag,
      accessPolicy: accessPolicy
    )
    do {
      return try compressedPublicKey(for: privateKey)
    } catch let generationError {
      // Key generation is permanent. If any post-generation validation
      // fails, remove the entry so callers never inherit an orphaned key.
      do {
        try deleteKey(applicationTag: applicationTag)
      } catch {
        throw ReallyMeCryptoError.providerFailure
      }
      throw generationError
    }
  }

  public static func derivePublicKey(privateKeyHandle: [UInt8]) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    let tag = try decodePrivateKeyHandle(privateKeyHandle)
    let reference = try ReallyMeP256SecureEnclaveEcdhKeyReference(
      applicationTag: storageTag(for: tag)
    )
    return try derivePublicKey(reference: reference)
  }

  public static func derivePublicKey(
    reference: ReallyMeP256SecureEnclaveEcdhKeyReference
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    try compressedPublicKey(
      for: privateKey(applicationTag: reference.applicationTag)
    )
  }

  /// Reports whether the local reference resolves without returning or using the private key.
  public static func keyExists(
    reference: ReallyMeP256SecureEnclaveEcdhKeyReference
  ) throws(ReallyMeCryptoError) -> Bool {
    try privateKeyExists(applicationTag: reference.applicationTag)
  }

  public static func deriveSharedSecret(
    publicKey: [UInt8],
    privateKeyHandle: [UInt8],
    authenticationContext: LAContext? = nil
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    let tag = try decodePrivateKeyHandle(privateKeyHandle)
    let reference = try ReallyMeP256SecureEnclaveEcdhKeyReference(
      applicationTag: storageTag(for: tag)
    )
    return try deriveSharedSecret(
      publicKey: publicKey,
      reference: reference,
      authenticationContext: authenticationContext
    )
  }

  public static func deriveSharedSecret(
    publicKey: [UInt8],
    reference: ReallyMeP256SecureEnclaveEcdhKeyReference,
    authenticationContext: LAContext? = nil
  ) throws(ReallyMeCryptoError) -> [UInt8] {
    guard publicKey.count == compressedPublicKeyLength else {
      throw ReallyMeCryptoError.invalidInput
    }
    let privateKey = try privateKey(
      applicationTag: reference.applicationTag,
      authenticationContext: authenticationContext
    )
    let peerPublicKey = try secKeyPublicKey(fromCompressedP256: publicKey)
    var error: Unmanaged<CFError>?
    guard
      let secret = SecKeyCopyKeyExchangeResult(
        privateKey,
        SecKeyAlgorithm.ecdhKeyExchangeStandard,
        peerPublicKey,
        [:] as CFDictionary,
        &error
      ) as Data?
    else {
      throw mapKeychainError(error)
    }
    // Security.framework owns the transient `Data`; this wrapper clears the
    // mutable Swift copy it creates before any validation error return.
    var bytes = Array(secret)
    guard bytes.count == sharedSecretLength else {
      ReallyMeCryptoMemory.bestEffortClear(&bytes)
      throw ReallyMeCryptoError.providerFailure
    }
    return bytes
  }

  public static func deleteKey(privateKeyHandle: [UInt8]) throws(ReallyMeCryptoError) {
    let tag = try decodePrivateKeyHandle(privateKeyHandle)
    let reference = try ReallyMeP256SecureEnclaveEcdhKeyReference(
      applicationTag: storageTag(for: tag)
    )
    try deleteKey(reference: reference)
  }

  public static func deleteKey(
    reference: ReallyMeP256SecureEnclaveEcdhKeyReference
  ) throws(ReallyMeCryptoError) {
    lifecycleLock.lock()
    defer { lifecycleLock.unlock() }
    try deleteKey(applicationTag: reference.applicationTag)
  }

  private static var supportsSecureEnclaveKeyAgreement: Bool {
    #if targetEnvironment(simulator)
      return false
    #else
      return true
    #endif
  }

  private static func validateTag(_ tag: [UInt8]) throws(ReallyMeCryptoError) {
    guard (minTagLength...maxTagLength).contains(tag.count) else {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  private static func createPrivateKey(
    applicationTag: [UInt8],
    accessPolicy: ReallyMeSecureEnclaveEcdhAccessPolicy
  ) throws(ReallyMeCryptoError) -> SecKey {
    var accessError: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        nil,
        accessPolicy.accessibility,
        accessPolicy.accessControlFlags,
        &accessError
      )
    else {
      throw mapKeychainError(accessError)
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: Data(applicationTag),
        kSecAttrAccessControl as String: access,
      ],
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw mapKeychainError(error)
    }
    return privateKey
  }

  private static func privateKey(
    applicationTag: [UInt8],
    authenticationContext: LAContext? = nil
  ) throws(ReallyMeCryptoError) -> SecKey {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrApplicationTag as String: Data(applicationTag),
      kSecReturnRef as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    if let authenticationContext {
      query[kSecUseAuthenticationContext as String] = authenticationContext
    }
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item else {
      if status == errSecItemNotFound {
        throw ReallyMeCryptoError.invalidInput
      }
      throw mapSecurityStatus(status)
    }
    guard CFGetTypeID(key) == SecKeyGetTypeID() else {
      throw ReallyMeCryptoError.providerFailure
    }
    // Security.framework returns a retained CoreFoundation object through a
    // CFTypeRef slot. The type ID check above is the fail-closed validation
    // boundary; this bridge preserves ownership without using a trapping
    // Swift forced cast.
    let opaque = Unmanaged.passUnretained(key).toOpaque()
    return Unmanaged<SecKey>.fromOpaque(opaque).takeUnretainedValue()
  }

  private static func deleteKey(applicationTag: [UInt8]) throws(ReallyMeCryptoError) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrApplicationTag as String: Data(applicationTag),
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw mapSecurityStatus(status)
    }
  }

  private static func deleteKey(tag: [UInt8]) throws(ReallyMeCryptoError) {
    try validateTag(tag)
    try deleteKey(applicationTag: storageTag(for: tag))
  }

  private static func privateKeyExists(applicationTag: [UInt8]) throws(ReallyMeCryptoError) -> Bool
  {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecAttrApplicationTag as String: Data(applicationTag),
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    if status == errSecSuccess {
      return true
    }
    if status == errSecItemNotFound {
      return false
    }
    throw mapSecurityStatus(status)
  }

  private static func privateKeyExists(tag: [UInt8]) throws(ReallyMeCryptoError) -> Bool {
    try validateTag(tag)
    return try privateKeyExists(applicationTag: storageTag(for: tag))
  }

  private static func storageTag(for tag: [UInt8]) -> [UInt8] {
    // The Keychain identifier binds the cryptographic purpose even when an
    // application deliberately reuses the same public tag across APIs.
    storageTagPrefix + Array(SHA256.hash(data: Data(tag)))
  }

  private static func compressedPublicKey(for privateKey: SecKey) throws(ReallyMeCryptoError)
    -> [UInt8]
  {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw ReallyMeCryptoError.providerFailure
    }
    var error: Unmanaged<CFError>?
    guard let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw mapKeychainError(error)
    }
    return try compressedP256PublicKey(fromX963: Array(publicData))
  }

  private static func secKeyPublicKey(fromCompressedP256 publicKey: [UInt8])
    throws(ReallyMeCryptoError) -> SecKey
  {
    do {
      let cryptoKitKey = try P256.KeyAgreement.PublicKey(
        compressedRepresentation: Data(publicKey))
      let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
      ]
      var error: Unmanaged<CFError>?
      guard
        let secKey = SecKeyCreateWithData(
          Data(cryptoKitKey.x963Representation) as CFData,
          attributes as CFDictionary,
          &error
        )
      else {
        throw mapKeychainError(error)
      }
      return secKey
    } catch let error as ReallyMeCryptoError {
      throw error
    } catch {
      throw ReallyMeCryptoError.invalidInput
    }
  }

  private static func compressedP256PublicKey(fromX963 publicKey: [UInt8])
    throws(ReallyMeCryptoError) -> [UInt8]
  {
    guard publicKey.count == 65, publicKey.first == 0x04 else {
      throw ReallyMeCryptoError.providerFailure
    }
    let x = publicKey[1...32]
    let yLastByte = publicKey[64]
    let prefix: UInt8 = (yLastByte & 1) == 0 ? 0x02 : 0x03
    return [prefix] + Array(x)
  }

  private static func mapKeychainError(_ error: Unmanaged<CFError>?) -> ReallyMeCryptoError {
    guard let error else {
      return ReallyMeCryptoError.providerFailure
    }
    let cfError = error.takeRetainedValue()
    if CFErrorGetDomain(cfError) as String == NSOSStatusErrorDomain,
      let status = OSStatus(exactly: CFErrorGetCode(cfError))
    {
      return mapSecurityStatus(status)
    }
    return ReallyMeCryptoError.providerFailure
  }

  private static func mapSecurityStatus(_ status: OSStatus) -> ReallyMeCryptoError {
    switch status {
    case errSecUnimplemented:
      return ReallyMeCryptoError.unsupportedPlatform
    case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
      return ReallyMeCryptoError.authenticationFailed
    case errSecParam, errSecItemNotFound, errSecDuplicateItem:
      return ReallyMeCryptoError.invalidInput
    default:
      return ReallyMeCryptoError.providerFailure
    }
  }
}
