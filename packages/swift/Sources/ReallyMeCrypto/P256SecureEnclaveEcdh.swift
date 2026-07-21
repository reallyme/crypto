// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import Security

public struct ReallyMeKeyAgreementHandleKeyPair: Sendable {
    public let publicKey: [UInt8]
    public let privateKeyHandle: [UInt8]
}

/// P-256 ECDH with the private key held by Secure Enclave / Keychain.
///
/// The byte-oriented ECDH APIs accept raw private keys. This type exists for
/// the different residency model used by applications: private material is
/// generated as a permanent Secure Enclave key and callers receive only a
/// small handle (`SE:` + application tag). JWE/JOSE code can use the handle to
/// derive an ECDH shared secret without exporting the private key.
///
/// ECDH keys deliberately use `.privateKeyUsage` without an interactive
/// user-presence constraint so background receive/decryption flows can derive
/// shared secrets. Secure Enclave residency prevents private-key export but
/// does not imply per-operation user authentication.
public enum ReallyMeP256SecureEnclaveEcdh {
    public static let handlePrefix = Array("SE:".utf8)
    public static let minTagLength = 1
    public static let maxTagLength = 256
    public static let compressedPublicKeyLength = ReallyMeP256Ecdh.compressedPublicKeyLength
    public static let sharedSecretLength = ReallyMeP256Ecdh.sharedSecretLength
    internal static let storageTagPrefix =
        Array("me.really.crypto.secure-enclave.ecdh.v1:".utf8)
    private static let lifecycleLock = NSLock()

    public static func encodePrivateKeyHandle(tag: [UInt8]) throws -> [UInt8] {
        try validateTag(tag)
        return handlePrefix + tag
    }

    public static func decodePrivateKeyHandle(_ privateKeyHandle: [UInt8]) throws -> [UInt8] {
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
        overwriteExisting: Bool = false
    ) throws -> ReallyMeKeyAgreementHandleKeyPair {
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

        let privateKey = try createPrivateKey(tag: tag)
        do {
            let publicKey = try compressedPublicKey(for: privateKey)
            return ReallyMeKeyAgreementHandleKeyPair(
                publicKey: publicKey,
                privateKeyHandle: try encodePrivateKeyHandle(tag: tag)
            )
        } catch let generationError {
            // Key generation is permanent. If any post-generation validation
            // fails, remove the entry so callers never inherit an orphaned key.
            do {
                try deleteKey(tag: tag)
            } catch {
                throw ReallyMeCryptoError.providerFailure
            }
            throw generationError
        }
    }

    public static func derivePublicKey(privateKeyHandle: [UInt8]) throws -> [UInt8] {
        try compressedPublicKey(for: privateKey(for: privateKeyHandle))
    }

    public static func deriveSharedSecret(
        publicKey: [UInt8],
        privateKeyHandle: [UInt8]
    ) throws -> [UInt8] {
        guard publicKey.count == compressedPublicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let privateKey = try privateKey(for: privateKeyHandle)
        let peerPublicKey = try secKeyPublicKey(fromCompressedP256: publicKey)
        var error: Unmanaged<CFError>?
        guard let secret = SecKeyCopyKeyExchangeResult(
            privateKey,
            SecKeyAlgorithm.ecdhKeyExchangeStandard,
            peerPublicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
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

    public static func deleteKey(privateKeyHandle: [UInt8]) throws {
        let tag = try decodePrivateKeyHandle(privateKeyHandle)
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        try deleteKey(tag: tag)
    }

    private static var supportsSecureEnclaveKeyAgreement: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }

    private static func validateTag(_ tag: [UInt8]) throws {
        guard (minTagLength...maxTagLength).contains(tag.count) else {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private static func createPrivateKey(tag: [UInt8]) throws -> SecKey {
        let keychainTag = storageTag(for: tag)
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            throw mapKeychainError(accessError)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(keychainTag),
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw mapKeychainError(error)
        }
        return privateKey
    }

    private static func privateKey(for privateKeyHandle: [UInt8]) throws -> SecKey {
        let tag = try decodePrivateKeyHandle(privateKeyHandle)
        let keychainTag = storageTag(for: tag)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: Data(keychainTag),
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
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

    private static func deleteKey(tag: [UInt8]) throws {
        try validateTag(tag)
        let keychainTag = storageTag(for: tag)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: Data(keychainTag),
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw mapSecurityStatus(status)
        }
    }

    private static func privateKeyExists(tag: [UInt8]) throws -> Bool {
        let keychainTag = storageTag(for: tag)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: Data(keychainTag),
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

    private static func storageTag(for tag: [UInt8]) -> [UInt8] {
        // The Keychain identifier binds the cryptographic purpose even when an
        // application deliberately reuses the same public tag across APIs.
        storageTagPrefix + Array(SHA256.hash(data: Data(tag)))
    }

    private static func compressedPublicKey(for privateKey: SecKey) throws -> [UInt8] {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw ReallyMeCryptoError.providerFailure
        }
        var error: Unmanaged<CFError>?
        guard let publicData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw mapKeychainError(error)
        }
        return try compressedP256PublicKey(fromX963: Array(publicData))
    }

    private static func secKeyPublicKey(fromCompressedP256 publicKey: [UInt8]) throws -> SecKey {
        do {
            let cryptoKitKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: Data(publicKey))
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256,
            ]
            var error: Unmanaged<CFError>?
            guard let secKey = SecKeyCreateWithData(
                Data(cryptoKitKey.x963Representation) as CFData,
                attributes as CFDictionary,
                &error
            ) else {
                throw mapKeychainError(error)
            }
            return secKey
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    private static func compressedP256PublicKey(fromX963 publicKey: [UInt8]) throws -> [UInt8] {
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
        case errSecParam, errSecItemNotFound, errSecDuplicateItem:
            return ReallyMeCryptoError.invalidInput
        default:
            return ReallyMeCryptoError.providerFailure
        }
    }
}
