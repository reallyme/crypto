// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import LocalAuthentication
import Security

public struct ReallyMeSignatureHandleKeyPair: Sendable {
    public let publicKey: [UInt8]
    public let privateKeyHandle: [UInt8]
}

/// Keychain access policy for Secure Enclave private-key operations.
///
/// The raw deterministic ECDSA facade uses Rust so signatures can match the
/// cross-lane vector contract byte-for-byte. This policy is for a different
/// security boundary: a platform-held P-256 signing key whose private material
/// is not exported to Swift or Rust.
public enum ReallyMeSecureEnclaveAccessControl: Sendable {
    /// Allow private-key use while the device is unlocked.
    case privateKeyUsage
    /// Require user presence. On Apple platforms this may be satisfied by
    /// biometrics or the device passcode, depending on device policy.
    case userPresence
    /// Require any enrolled biometric.
    case biometryAny
    /// Require the current biometric enrollment set.
    case biometryCurrentSet

    fileprivate var secAccessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .privateKeyUsage:
            return [.privateKeyUsage]
        case .userPresence:
            return [.privateKeyUsage, .userPresence]
        case .biometryAny:
            return [.privateKeyUsage, .biometryAny]
        case .biometryCurrentSet:
            return [.privateKeyUsage, .biometryCurrentSet]
        }
    }
}

/// P-256 ECDSA with the private key held by Secure Enclave / Keychain.
///
/// This API is intentionally handle-backed and separate from
/// `ReallyMeRustCAbiP256Ecdsa`. Secure Enclave signatures are produced by
/// Security.framework using a non-exportable key and the caller-selected access
/// control policy; they are not expected to match the deterministic Rust ECDSA
/// test vectors byte-for-byte.
public enum ReallyMeP256SecureEnclaveEcdsa {
    public static let handlePrefix = Array("SES:".utf8)
    public static let minTagLength = 1
    public static let maxTagLength = 256
    public static let compressedPublicKeyLength = 33
    public static let signatureDerMaxLength = 72
    internal static let storageTagPrefix =
        Array("me.really.crypto.secure-enclave.signing.v1:".utf8)
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
        accessControl: ReallyMeSecureEnclaveAccessControl = .userPresence,
        overwriteExisting: Bool = false
    ) throws -> ReallyMeSignatureHandleKeyPair {
        try validateTag(tag)
        guard supportsSecureEnclaveSigning else {
            throw ReallyMeCryptoError.unsupportedPlatform
        }
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        if overwriteExisting {
            try deleteKey(tag: tag)
        } else if try privateKeyExists(tag: tag) {
            throw ReallyMeCryptoError.invalidInput
        }

        let privateKey = try createPrivateKey(tag: tag, accessControl: accessControl)
        do {
            let publicKey = try compressedPublicKey(for: privateKey)
            return ReallyMeSignatureHandleKeyPair(
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
        try compressedPublicKey(for: privateKey(for: privateKeyHandle, authenticationPrompt: nil))
    }

    public static func sign(
        message: [UInt8],
        privateKeyHandle: [UInt8],
        authenticationPrompt: String? = nil
    ) throws -> [UInt8] {
        let privateKey = try privateKey(
            for: privateKeyHandle,
            authenticationPrompt: authenticationPrompt
        )
        guard SecKeyIsAlgorithmSupported(
            privateKey,
            .sign,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        ) else {
            throw ReallyMeCryptoError.unsupportedPlatform
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
            Data(message) as CFData,
            &error
        ) as Data? else {
            throw mapKeychainError(error)
        }
        let bytes = Array(signature)
        guard !bytes.isEmpty, bytes.count <= signatureDerMaxLength else {
            throw ReallyMeCryptoError.providerFailure
        }
        return bytes
    }

    public static func verify(
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        guard publicKey.count == compressedPublicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        do {
            guard !signature.isEmpty, signature.count <= signatureDerMaxLength else {
                throw ReallyMeCryptoError.invalidInput
            }
            _ = try P256.Signing.ECDSASignature(derRepresentation: Data(signature))
            let verifyingKey = try secKeyPublicKey(fromCompressedP256: publicKey)
            guard SecKeyIsAlgorithmSupported(
                verifyingKey,
                .verify,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            ) else {
                throw ReallyMeCryptoError.unsupportedPlatform
            }
            var error: Unmanaged<CFError>?
            let valid = SecKeyVerifySignature(
                verifyingKey,
                SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                Data(message) as CFData,
                Data(signature) as CFData,
                &error
            )
            guard valid else {
                throw ReallyMeCryptoError.invalidSignature
            }
        } catch let error as ReallyMeCryptoError {
            throw error
        } catch {
            throw ReallyMeCryptoError.invalidInput
        }
    }

    public static func deleteKey(privateKeyHandle: [UInt8]) throws {
        let tag = try decodePrivateKeyHandle(privateKeyHandle)
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        try deleteKey(tag: tag)
    }

    private static var supportsSecureEnclaveSigning: Bool {
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

    private static func createPrivateKey(
        tag: [UInt8],
        accessControl: ReallyMeSecureEnclaveAccessControl
    ) throws -> SecKey {
        let keychainTag = storageTag(for: tag)
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControl.secAccessControlFlags,
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

    private static func privateKey(
        for privateKeyHandle: [UInt8],
        authenticationPrompt: String?
    ) throws -> SecKey {
        let tag = try decodePrivateKeyHandle(privateKeyHandle)
        let keychainTag = storageTag(for: tag)
        let authenticationContext: LAContext?
        if let authenticationPrompt {
            let context = LAContext()
            context.localizedReason = authenticationPrompt
            authenticationContext = context
        } else {
            authenticationContext = nil
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: Data(keychainTag),
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
            let cryptoKitKey = try P256.Signing.PublicKey(compressedRepresentation: Data(publicKey))
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
        case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
            return ReallyMeCryptoError.providerFailure
        default:
            return ReallyMeCryptoError.providerFailure
        }
    }
}
