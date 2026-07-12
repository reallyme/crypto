// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import CSecp256k1
import Digest
import Foundation

/// Providers compiled into the Swift package.
///
/// This lists only providers an operational code path actually routes to,
/// matching `PROVIDER_POLICY.md`: post-quantum (ML-KEM/ML-DSA/SLH-DSA/X-Wing)
/// goes through the ReallyMe Rust C ABI, so no Swift-native PQ package is
/// linked. Do not add a provider here without a code path that uses it.
public enum ReallyMeCryptoProvider: String, CaseIterable, Sendable {
    case cryptoKit = "CryptoKit"
    case secureEnclaveKeychain = "Secure Enclave/Keychain"
    case cSecp256k1 = "CSecp256k1"
    case digest = "Digest"
    case rustCAbi = "ReallyMe Rust C ABI"
}

/// Compile-time provider catalog used by package consumers and conformance
/// tests to assert that Swift crypto is backed by explicit provider packages.
public enum ReallyMeCryptoProviderCatalog {
    public static let compiledProviders: [ReallyMeCryptoProvider] = [
        .cryptoKit,
        .secureEnclaveKeychain,
        .cSecp256k1,
        .digest,
        .rustCAbi,
    ]
}

/// Small Apple-native digest surface used by package tests and as the first
/// package API slice while algorithm wrappers are added one at a time.
public enum ReallyMeDigest {
    public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(bytes)))
    }

    public static func sha384(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA384.hash(data: Data(bytes)))
    }

    public static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA512.hash(data: Data(bytes)))
    }

    public static func sha3_224(_ bytes: [UInt8]) -> [UInt8] {
        MessageDigest(.SHA3_224).digest(bytes)
    }

    public static func sha3_256(_ bytes: [UInt8]) -> [UInt8] {
        MessageDigest(.SHA3_256).digest(bytes)
    }

    public static func sha3_384(_ bytes: [UInt8]) -> [UInt8] {
        MessageDigest(.SHA3_384).digest(bytes)
    }

    public static func sha3_512(_ bytes: [UInt8]) -> [UInt8] {
        MessageDigest(.SHA3_512).digest(bytes)
    }
}
