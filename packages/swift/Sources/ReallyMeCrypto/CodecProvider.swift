// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCodec

/// Explicit codec provider hook for Swift package consumers.
///
/// Crypto keeps its JWK and multikey public API stable, but codec primitives
/// are owned by `reallyme-codec`. Applications install that provider once at
/// startup; codec-dependent static crypto helpers then fail closed if it is
/// missing instead of falling back to duplicated Swift codec code.
public enum ReallyMeCryptoCodecProvider {
    private static let storage = ReallyMeCryptoCodecProviderStorage()

    public static func install(_ codec: ReallyMeCodec) {
        storage.install(codec)
    }

    static func requireCodec() throws -> ReallyMeCodec {
        try storage.requireCodec()
    }
}

private final class ReallyMeCryptoCodecProviderStorage: @unchecked Sendable {
    private let lock = NSLock()
    private var codec: ReallyMeCodec?

    func install(_ codec: ReallyMeCodec) {
        lock.lock()
        self.codec = codec
        lock.unlock()
    }

    func requireCodec() throws -> ReallyMeCodec {
        lock.lock()
        let installed = codec
        lock.unlock()
        guard let installed else {
            throw ReallyMeCryptoError.providerFailure
        }
        return installed
    }
}

func mapCodecError(_ error: Error) -> ReallyMeCryptoError {
    guard let codecError = error as? ReallyMeCodecError else {
        return .providerFailure
    }
    switch codecError {
    case .unsupportedPlatform:
        return .unsupportedPlatform
    case .dynamicLibraryNotFound:
        return .dynamicLibraryNotFound
    case .dynamicLibraryLoadFailed:
        return .dynamicLibraryLoadFailed
    case .symbolNotFound:
        return .symbolNotFound
    case .invalidInput:
        return .invalidInput
    case .providerFailure:
        return .providerFailure
    }
}
