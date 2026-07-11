// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#if canImport(Darwin)
import Darwin
#endif
import Foundation

/// Runtime handle for the ReallyMe Rust C ABI dynamic library.
///
/// The Swift SDK keeps dynamic loading typed and explicit so package consumers
/// can choose whether they use Apple-native providers, the Rust ABI, or both.
public final class ReallyMeRustCAbiLibrary: @unchecked Sendable {
    private let handle: UnsafeMutableRawPointer

    public init(path: String) throws {
        #if canImport(Darwin)
        guard FileManager.default.fileExists(atPath: path) else {
            throw ReallyMeCryptoError.dynamicLibraryNotFound
        }
        guard let loadedHandle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            throw ReallyMeCryptoError.dynamicLibraryLoadFailed
        }
        handle = loadedHandle
        #else
        _ = path
        throw ReallyMeCryptoError.unsupportedPlatform
        #endif
    }

    deinit {
        #if canImport(Darwin)
        dlclose(handle)
        #endif
    }

    public func loadFunction<Function>(_ symbol: StaticString, as _: Function.Type) throws -> Function {
        #if canImport(Darwin)
        guard let rawSymbol = dlsym(handle, symbol.description) else {
            throw ReallyMeCryptoError.symbolNotFound
        }
        return unsafeBitCast(rawSymbol, to: Function.self)
        #else
        _ = symbol
        throw ReallyMeCryptoError.unsupportedPlatform
        #endif
    }
}
