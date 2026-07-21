// swift-tools-version: 6.0
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Root manifest for `reallyme-crypto`.
//
// SwiftPM and Xcode only read a `Package.swift` at the repository root when a
// package is consumed by URL, e.g.
//
//     .package(url: "https://github.com/reallyme/crypto", from: "0.3.2")
//     .product(name: "ReallyMeCrypto", package: "crypto")
//
// The Swift sources live under `packages/swift/` to keep symmetry with the
// other language lanes (`packages/ts`, `packages/kotlin`); this manifest points
// its targets there explicitly so there is a single source of truth.

import PackageDescription
import Foundation

let ffiArtifactChecksum = "06c8c4a74d0f3b0d06c3a0a302f20103465d42516151c291c85012f27590fdde"
let ffiArtifactVersion = "0.3.2"
let ffiArtifactLocalPathOverride = ""
// Source-tree CI explicitly exercises the runtime loader before testing the
// linked release artifact. Public consumers do not set this development-only
// override and therefore always receive the reviewed binary target. Require a
// repo-local marker as a second gate so inherited environment does not silently
// remove the release binary target.
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let runtimeFfiOverrideMarkerPath = "\(packageRoot)/.reallyme-crypto-runtime-ffi"
let runtimeFfiOverrideRequested =
    ProcessInfo.processInfo.environment["REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI"] == "1"
let useRuntimeFfiProvider =
    runtimeFfiOverrideRequested &&
    FileManager.default.fileExists(atPath: runtimeFfiOverrideMarkerPath)

var cryptoTargetDependencies: [Target.Dependency] = [
    .product(name: "CSecp256k1", package: "CSecp256k1"),
    .product(name: "Digest", package: "Digest"),
    .product(name: "ReallyMeCodec", package: "codec"),
    .product(name: "ReallyMeCodecProto", package: "codec"),
]
var cryptoSwiftSettings: [SwiftSetting] = []
var packageTargets: [Target] = []

if !useRuntimeFfiProvider {
    cryptoTargetDependencies.append("ReallyMeCryptoFFI")
    cryptoSwiftSettings.append(.define("REALLYME_CRYPTO_LINKED_FFI"))
    if ffiArtifactLocalPathOverride.isEmpty {
        packageTargets.append(
            .binaryTarget(
                name: "ReallyMeCryptoFFI",
                url: "https://github.com/reallyme/crypto/releases/download/v\(ffiArtifactVersion)/ReallyMeCryptoFFI.xcframework.zip",
                checksum: ffiArtifactChecksum
            )
        )
    } else {
        packageTargets.append(
            .binaryTarget(
                name: "ReallyMeCryptoFFI",
                path: ffiArtifactLocalPathOverride
            )
        )
    }
}

packageTargets.append(
    .target(
        name: "ReallyMeCrypto",
        dependencies: cryptoTargetDependencies,
        path: "packages/swift/Sources/ReallyMeCrypto",
        swiftSettings: cryptoSwiftSettings
    )
)
packageTargets.append(
    .target(
        name: "ReallyMeCryptoProto",
        dependencies: [
            .product(name: "SwiftProtobuf", package: "swift-protobuf"),
        ],
        path: "gen/swift"
    )
)
packageTargets.append(
    .target(
        name: "ReallyMeCryptoProtoAdapters",
        dependencies: [
            "ReallyMeCrypto",
            "ReallyMeCryptoProto",
        ],
        path: "packages/swift/Sources/ReallyMeCryptoProtoAdapters"
    )
)
packageTargets.append(
    .testTarget(
        name: "ReallyMeCryptoTests",
        dependencies: [
            "ReallyMeCrypto",
            "ReallyMeCryptoProto",
            "ReallyMeCryptoProtoAdapters",
            .product(name: "ReallyMeCodec", package: "codec"),
        ],
        path: "packages/swift/Tests/ReallyMeCryptoTests"
    )
)

let package = Package(
    name: "reallyme-crypto",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "ReallyMeCrypto",
            targets: ["ReallyMeCrypto"]
        ),
        .library(
            name: "ReallyMeCryptoProto",
            targets: ["ReallyMeCryptoProto"]
        ),
        .library(
            name: "ReallyMeCryptoProtoAdapters",
            targets: ["ReallyMeCryptoProtoAdapters"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/reallyme/codec",
            from: "0.2.0"
        ),
        .package(
            url: "https://github.com/reallyme/CSecp256k1",
            from: "0.1.0"
        ),
        // Digest supplies SHA-3 (CryptoKit has none). Post-quantum goes
        // through the ReallyMe Rust C ABI per PROVIDER_POLICY.md, so no
        // Swift-native PQ package (SwiftKyber/SwiftDilithium) is linked.
        .package(
            url: "https://github.com/leif-ibsen/Digest",
            from: "1.13.0"
        ),
        .package(
            url: "https://github.com/apple/swift-protobuf.git",
            from: "1.30.0"
        ),
    ],
    targets: packageTargets
)
