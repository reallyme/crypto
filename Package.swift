// swift-tools-version: 6.0
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Root manifest for `reallyme-crypto`.
//
// SwiftPM and Xcode only read a `Package.swift` at the repository root when a
// package is consumed by URL, e.g.
//
//     .package(url: "https://github.com/reallyme/crypto", from: "0.1.1")
//     .product(name: "ReallyMeCrypto", package: "crypto")
//
// The Swift sources live under `packages/swift/` to keep symmetry with the
// other language lanes (`packages/ts`, `packages/kotlin`); this manifest points
// its targets there explicitly so there is a single source of truth.

import PackageDescription

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
    targets: [
        .target(
            name: "ReallyMeCrypto",
            dependencies: [
                .product(name: "CSecp256k1", package: "CSecp256k1"),
                .product(name: "Digest", package: "Digest"),
            ],
            path: "packages/swift/Sources/ReallyMeCrypto"
        ),
        .target(
            name: "ReallyMeCryptoProto",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "gen/swift"
        ),
        .target(
            name: "ReallyMeCryptoProtoAdapters",
            dependencies: [
                "ReallyMeCrypto",
                "ReallyMeCryptoProto",
            ],
            path: "packages/swift/Sources/ReallyMeCryptoProtoAdapters"
        ),
        .testTarget(
            name: "ReallyMeCryptoTests",
            dependencies: [
                "ReallyMeCrypto",
                "ReallyMeCryptoProto",
                "ReallyMeCryptoProtoAdapters",
            ],
            path: "packages/swift/Tests/ReallyMeCryptoTests"
        ),
    ]
)
