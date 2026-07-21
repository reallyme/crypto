// swift-tools-version: 6.0
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import PackageDescription

let package = Package(
    name: "ReallyMeCryptoVectorConformance",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [],
    dependencies: [
        .package(
            url: "https://github.com/leif-ibsen/SwiftKyber",
            from: "3.5.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/SwiftDilithium",
            from: "3.6.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/BigInt",
            from: "1.24.0"
        ),
        .package(
            url: "https://github.com/leif-ibsen/Digest",
            from: "1.13.0"
        ),
        .package(
            url: "https://github.com/reallyme/CSecp256k1",
            from: "0.1.0"
        ),
    ],
    targets: [
        .target(
            name: "Secp256k1ABI",
            dependencies: [
                .product(name: "CSecp256k1", package: "CSecp256k1"),
            ]
        ),
        .target(
            name: "SwiftProviderProbes",
            dependencies: [
                .product(name: "SwiftKyber", package: "SwiftKyber"),
                .product(name: "SwiftDilithium", package: "SwiftDilithium"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Digest", package: "Digest"),
            ]
        ),
        .testTarget(
            name: "ReallyMeCryptoVectorTests",
            dependencies: [
                "Secp256k1ABI",
                "SwiftProviderProbes",
            ]
        ),
    ]
)
