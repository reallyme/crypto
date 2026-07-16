// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoRustCAbiTests {
    func testRustCAbiMlKemVectorsWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()

        try Self.assertMlKemVector(
            algorithm: .mlKem512,
            vectorFileName: "mlkem512.json",
            library: library
        )
        try Self.assertMlKemVector(
            algorithm: .mlKem768,
            vectorFileName: "mlkem768.json",
            library: library
        )
        try Self.assertMlKemVector(
            algorithm: .mlKem1024,
            vectorFileName: "mlkem1024.json",
            library: library
        )
    }

    func testRustCAbiMlDsaVectorsWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()

        try Self.assertMlDsaVector(
            algorithm: .mlDsa44,
            vectorFileName: "ml_dsa_44.json",
            library: library
        )
        try Self.assertMlDsaVector(
            algorithm: .mlDsa65,
            vectorFileName: "ml_dsa_65.json",
            library: library
        )
        try Self.assertMlDsaVector(
            algorithm: .mlDsa87,
            vectorFileName: "ml_dsa_87.json",
            library: library
        )
    }

    func testRustCAbiSlhDsaVectorWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        try Self.assertSlhDsaVector(library: library)
    }

    func testRustCAbiXWingVectorsWhenLibraryConfigured() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let vectors = try Self.loadXWingVectors()

        try Self.assertXWingVector(
            algorithm: .xWing768,
            vector: vectors.xWing768,
            library: library
        )
        try Self.assertXWingVector(
            algorithm: .xWing1024,
            vector: vectors.xWing1024,
            library: library
        )

        let freshKeyPair = try ReallyMeCrypto.generateKemKeyPair(.xWing768, rustCAbiLibrary: library)
        let freshEncapsulation = try ReallyMeCrypto.encapsulate(
            .xWing768,
            publicKey: freshKeyPair.publicKey,
            rustCAbiLibrary: library
        )
        XCTAssertEqual(
            try ReallyMeCrypto.decapsulate(
                .xWing768,
                ciphertext: freshEncapsulation.ciphertext,
                secretKey: freshKeyPair.secretKey,
                rustCAbiLibrary: library
            ),
            freshEncapsulation.sharedSecret
        )
    }
}
