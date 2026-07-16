// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import ReallyMeCrypto
import ReallyMeCryptoProto
import ReallyMeCryptoProtoAdapters
import XCTest

extension ReallyMeCryptoTests {
    func testProtoAlgorithmAdaptersRoundTripSupportedValues() throws {
        XCTAssertEqual(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm.ed25519
            ),
            ReallyMeSignatureAlgorithm.ed25519
        )
        XCTAssertEqual(
            ReallyMeCryptoProtoAdapters.toProto(
                ReallyMeSignatureAlgorithm.bip340SchnorrSecp256k1Sha256
            ),
            ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm.bip340SchnorrSecp256K1Sha256
        )
        XCTAssertEqual(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm.sha2256
            ),
            ReallyMeHashAlgorithm.sha2_256
        )
        XCTAssertEqual(
            ReallyMeCryptoProtoAdapters.toProto(ReallyMeHashAlgorithm.sha3_512),
            ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm.sha3512
        )
        XCTAssertEqual(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm.mlKem768Pub
            ),
            ReallyMeMulticodecKeyAlgorithm.mlKem768PublicKey
        )
    }

    func testProtoAlgorithmAdaptersRejectUnspecifiedAndPrivateCodecs() {
        XCTAssertThrowsError(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm.unspecified
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm.ed25519Priv
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
        XCTAssertThrowsError(
            try ReallyMeCryptoProtoAdapters.fromProto(
                ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm.UNRECOGNIZED(65_535)
            )
        ) { error in
            XCTAssertEqual(error as? ReallyMeCryptoError, .unsupportedAlgorithm)
        }
    }

    func testProtoErrorBytesRoundTripTypedCryptoErrors() throws {
        let encoded = try ReallyMeCryptoProtoAdapters.toProtoBytes(
            ReallyMeCryptoError.invalidSignature
        )
        let decoded = try ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(encoded)
        let authenticationEncoded = try ReallyMeCryptoProtoAdapters.toProtoBytes(
            ReallyMeCryptoError.authenticationFailed
        )
        let authenticationDecoded = try ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(
            authenticationEncoded
        )

        XCTAssertEqual(decoded, .invalidSignature)
        XCTAssertEqual(authenticationDecoded, .authenticationFailed)
        XCTAssertEqual(
            try ReallyMeCryptoProtoAdapters.fromProtoErrorBytes([0xff]),
            .providerFailure
        )
    }

    func testProtoWireErrorsPreserveBranchAndReason() throws {
        let wireError = try ReallyMeCryptoWireError.tryNew(
            branch: .primitive,
            reason: .primitiveInvalidPrivateKey
        )
        let encoded = try ReallyMeCryptoProtoAdapters.wireErrorToProtoBytes(wireError)
        let decoded = try ReallyMeCryptoProtoAdapters.wireError(
            fromProtoErrorBytes: encoded
        )
        let errorResult = try ReallyMeCryptoProtoAdapters.protoErrorResult(wireError)
        let successResult = ReallyMeCryptoProtoAdapters.protoResult(bytes: [1, 2, 3])

        XCTAssertEqual(decoded, wireError)
        XCTAssertEqual(errorResult.status, .cryptoError)
        XCTAssertTrue(errorResult.isCryptoError)
        XCTAssertEqual(
            try ReallyMeCryptoProtoAdapters.wireError(
                fromProtoErrorBytes: errorResult.bytes
            ),
            wireError
        )
        XCTAssertEqual(successResult.status, .result)
        XCTAssertFalse(successResult.isCryptoError)
        XCTAssertEqual(successResult.bytes, [1, 2, 3])
    }

    func testProtoWireErrorsPreserveFutureBranchReasonCodes() throws {
        var error = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
        var primitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
        primitive.reason = .UNRECOGNIZED(199)
        error.primitive = primitive

        let wire = try ReallyMeCryptoProtoAdapters.wireError(
            fromProtoErrorBytes: error.serializedBytes()
        )
        XCTAssertEqual(wire.branch, .primitive)
        XCTAssertEqual(wire.reasonCode, 199)
        XCTAssertEqual(wire.reason, .UNRECOGNIZED(199))
        let roundTrip = try ReallyMeCryptoProtoAdapters.wireError(
            fromProtoErrorBytes: ReallyMeCryptoProtoAdapters.wireErrorToProtoBytes(wire)
        )
        XCTAssertEqual(roundTrip, wire)
    }

    func testProtoResultAndGeneratedMessagesRedactAndClearBytes() {
        var result = ReallyMeCryptoProtoAdapters.protoResult(bytes: [1, 2, 3])
        XCTAssertTrue(result.debugDescription.contains("<redacted>"))
        result.bestEffortClear()
        XCTAssertTrue(result.bytes.isEmpty)

        var first = ReallyMeCryptoProto.ReallyMeProtoCryptoSignatureDeriveKeyPairRequest()
        first.secretKey = Data([1, 2, 3])
        var second = ReallyMeCryptoProto.ReallyMeProtoCryptoSignatureDeriveKeyPairRequest()
        second.secretKey = Data([4, 5, 6])
        XCTAssertTrue(first.debugDescription.contains("<redacted>"))
        XCTAssertFalse(first.debugDescription.contains("AQID"))
        XCTAssertEqual(first.hashValue, second.hashValue)
    }

    func testProtoWireErrorConstructorRejectsInvalidPairs() throws {
        XCTAssertThrowsError(
            try ReallyMeCryptoWireError.tryNew(
                branch: .primitive,
                reason: .unspecified
            )
        ) { error in
            XCTAssertEqual(
                error as? ReallyMeCryptoWireErrorValidationError,
                .unspecifiedReason
            )
        }
        XCTAssertThrowsError(
            try ReallyMeCryptoWireError.tryNew(
                branch: .provider,
                reason: .primitiveInvalidKey
            )
        ) { error in
            XCTAssertEqual(
                error as? ReallyMeCryptoWireErrorValidationError,
                .branchReasonMismatch
            )
        }
    }

    func testMalformedCryptoErrorEnvelopesBecomeBackendFailures() throws {
        let malformedBytes: [UInt8] = [0xff]
        let missingBranch = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
        var unspecifiedReason = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
        var unspecifiedPrimitive = ReallyMeCryptoProto.ReallyMeProtoCryptoPrimitiveError()
        unspecifiedPrimitive.reason = .unspecified
        unspecifiedReason.primitive = unspecifiedPrimitive
        var mismatchedBranch = ReallyMeCryptoProto.ReallyMeProtoCryptoError()
        var mismatchedProvider = ReallyMeCryptoProto.ReallyMeProtoCryptoProviderError()
        mismatchedProvider.reason = .primitiveInvalidKey
        mismatchedBranch.provider = mismatchedProvider

        for bytes in [
            malformedBytes,
            try missingBranch.serializedBytes(),
            try unspecifiedReason.serializedBytes(),
            try mismatchedBranch.serializedBytes(),
        ] {
            let wire = try ReallyMeCryptoProtoAdapters.wireError(fromProtoErrorBytes: bytes)
            XCTAssertEqual(wire.branch, .backend)
            XCTAssertEqual(wire.reason, .backendMalformedProtobuf)
            XCTAssertEqual(
                try ReallyMeCryptoProtoAdapters.fromProtoErrorBytes(bytes),
                .providerFailure
            )
        }
    }

    func testProtoFacadeProjectionDoesNotCollapseInvalidInputToAuthentication() throws {
        let invalidReasons: [ReallyMeCryptoProto.ReallyMeProtoCryptoErrorReason] = [
            .primitiveInvalidParameter,
            .primitiveInvalidLength,
            .primitiveInvalidKey,
            .primitiveInvalidPublicKey,
            .primitiveInvalidPrivateKey,
            .primitiveInvalidNonce,
            .primitiveInvalidSalt,
            .primitiveInvalidPassword,
            .primitiveInvalidEncoding,
            .primitiveInvalidSharedSecret,
            .primitiveMalformedCiphertext,
            .primitiveInvalidTag,
        ]

        for reason in invalidReasons {
            let wireError = try ReallyMeCryptoWireError.tryNew(branch: .primitive, reason: reason)
            XCTAssertEqual(
                ReallyMeCryptoProtoAdapters.facadeError(fromWireError: wireError),
                .invalidInput
            )
        }

        XCTAssertEqual(
            ReallyMeCryptoProtoAdapters.facadeError(
                fromWireError: try ReallyMeCryptoWireError.tryNew(
                    branch: .primitive,
                    reason: .primitiveAuthenticationFailed
                )
            ),
            .authenticationFailed
        )
    }

    func testProtoJsonWebKeyBytesRoundTripThroughCodecPackage() throws {
        try installReallyMeCodecProviderForTest()
        let publicKey = (0..<32).map { UInt8($0) }
        let jwk = try ReallyMeJwk.toJwk(algorithm: .ed25519, publicKey: publicKey)
        let key = ReallyMeJwkKey(algorithm: .ed25519, publicKey: publicKey, jwk: jwk)

        let decoded = try ReallyMeCryptoProtoAdapters.fromProtoJsonWebKeyBytes(
            try ReallyMeCryptoProtoAdapters.toProtoBytes(key)
        )
        XCTAssertEqual(decoded.algorithm, key.algorithm)
        XCTAssertEqual(decoded.publicKey, key.publicKey)
        XCTAssertEqual(try ReallyMeJwk.toJcs(decoded.jwk), try ReallyMeJwk.toJcs(key.jwk))

        let decodedSet = try ReallyMeCryptoProtoAdapters.fromProtoJsonWebKeySetBytes(
            try ReallyMeCryptoProtoAdapters.toProtoJsonWebKeySetBytes([key])
        )
        XCTAssertEqual(decodedSet.count, 1)
        XCTAssertEqual(decodedSet[0].publicKey, key.publicKey)
    }

    func testProtoMultiFieldCryptoEnvelopeBytesRoundTrip() throws {
        let publicKey: [UInt8] = [1, 2, 3, 4]
        let secretKey: [UInt8] = [5, 6, 7, 8]

        let signature = try ReallyMeCryptoProtoAdapters.signatureKeyPair(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.signatureKeyPairToProtoBytes(
                algorithm: .ed25519,
                keyPair: ReallyMeSignatureKeyPair(publicKey: publicKey, secretKey: secretKey)
            )
        )
        XCTAssertEqual(signature.algorithm, .ed25519)
        XCTAssertEqual(signature.keyPair.publicKey, publicKey)
        XCTAssertEqual(signature.keyPair.secretKey, secretKey)

        let keyAgreement = try ReallyMeCryptoProtoAdapters.keyAgreementKeyPair(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.keyAgreementKeyPairToProtoBytes(
                algorithm: .x25519,
                keyPair: ReallyMeKeyAgreementKeyPair(publicKey: publicKey, secretKey: secretKey)
            )
        )
        XCTAssertEqual(keyAgreement.algorithm, .x25519)
        XCTAssertEqual(keyAgreement.keyPair.publicKey, publicKey)
        XCTAssertEqual(keyAgreement.keyPair.secretKey, secretKey)

        let kem = try ReallyMeCryptoProtoAdapters.kemKeyPair(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.kemKeyPairToProtoBytes(
                algorithm: .mlKem768,
                keyPair: ReallyMeKemKeyPair(publicKey: publicKey, secretKey: secretKey)
            )
        )
        XCTAssertEqual(kem.algorithm, .mlKem768)
        XCTAssertEqual(kem.keyPair.publicKey, publicKey)
        XCTAssertEqual(kem.keyPair.secretKey, secretKey)

        let encapsulation = try ReallyMeCryptoProtoAdapters.kemEncapsulation(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.kemEncapsulationToProtoBytes(
                algorithm: .mlKem768,
                encapsulation: ReallyMeKemEncapsulation(
                    sharedSecret: [9, 10],
                    ciphertext: [11, 12]
                )
            )
        )
        XCTAssertEqual(encapsulation.algorithm, .mlKem768)
        XCTAssertEqual(encapsulation.encapsulation.sharedSecret, [9, 10])
        XCTAssertEqual(encapsulation.encapsulation.ciphertext, [11, 12])

        let sealedMessage = try ReallyMeCryptoProtoAdapters.hpkeSealedMessage(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.hpkeSealedMessageToProtoBytes(
                suite: .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                sealedMessage: ReallyMeHpkeSealedMessage(
                    encapsulatedKey: [13, 14],
                    ciphertext: [15, 16]
                )
            )
        )
        XCTAssertEqual(sealedMessage.suite, .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305)
        XCTAssertEqual(sealedMessage.sealedMessage.encapsulatedKey, [13, 14])
        XCTAssertEqual(sealedMessage.sealedMessage.ciphertext, [15, 16])
    }

    func testProtoVerificationAndProviderCapabilityEnvelopeBytesRoundTrip() throws {
        var algorithm = ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmIdentifier()
        algorithm.signature = .ed25519

        let verification = try ReallyMeCryptoProtoAdapters.verificationResult(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.verificationResultToProtoBytes(
                ReallyMeCryptoProtoAdapters.verificationResultToProto(
                    algorithm: algorithm,
                    valid: true
                )
            )
        )
        XCTAssertEqual(verification.status, .valid)

        let verificationError = try ReallyMeCryptoProtoAdapters.verificationResult(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.verificationResultToProtoBytes(
                ReallyMeCryptoProtoAdapters.verificationErrorToProto(
                    algorithm: algorithm,
                    error: .invalidSignature
                )
            )
        )
        XCTAssertEqual(verificationError.status, .error)

        let decodedCapabilities = try ReallyMeCryptoProtoAdapters.providerCapabilitySet(
            fromProtoBytes: ReallyMeCryptoProtoAdapters.providerCapabilitySetToProtoBytes([
                ReallyMeProviderCapabilityProtoValue(
                    algorithm: algorithm,
                    family: .signature,
                    providerNames: ["rust"],
                    status: .supported,
                    usesRust: true
                ),
            ])
        )
        XCTAssertEqual(decodedCapabilities.count, 1)
        XCTAssertEqual(
            decodedCapabilities[0].family,
            ReallyMeCryptoProto.ReallyMeProtoCryptoAlgorithmFamily.signature
        )
        XCTAssertEqual(decodedCapabilities[0].providerNames, ["rust"])
        XCTAssertEqual(
            decodedCapabilities[0].status,
            ReallyMeCryptoProto.ReallyMeProtoCryptoProviderSupportStatus.supported
        )
        XCTAssertTrue(decodedCapabilities[0].usesRust)
    }
}
