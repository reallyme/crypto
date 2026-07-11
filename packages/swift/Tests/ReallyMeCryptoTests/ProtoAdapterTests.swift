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
}
