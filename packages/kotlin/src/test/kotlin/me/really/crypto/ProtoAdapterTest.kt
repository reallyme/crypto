// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

import me.really.crypto.proto.ReallyMeCryptoProtoAdapters
import me.really.crypto.v1.HashAlgorithm
import me.really.crypto.v1.MulticodecKeyAlgorithm
import me.really.crypto.v1.SignatureAlgorithm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtoAdapterTest {
    @Test
    fun supportedProtoAlgorithmsRoundTripToFacadeEnums() {
        assertEquals(
            ReallyMeSignatureAlgorithm.ED25519,
            ReallyMeCryptoProtoAdapters.fromProto(
                SignatureAlgorithm.SIGNATURE_ALGORITHM_ED25519,
            ),
        )
        assertEquals(
            SignatureAlgorithm.SIGNATURE_ALGORITHM_BIP340_SCHNORR_SECP256K1_SHA256,
            ReallyMeCryptoProtoAdapters.toProto(
                ReallyMeSignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
            ),
        )
        assertEquals(
            ReallyMeHashAlgorithm.SHA2_256,
            ReallyMeCryptoProtoAdapters.fromProto(HashAlgorithm.HASH_ALGORITHM_SHA2_256),
        )
        assertEquals(
            HashAlgorithm.HASH_ALGORITHM_SHA3_512,
            ReallyMeCryptoProtoAdapters.toProto(ReallyMeHashAlgorithm.SHA3_512),
        )
        assertEquals(
            ReallyMeMulticodecKeyAlgorithm.ML_KEM_768_PUBLIC_KEY,
            ReallyMeCryptoProtoAdapters.fromProto(
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ML_KEM_768_PUB,
            ),
        )
    }

    @Test
    fun adaptersRejectUnspecifiedAndPrivateCodecs() {
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED)
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(
                MulticodecKeyAlgorithm.MULTICODEC_KEY_ALGORITHM_ED25519_PRIV,
            )
        }
        assertFailsWith<ReallyMeCryptoException.UnsupportedAlgorithm> {
            ReallyMeCryptoProtoAdapters.fromProto(SignatureAlgorithm.UNRECOGNIZED)
        }
    }
}
