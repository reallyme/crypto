// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class ReallyMeCryptoJavaTest {
    @Test
    void javaCallersUseStaticCryptoFacade() {
        byte[] digest = ReallyMeCrypto.hash(
            ReallyMeHashAlgorithm.SHA2_256,
            "abc".getBytes(StandardCharsets.UTF_8)
        );

        assertArrayEquals(
            new byte[] {
                (byte) 0xba, 0x78, 0x16, (byte) 0xbf, (byte) 0x8f, 0x01, (byte) 0xcf, (byte) 0xea,
                0x41, 0x41, 0x40, (byte) 0xde, 0x5d, (byte) 0xae, 0x22, 0x23,
                (byte) 0xb0, 0x03, 0x61, (byte) 0xa3, (byte) 0x96, 0x17, 0x7a, (byte) 0x9c,
                (byte) 0xb4, 0x10, (byte) 0xff, 0x61, (byte) 0xf2, 0x00, 0x15, (byte) 0xad,
            },
            digest
        );
    }
}
