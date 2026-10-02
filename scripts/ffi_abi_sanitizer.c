// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#include "reallyme_crypto_ffi.h"
#include <stdint.h>
#include <string.h>

int main(void) {
    static const uint8_t message[] = {'a', 'b', 'c'};
    static const uint8_t expected_digest[RM_CRYPTO_SHA2_256_DIGEST_LEN] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t digest[RM_CRYPTO_SHA2_256_DIGEST_LEN] = {0};
    uint8_t short_digest[RM_CRYPTO_SHA2_256_DIGEST_LEN - 1] = {0};

    if (rm_crypto_sha2_256_digest(message, sizeof(message), digest, sizeof(digest)) != RM_CRYPTO_OK ||
        memcmp(digest, expected_digest, sizeof(digest)) != 0) {
        return 1;
    }
    if (rm_crypto_sha2_256_digest(message, sizeof(message), short_digest,
                                    sizeof(short_digest)) != RM_CRYPTO_BUFFER_TOO_SMALL) {
        return 2;
    }
    if (rm_crypto_sha2_256_digest(NULL, sizeof(message), digest,
                                    sizeof(digest)) != RM_CRYPTO_INVALID_ARGUMENT) {
        return 3;
    }
    if (rm_crypto_sha2_256_digest(NULL, 0, digest, sizeof(digest)) != RM_CRYPTO_OK) {
        return 4;
    }

    uint8_t response[128] = {0};
    size_t produced = 0;
    if (rm_crypto_process_operation_response_json(NULL, 1, response, sizeof(response),
                                                    &produced) != RM_CRYPTO_INVALID_ARGUMENT) {
        return 5;
    }
    if (rm_crypto_process_operation_response_json(message, sizeof(message), response,
                                                    sizeof(response), (size_t *)response) !=
        RM_CRYPTO_INVALID_ARGUMENT) {
        return 6;
    }
    return 0;
}
