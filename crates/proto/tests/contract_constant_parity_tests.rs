// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compatibility values recorded before leaf aliases move to the schema.

#![cfg(feature = "contract-types")]

use reallyme_crypto_proto::contract_constants;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scalar_values_preserve_existing_primitive_parameters_and_limits() {
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_ALGORITHM_VERSION,
        19u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_DERIVED_KEY_LENGTH,
        32usize
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_DESKTOP_MODERN_LANES_CAP,
        4u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_DESKTOP_MODERN_MEMORY_CAP_KIB,
        2097152u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_DESKTOP_MODERN_TIME_COST_CAP,
        6u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_MOBILE_MODERN_LANES_CAP,
        4u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_MOBILE_MODERN_MEMORY_CAP_KIB,
        524288u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_MOBILE_MODERN_TIME_COST_CAP,
        4u32
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_SALT_MAX_LENGTH,
        32usize
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_SALT_MIN_LENGTH,
        16usize
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_SECRET_MAX_LENGTH,
        1048576usize
    );
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_SECRET_MIN_LENGTH,
        1usize
    );
    assert_eq!(contract_constants::argon2id::ARGON2ID_V1_LANES, 1u32);
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_V1_MEMORY_COST_KIB,
        262144u32
    );
    assert_eq!(contract_constants::argon2id::ARGON2ID_V1_TIME_COST, 3u32);
    assert_eq!(contract_constants::argon2id::ARGON2ID_V2_LANES, 1u32);
    assert_eq!(
        contract_constants::argon2id::ARGON2ID_V2_MEMORY_COST_KIB,
        524288u32
    );
    assert_eq!(contract_constants::argon2id::ARGON2ID_V2_TIME_COST, 3u32);
    assert_eq!(
        contract_constants::kmac::KMAC256_MAX_CONTEXT_LENGTH,
        65536usize
    );
    assert_eq!(
        contract_constants::kmac::KMAC256_MAX_CUSTOMIZATION_LENGTH,
        4096usize
    );
    assert_eq!(contract_constants::kmac::KMAC256_MAX_KEY_LENGTH, 4096usize);
    assert_eq!(
        contract_constants::kmac::KMAC256_MAX_OUTPUT_LENGTH,
        65536usize
    );
    assert_eq!(contract_constants::kmac::KMAC256_MIN_CONTEXT_LENGTH, 0usize);
    assert_eq!(
        contract_constants::kmac::KMAC256_MIN_CUSTOMIZATION_LENGTH,
        0usize
    );
    assert_eq!(contract_constants::kmac::KMAC256_MIN_KEY_LENGTH, 32usize);
    assert_eq!(contract_constants::kmac::KMAC256_MIN_OUTPUT_LENGTH, 1usize);
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MAX_HMAC_EVALUATIONS,
        20000000u64
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MAX_ITERATIONS,
        10000000u32
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MAX_OUTPUT_LENGTH,
        4096usize
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MAX_PASSWORD_LENGTH,
        4096usize
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MAX_SALT_LENGTH,
        4096usize
    );
    assert_eq!(contract_constants::pbkdf2::PBKDF2_MIN_OUTPUT_LENGTH, 1usize);
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MIN_PASSWORD_LENGTH,
        1usize
    );
    assert_eq!(contract_constants::pbkdf2::PBKDF2_MIN_SALT_LENGTH, 1usize);
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_MODERN_MIN_ITERATIONS,
        100000u32
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_SHA256_OUTPUT_LENGTH,
        32usize
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_SHA512_OUTPUT_LENGTH,
        64usize
    );
    assert_eq!(
        contract_constants::pbkdf2::PBKDF2_STANDARD_MIN_ITERATIONS,
        1u32
    );
    assert_eq!(
        contract_constants::proto_wire::BACKEND_REASON_CODE_MAX,
        399i32
    );
    assert_eq!(
        contract_constants::proto_wire::BACKEND_REASON_CODE_MIN,
        300i32
    );
    assert_eq!(
        contract_constants::proto_wire::CRYPTO_ERROR_ENVELOPE_PROTOBUF_DECODE_LIMIT,
        1024usize
    );
    assert_eq!(
        contract_constants::proto_wire::CRYPTO_PROTO_RECURSION_LIMIT,
        64u32
    );
    assert_eq!(
        contract_constants::proto_wire::CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT,
        0usize
    );
    assert_eq!(
        contract_constants::proto_wire::MAX_CRYPTO_PROTO_JSON_BYTES,
        1572864usize
    );
    assert_eq!(
        contract_constants::proto_wire::MAX_CRYPTO_PROTO_MESSAGE_BYTES,
        1048576usize
    );
    assert_eq!(
        contract_constants::proto_wire::PRIMITIVE_REASON_CODE_MAX,
        199i32
    );
    assert_eq!(
        contract_constants::proto_wire::PRIMITIVE_REASON_CODE_MIN,
        100i32
    );
    assert_eq!(
        contract_constants::proto_wire::PROVIDER_REASON_CODE_MAX,
        299i32
    );
    assert_eq!(
        contract_constants::proto_wire::PROVIDER_REASON_CODE_MIN,
        200i32
    );
    assert_eq!(contract_constants::rsa::RSA_MAX_EXPONENT_BITS, 64usize);
    assert_eq!(contract_constants::rsa::RSA_MAX_MODULUS_BITS, 8192usize);
    assert_eq!(contract_constants::rsa::RSA_MIN_EXPONENT_BITS, 2usize);
    assert_eq!(contract_constants::rsa::RSA_MIN_MODULUS_BITS, 1024usize);
    assert_eq!(
        contract_constants::rsa::RSA_PUBLIC_KEY_DER_MAX_LEN,
        4096usize
    );
    assert_eq!(contract_constants::rsa::RSA_SIGNATURE_MAX_LEN, 1024usize);
}
