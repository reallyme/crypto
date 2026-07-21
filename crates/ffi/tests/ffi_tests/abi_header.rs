// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[test]
fn ffi_header_exposes_only_the_self_describing_proto_request() {
    let header = include_str!("../../abi/reallyme_crypto_ffi.h");
    assert!(!header.contains("RM_CRYPTO_PROTO_OP_"));
    assert!(!header.contains("RM_CRYPTO_PROTO_MAX_REQUEST_LEN"));
    assert!(header.contains("#define RM_CRYPTO_PROTOBUF_MAX_REQUEST_LEN         1048576"));
    assert!(header.contains("#define RM_CRYPTO_PROTO_JSON_MAX_REQUEST_LEN       1572864"));
    assert!(!header.contains("RM_CRYPTO_PROTO_MAX_RESULT_ENVELOPE_LEN"));
    assert!(!header.contains("rm_crypto_process_proto"));
}

#[test]
fn ffi_header_documents_probe_and_len_out_semantics() {
    let header = include_str!("../../abi/reallyme_crypto_ffi.h");

    assert!(header.contains("Only rm_crypto_process_operation_response"));
    assert!(header.contains("write the required length to len_out on RM_CRYPTO_BUFFER_TOO_SMALL"));
    assert!(header.contains("Other variable-length scalar helpers do not define probe semantics"));
    assert!(header.contains("A probe executes the complete operation"));
    assert!(header.contains("Randomized responses can therefore differ"));
    assert!(header.contains("RM_CRYPTO_OPERATION_RESPONSE_MAX_LEN when single execution is required"));
    assert!(header.contains("Callers must discard every output from a call that returns a status other"));
    assert!(header.contains("Ed25519 signing accepts only a 32-byte seed"));
    assert!(!header.contains("RM_CRYPTO_ED25519_EXPANDED_SECRET_KEY_LEN"));
    assert!(header.contains("collapse authentication/tag failures to RM_CRYPTO_AUTHENTICATION_FAILED"));
}

#[test]
fn ffi_header_uses_the_primitive_p256_der_signature_bound() {
    let header = include_str!("../../abi/reallyme_crypto_ffi.h");

    assert_eq!(p256::P256_SIGNATURE_DER_MAX_LEN, 72);
    assert!(header.contains("#define RM_CRYPTO_P256_SIGNATURE_DER_MAX_LEN        72"));
}

#[test]
fn ffi_header_excludes_deterministic_encryption_entrypoints() {
    let header = include_str!("../../abi/reallyme_crypto_ffi.h");

    assert!(!header.contains("encapsulate_derand"));
    assert!(!header.contains("RM_CRYPTO_X_WING_ENCAPS_SEED_LEN"));
    assert!(header.contains("rm_crypto_x_wing_768_generate_keypair_derand"));
}
