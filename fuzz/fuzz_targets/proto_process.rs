// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_crypto::proto_process::{
    process_proto, OP_AEAD_OPEN, OP_AEAD_SEAL, OP_BIP340_SCHNORR_SIGN, OP_HASH, OP_HKDF_DERIVE,
    OP_HPKE_OPEN, OP_HPKE_SEAL, OP_JWA_CONCAT_KDF_SHA256_DERIVE, OP_KDF_DERIVE_KEY,
    OP_KEM_DECAPSULATE, OP_KEM_ENCAPSULATE, OP_KEM_GENERATE_KEY_PAIR,
    OP_KEY_AGREEMENT_DERIVE_KEY_PAIR, OP_KEY_AGREEMENT_DERIVE_SHARED_SECRET, OP_KEY_UNWRAP,
    OP_KEY_WRAP, OP_MAC_AUTHENTICATE, OP_MAC_VERIFY, OP_RSA_VERIFY, OP_SIGNATURE_DERIVE_KEY_PAIR,
    OP_SIGNATURE_GENERATE_KEY_PAIR, OP_SIGNATURE_SIGN, OP_SIGNATURE_VERIFY,
};

const OPERATIONS: &[u32] = &[
    OP_HASH,
    OP_AEAD_SEAL,
    OP_AEAD_OPEN,
    OP_MAC_AUTHENTICATE,
    OP_MAC_VERIFY,
    OP_SIGNATURE_GENERATE_KEY_PAIR,
    OP_SIGNATURE_DERIVE_KEY_PAIR,
    OP_SIGNATURE_SIGN,
    OP_SIGNATURE_VERIFY,
    OP_BIP340_SCHNORR_SIGN,
    OP_RSA_VERIFY,
    OP_KEY_AGREEMENT_DERIVE_SHARED_SECRET,
    OP_KEY_AGREEMENT_DERIVE_KEY_PAIR,
    OP_KEM_GENERATE_KEY_PAIR,
    OP_KEM_ENCAPSULATE,
    OP_KEM_DECAPSULATE,
    OP_HKDF_DERIVE,
    OP_KDF_DERIVE_KEY,
    OP_JWA_CONCAT_KDF_SHA256_DERIVE,
    OP_KEY_WRAP,
    OP_KEY_UNWRAP,
    OP_HPKE_SEAL,
    OP_HPKE_OPEN,
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, request_bytes)) = data.split_first() else {
        return;
    };
    let operation = OPERATIONS[usize::from(selector) % OPERATIONS.len()];
    let result = process_proto(operation, request_bytes);

    // Touch the envelope so libFuzzer exercises both decode failure and
    // result/error serialization paths without asserting semantic validity for
    // random requests.
    let _status = result.status;
    let _len = result.bytes().len();
});
