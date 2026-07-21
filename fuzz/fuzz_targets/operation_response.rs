// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_crypto::operation_contract::{
    process_operation_response, process_operation_response_json,
};

fuzz_target!(|data: &[u8]| {
    let binary_response = process_operation_response(data);
    let _binary_len = binary_response.len();
    let json_envelope = process_operation_response_json(data);
    let _json_len = json_envelope.len();
});
