<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-ffi

`crypto-ffi` builds the native C ABI for ReallyMe Crypto. Swift, Kotlin, and
other non-Rust package bindings use this boundary when a primitive should stay
shared with Rust.

The crate builds an `rlib`, `staticlib`, and `cdylib`. The public C header is
[abi/reallyme_crypto_ffi.h](abi/reallyme_crypto_ffi.h). ABI names use the
`rm_crypto_*` prefix.

## Boundary Rules

- all byte pointer/length pairs are checked in `src/pointer.rs` before Rust
  slices are constructed
- null byte pointers are accepted only with a paired length of `0`
- byte lengths greater than `isize::MAX` are rejected at the boundary
- typed output pointers (`size_t*`, `int32_t*`) must be non-null and naturally
  aligned
- output lengths are explicit and caller-owned output buffers must not overlap
  inputs unless a function explicitly documents in-place operation
- callers discard every output whenever a call returns a non-success status
- failures return `rm_crypto_status_t`
- errors never carry secret or caller-provided data
- callers own output buffers and any platform-specific zeroization policy

Only `rm_crypto_process_operation_response` and
`rm_crypto_process_operation_response_json` support probe/fill sizing: when the
output buffer is too small, they write the required size to `len_out` and return
`RM_CRYPTO_BUFFER_TOO_SMALL`. A probe executes the requested operation, and the
subsequent fill call executes it again. Randomized results may differ between
the calls and expensive operations pay their cost twice. Allocate
`RM_CRYPTO_OPERATION_RESPONSE_MAX_LEN` when the operation must execute once.
Other scalar variable-length helpers do not define probe semantics unless their
function-specific C comment says so.

## Panic strategy

Release C/JNI artifacts must be built with the dedicated unwind-capable profile
and its compile-time assertion:

```sh
cargo build --locked -p crypto-ffi --profile release-ffi
```

The ordinary workspace `release` profile intentionally uses `panic = "abort"`
and is not a valid packaging profile for this crate. As a negative policy check,
`cargo check -p crypto-ffi --release` must fail at compile time; otherwise
`catch_unwind` could not implement the documented panic firewall.

Scalar AEAD decrypt and HPKE open functions intentionally coarsen
authentication/tag failures to `RM_CRYPTO_AUTHENTICATION_FAILED`. Generated
`CryptoOperationResponse` lanes keep the typed primitive, provider, or backend
classification without exposing backend exception text.

## Calling the ABI from Rust

Rust callers normally use `reallyme-crypto` directly. This example exists to
compile-check the pointer, length, status, and output-buffer contract exposed to
C, Swift, and Kotlin bindings:

```rust
use crypto_ffi::sha2_256::{rm_crypto_sha2_256_digest, SHA2_256_DIGEST_LEN};
use crypto_ffi::status::CRYPTO_OK;

let message = b"abc";
let mut digest = [0u8; SHA2_256_DIGEST_LEN];

// SAFETY: both pointers are valid for their paired lengths, the output is
// writable and correctly sized, and the two buffers do not overlap.
let status = unsafe {
    rm_crypto_sha2_256_digest(
        message.as_ptr(),
        message.len(),
        digest.as_mut_ptr(),
        digest.len(),
    )
};

assert_eq!(status, CRYPTO_OK);
assert_eq!(
    digest,
    [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ],
);
```

## Test

```sh
cargo test -p crypto-ffi
```

The Swift conformance harness also loads this library dynamically for the
post-quantum and SHA-3 checks. Rust FFI tests cover the exported SHA-2 and
SHA-3 ABI.
