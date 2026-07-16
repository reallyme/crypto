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
- failures return `rm_crypto_status_t`
- errors never carry secret or caller-provided data
- callers own output buffers and any platform-specific zeroization policy

## Test

```sh
cargo test -p crypto-ffi
```

The Swift conformance harness also loads this library dynamically for the
post-quantum and SHA-3 checks. Rust FFI tests cover the exported SHA-2 and
SHA-3 ABI.
