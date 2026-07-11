<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-sha3

`reallyme-crypto-sha3` provides SHA3-224, SHA3-384, and SHA3-512 digest
wrappers for the ReallyMe Crypto workspace. SHA3-256 remains in
`reallyme-crypto-sha3-256` so callers that only need SHA3-256 can keep a
smaller dependency surface.

The crate owns fixed-size digest types, zeroizes digest buffers on drop, and
leaves algorithm dispatch, FFI, and platform package bindings to adapter
crates.

## Test

```sh
cargo test -p reallyme-crypto-sha3 --features native
```
