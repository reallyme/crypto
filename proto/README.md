<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Protobuf

The importable protobuf contract for ReallyMe crypto now lives inside the
publishable proto crate at
[`../crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto`](../crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto).
Other service and application protos can import these enums when they need
stable crypto configuration, storage, or Connect API fields.

The schema intentionally standardizes identifiers, safe descriptors, and
non-secret error envelopes only. Raw private keys, plaintexts, ciphertexts,
passwords, salts, recovery shares, and backend exception text stay out of this
shared schema until an owning protocol defines its memory and authorization
model.

## Generate

From the repository root:

```sh
buf lint
buf generate
```

The generation config follows the workspace package convention for Rust: the
protobuf source and Buffa message/view types are owned by
`crates/proto/crypto`, behind the `reallyme-crypto-proto/generated` feature.
TypeScript, Swift, Java, and Kotlin outputs are emitted under `gen/` for
package consumers.

This repository expects `protoc-gen-buffa` and `protoc-gen-buffa-packaging`
`0.8.1` or newer.
