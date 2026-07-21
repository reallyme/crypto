<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Crypto Protobuf

The importable protobuf contract for ReallyMe Crypto lives at
[`../crates/proto/proto/reallyme/crypto/v1/crypto.proto`](../crates/proto/proto/reallyme/crypto/v1/crypto.proto).
It is the source of truth for executable structured requests and responses,
algorithm identifiers, typed results, and wire errors. Services and
applications can import the same schema for RPC, storage, and message fields.

Some operation messages necessarily carry private keys, plaintext, passwords,
salts, and derived material. Prefer protobuf binary for those operations, keep
messages short-lived, enforce the shared size and recursion limits, and do not
log or persist request payloads. Generated Rust messages redact byte-bearing
debug output and zeroize owned sensitive fields on drop. Managed-language
bindings require the package-specific best-effort clearing discipline.

## Generate

From the repository root:

```sh
buf lint
buf generate
```

The protobuf source and Buffa message/view types are owned by `crates/proto`,
behind the `reallyme-crypto-proto/generated` feature.
TypeScript, Swift, Java, and Kotlin outputs are emitted under `gen/` for
package consumers.

This repository expects `protoc-gen-buffa` and `protoc-gen-buffa-packaging`
`0.8.1` or newer.
