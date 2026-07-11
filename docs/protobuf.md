<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Protobuf

The importable wire/config contract lives at
[../proto/reallyme/crypto/v1/crypto.proto](../proto/reallyme/crypto/v1/crypto.proto).
Service, application, and storage protos can import that file when they need to
store or transmit crypto choices.

Use proto enums for API and storage boundaries, not string algorithm names.
Inside SDK and application code, use the native facade types for each language.

## Generated Surfaces

| Language | Surface |
|---|---|
| Rust | `reallyme-crypto-proto` |
| Swift | `ReallyMeCryptoProto` plus `ReallyMeCryptoProtoAdapters` |
| Kotlin | generated `me.really.crypto.v1` types plus `me.really.crypto.proto.ReallyMeCryptoProtoAdapters` |
| TypeScript | `@reallyme/crypto/proto` |

## Boundary Rule

Convert at API, storage, and message boundaries:

```text
proto enum -> facade enum/string union -> crypto operation
crypto result -> facade type -> proto enum when persisted or transmitted
```

The adapters reject `UNSPECIFIED`, unrecognized enum values, and
private/reserved multicodec values with typed unsupported-algorithm errors.

## TypeScript Example

```ts
import {
  HashAlgorithm,
  hashAlgorithmFromProto,
  hashAlgorithmToProto,
} from "@reallyme/crypto/proto";

const facadeAlgorithm = hashAlgorithmFromProto(HashAlgorithm.SHA2_256);
const protoAlgorithm = hashAlgorithmToProto(facadeAlgorithm);
```

## When To Use Proto

Use the proto definitions when another protocol needs to refer to a crypto
choice: Connect APIs, durable configuration, stored keys, or network messages.

Do not force proto types into ordinary facade calls when the caller is already
inside one language package. The facade types are intentionally more ergonomic
there.
