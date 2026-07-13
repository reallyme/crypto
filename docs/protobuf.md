<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Protobuf

The importable wire/config contract lives at
[../proto/reallyme/crypto/v1/crypto.proto](../proto/reallyme/crypto/v1/crypto.proto)
and [../proto/reallyme/codec/v1/codec.proto](../proto/reallyme/codec/v1/codec.proto).
Service, application, and storage protos can import those files when they need
to store or transmit crypto choices, codec choices, or non-secret error
envelopes.

Use proto enums for API and storage boundaries, not string algorithm names.
Inside SDK and application code, use the native facade types for each language.
`CryptoError` and `CodecError` are non-PII boundary envelopes. Their reason
enums are coarse wire categories. Keep local typed errors at the owning layer
and map to these messages only when an API, log-safe status surface, or
persisted message needs a stable reason code.

## Generated Surfaces

| Language | Surface |
|---|---|
| Rust | `reallyme-crypto-proto` for `reallyme.crypto.v1`; `reallyme-codec-proto` for `reallyme.codec.v1` |
| Swift | `ReallyMeCryptoProto` plus `ReallyMeCryptoProtoAdapters` |
| Kotlin | generated `me.really.crypto.v1` and `me.really.codec.v1` types plus `me.really.crypto.proto.ReallyMeCryptoProtoAdapters` |
| TypeScript | `@reallyme/crypto/proto` |

## Boundary Rule

Convert at API, storage, and message boundaries:

```text
proto enum -> facade enum/string union -> crypto operation
crypto result -> facade type -> proto enum when persisted or transmitted
```

The adapters reject `UNSPECIFIED`, unrecognized enum values, and
private/reserved multicodec values with typed unsupported-algorithm errors.
Error reason enums follow the same rule: `UNSPECIFIED` is not a concrete
failure and should not be emitted by application code.

The error envelopes intentionally split failures by owning subpart:

| Package | Envelope | Sub-errors |
|---|---|---|
| `reallyme.crypto.v1` | `CryptoError` | `CryptoPrimitiveError`, `CryptoProviderError`, `CryptoBackendError` |
| `reallyme.codec.v1` | `CodecError` | `CodecBaseEncodingError`, `CodecPemError`, `CodecMultiformatError`, `CodecCanonicalizationError` |

Keep ownership intact when errors cross package boundaries. A crypto API that
fails while parsing PEM, multikey, CBOR, JCS, or another codec-owned format
should either preserve the codec origin with `CodecError`, or deliberately map
the failure to a crypto-owned public reason such as `CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_ENCODING`.
Do not add codec-specific reasons to `CryptoErrorReason`.

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
or codec choice: Connect APIs, durable configuration, stored keys, network
messages, or log-safe status records.

Do not force proto types into ordinary facade calls when the caller is already
inside one language package. The facade types are intentionally more ergonomic
there.
