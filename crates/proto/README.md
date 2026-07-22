<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-proto

`reallyme-crypto-proto` contains the Rust Buffa bindings for the canonical
`reallyme.crypto.v1` structured wire contract. The package publishes operation
requests and responses, stable algorithm identifiers, typed results, and
non-PII error envelopes for API, storage, and message boundaries.

This crate defines messages only; it intentionally declares no protobuf service.
`CryptoOperationRequest` is the single executable adapter request and
`CryptoOperationResponse` is the primary generated binary response shape.
JSON is a generated ProtoJSON request convenience. Results remain one fully
typed binary protobuf operation response. The executable JSON adapter accepts
only hash, public-key verification, public-key encapsulation, and key-generation
requests whose JSON input carries no cryptographic secret.

Operation requests can contain secrets and plaintext. Owned Rust messages
redact byte-bearing debug output and zeroize sensitive fields on drop. Callers
must keep messages short-lived and avoid cloning or logging payloads.
Secret-bearing executable requests are rejected on the ProtoJSON route before
value deserialization and must use binary protobuf.

```toml
[dependencies]
reallyme-crypto-proto = { version = "0.3.3", features = ["generated"] }
```

The `generated` feature includes Buffa protobuf bytes and strict ProtoJSON
support for the generated operation request/response contract. ProtoJSON is a
restricted request and conformance lane for JSON-only adapters and fixtures; it
is not a casual JSON crypto facade. Secret-bearing operations are binary-only.
See the repository's `docs/proto-json.md` for operation-family JSON examples.

The protobuf source lives at
[`proto/reallyme/crypto/v1/crypto.proto`](proto/reallyme/crypto/v1/crypto.proto).
