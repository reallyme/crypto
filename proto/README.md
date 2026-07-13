<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Protobuf

This directory contains the importable protobuf contract for ReallyMe crypto and
codec identifiers. Other service and application protos can import these enums
when they need stable crypto configuration, codec configuration, storage, or
Connect API fields.

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

The generation config follows the workspace package convention for Rust: Buffa
message and view types are emitted under
`crates/proto/crypto/src/generated/buffa` and
`crates/proto/codec/src/generated/buffa`, behind the
`reallyme-crypto-proto/generated` and `reallyme-codec-proto/generated`
features. TypeScript, Swift, Java, and Kotlin outputs are emitted under `gen/`
for package consumers.

This repository expects `protoc-gen-buffa` and `protoc-gen-buffa-packaging`
`0.8.1` or newer.
