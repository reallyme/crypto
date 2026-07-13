<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-crypto-proto

`reallyme-crypto-proto` contains the Rust Buffa bindings for
`reallyme.crypto.v1`. The package publishes stable crypto algorithm
identifiers and non-PII error envelopes for service, storage, and configuration
boundaries.

```toml
[dependencies]
reallyme-crypto-proto = { version = "0.1.3", features = ["generated"] }
```

The protobuf source lives at
[`proto/reallyme/crypto/v1/crypto.proto`](../../../proto/reallyme/crypto/v1/crypto.proto).
Codec protobuf bindings are published separately as `reallyme-codec-proto`.
