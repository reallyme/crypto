<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-codec

`reallyme-codec` is the codec-only Rust package from the ReallyMe Crypto
workspace. It provides stable byte-format utilities without pulling in
signature, AEAD, KEM, or password-hashing implementations.

Use this crate when a resolver, service, or tool needs key and content
encodings but does not need cryptographic operations. The supported surface is
algorithm-agnostic: base64/base64url, multibase, multicodec, multikey,
canonical CBOR/DAG-CBOR helpers, and JSON Canonicalization Scheme helpers.

## Install

```toml
[dependencies]
reallyme-codec = "0.1"
```

The default feature set enables every codec family. Consumers that need a
smaller dependency surface can select only the families they use:

```toml
[dependencies]
reallyme-codec = { version = "0.1", default-features = false, features = ["base64url", "multikey"] }
```

## Quick Start

```rust
use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};

fn round_trip() -> Result<(), reallyme_codec::base64url::Base64UrlError> {
    let encoded = bytes_to_base64url(b"hello");
    let decoded = base64url_to_bytes(&encoded)?;
    assert_eq!(decoded, b"hello");
    Ok(())
}
```

Multikey support treats keys as opaque public bytes plus a multicodec prefix.
Algorithm-aware key parsing, signing, verification, and JWK envelopes live in
`reallyme-crypto`.

## Features

- `base64`
- `base64url`
- `cbor`
- `jcs`
- `multibase`
- `multicodec`
- `multikey`

## Contract

The supported public entry points are the umbrella exports from
`reallyme-codec`; individual workspace crates are implementation details unless
their documentation says otherwise.
