<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# @reallyme/crypto

[![npm](https://img.shields.io/npm/v/@reallyme/crypto?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/crypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/reallyme/crypto/blob/main/LICENSE)

ReallyMe Crypto provides a platform-agnostic cryptography API for TypeScript,
Rust, Swift, and Kotlin.

Applications can implement cryptographic operations once and rely on identical
algorithms, key formats, verification behavior, and protocol contracts across
servers, browsers, iOS, Android, and WASM. Native platform providers are used
where appropriate, while shared conformance vectors ensure byte-for-byte
compatible behavior across every supported language.

## Why

Modern cryptography APIs differ across platforms. Algorithms are exposed
differently, key formats vary, providers have different capabilities, and error
behavior is inconsistent.

ReallyMe Crypto provides one consistent cryptography contract across every
supported platform. The same application logic can be shared between backend
services, mobile applications, and browsers without maintaining separate
cryptographic implementations.

## Installation

```sh
npm install @reallyme/crypto
```

## Example

```ts
import { ReallyMeCrypto } from "@reallyme/crypto";

const digest = ReallyMeCrypto.hash(
  "SHA2-256",
  new TextEncoder().encode("hello"),
);
```

The API is synchronous. Signature verification throws `ReallyMeCryptoError` on
invalid input rather than returning a boolean that can be accidentally ignored.

## Post-Quantum and WASM

Classical primitives are backed by pinned `@noble` packages. The primitives that
must stay identical to Rust — ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id, HPKE,
and others — are backed by a WASM module that ships prebuilt with the package.

Install the WASM provider once at startup before using those algorithms;
otherwise they fail closed with `provider-failure`.

```ts
import { readFileSync } from "node:fs";
import { installReallyMeWasmProvider, ReallyMeCrypto } from "@reallyme/crypto";
import * as wasmProvider from "@reallyme/crypto/wasm/reallyme_crypto_wasm.js";

const wasmUrl = import.meta.resolve(
  "@reallyme/crypto/wasm/reallyme_crypto_wasm_bg.wasm",
);
wasmProvider.initSync({ module: readFileSync(new URL(wasmUrl)) });
installReallyMeWasmProvider(wasmProvider);

const keyPair = ReallyMeCrypto.generateKemKeyPair("X-Wing-768");
```

## Features

- Platform-agnostic cryptography APIs.
- Consistent key formats and protocol identifiers.
- Shared conformance vectors across Rust, Swift, Kotlin, and TypeScript.
- Native providers where available, WASM-backed implementations where needed.
- Typed errors and fail-closed verification behavior.
- Protobuf algorithm identifiers for API and storage boundaries, via
  `@reallyme/crypto/proto`.
- JWK, multikey, multicodec, HPKE, ML-KEM, ML-DSA, Ed25519, secp256k1, X25519,
  AES-GCM, ChaCha20-Poly1305, and more.

## Documentation

The complete documentation, provider matrix, protocol contracts, and conformance
specifications are available in the main repository:

https://github.com/reallyme/crypto
