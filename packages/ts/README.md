<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# @reallyme/crypto

[![npm](https://img.shields.io/npm/v/@reallyme/crypto?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/crypto)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/reallyme/crypto/blob/main/LICENSE)

`@reallyme/crypto` is the TypeScript SDK for ReallyMe Crypto. It provides typed,
synchronous APIs for Node.js and browsers, with explicit JavaScript and
package-owned WASM providers.

The package shares algorithm identifiers, byte formats, typed failures, and
conformance vectors with the Rust, Swift, Kotlin, and Android SDKs. Availability
is provider-specific; unsupported routes fail closed.

## Why

Modern cryptography APIs differ across platforms. Algorithms are exposed
differently, key formats vary, providers have different capabilities, and error
behavior is inconsistent.

ReallyMe Crypto makes platform differences explicit while preserving a stable
contract for every supported route. Applications can share protocol logic
without silently changing cryptographic providers.

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

KDF facade selectors are family-specific: `deriveKey` accepts only PBKDF2,
`deriveHkdf` accepts only HKDF, and the JWA Concat KDF and KMAC methods accept
their exact selectors. Argon2id uses the dedicated `deriveArgon2id` route with
an immutable profile version rather than an iteration count.

## Post-Quantum and WASM

Classical primitives are backed by pinned `@noble` packages. The primitives that
must stay identical to Rust — ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id, HPKE,
and others — are backed by a WASM module that ships prebuilt with the package.

Applications may either install the WASM provider once for the package-level
`ReallyMeCrypto` convenience API, or build isolated facade instances with an
explicit provider object. Missing WASM providers fail closed with
`provider-failure`. JWK/JWKS helpers delegate base64url and JCS canonicalization
to the published `@reallyme/codec` package, so applications that use those
helpers should also install the Codec WASM provider.

JSON and protobuf JWKS ingress routes accept at most 1,024 keys. Encoded JWK
and JWKS protobuf inputs are capped at one mebibyte before decoding, and an
embedded canonical JCS value is capped at 8 KiB. These limits apply equally to
the direct message adapters and byte-oriented helpers.

```ts
import { readFileSync } from "node:fs";
import { installReallyMeCodecWasmProvider } from "@reallyme/codec";
import { initSync as initCodecWasm } from "@reallyme/codec/wasm/reallyme_codec_wasm.js";
import {
  createReallyMeCrypto,
  createReallyMeWasmProvider,
  installReallyMeWasmProvider,
  ReallyMeCrypto,
} from "@reallyme/crypto";
import { initSync as initCryptoWasm } from "@reallyme/crypto/wasm/reallyme_crypto_wasm.js";

// Provider constructors validate the dynamically imported module as `unknown`
// against the package's explicit required-export list.
const wasmProvider: unknown = await import(
  "@reallyme/crypto/wasm/reallyme_crypto_wasm.js"
);
const codecWasmProvider: unknown = await import(
  "@reallyme/codec/wasm/reallyme_codec_wasm.js"
);

const wasmUrl = import.meta.resolve(
  "@reallyme/crypto/wasm/reallyme_crypto_wasm_bg.wasm",
);
initCryptoWasm({ module: readFileSync(new URL(wasmUrl)) });
installReallyMeWasmProvider(wasmProvider);
const isolatedCrypto = createReallyMeCrypto({
  wasmProvider: createReallyMeWasmProvider(wasmProvider),
});

const codecWasmUrl = import.meta.resolve(
  "@reallyme/codec/wasm/reallyme_codec_wasm_bg.wasm",
);
initCodecWasm({ module: readFileSync(new URL(codecWasmUrl)) });
installReallyMeCodecWasmProvider(codecWasmProvider);

const keyPair = ReallyMeCrypto.generateKemKeyPair("X-Wing-768");
const isolatedKeyPair = isolatedCrypto.generateKemKeyPair("X-Wing-768");
```

The explicit facade form is preferred for Workers, SSR, tests, and multi-bundle
applications because each instance owns its provider routing and does not depend
on package-global mutable state.

The package-owned WASM provider derives ML-DSA, ML-KEM, and X-Wing seed-based
keypairs inside Rust and returns the public key produced by that implementation.
Custom provider objects are trusted providers: if an application supplies its
own seed-derived keypair provider, it is responsible for public-key
correspondence and must be covered by its own conformance evidence.

## Raw WASM Module Contract

The raw `@reallyme/crypto/wasm/reallyme_crypto_wasm.js` export is an internal
provider artifact for installing or constructing `ReallyMeWasmProvider`
instances. Direct raw WASM calls are unsupported for application logic. Use the
typed TypeScript facades, which validate caller inputs, numeric ranges, provider
outputs, aliasing, and cleanup before invoking the raw module.

This distinction matters for numeric parameters: JavaScript-to-WASM glue can
coerce raw `number` arguments before Rust receives them. The supported facades
reject out-of-range Argon2id, KMAC, HPKE, and RSA selector or length values
before provider dispatch. Package checks verify that the README, package
exports, TypeScript declarations, and generated WASM glue continue to agree on
this support boundary and that no ambient global crypto-provider functions are
used.

Variable-length direct primitive inputs are capped at one mebibyte before any
WASM copy or provider dispatch. Authenticated ciphertext may additionally carry
the 16-byte tag. HPKE `info` is capped at 65,530 bytes so the fixed five-byte
key-schedule label remains within RFC 9180's two-byte context-length limit.

### Browser WASM Lifecycle

Argon2id V1 and V2 require 256 MiB and 512 MiB of working memory respectively.
WebAssembly linear memory does not shrink, so an instance can retain that
resident allocation after derivation. Browser applications should run Argon2id
in a short-lived dedicated Worker and terminate the Worker after use, especially
on memory-constrained devices.

Treat a WebAssembly trap as fatal for that provider instance. The SDK maps the
trap to `provider-failure`, but does not guarantee that an instance interrupted
mid-operation remains reusable; discard its Worker or provider context before
performing another operation.

The generated loader resolves its `.wasm` file by relative URL and does not
embed a content hash. The npm tarball protects the installed package artifact,
but applications that separately host WASM bytes should use immutable asset
URLs and verify those bytes against a deployment-controlled digest before
initialization.

## Memory Hygiene

Rust-owned secret buffers are zeroized by the Rust implementation and WASM
adapters. JavaScript `Uint8Array` values are best-effort only: engines, WASM
marshalling, providers, protobuf codecs, debuggers, and crash reporters can
create copies outside the SDK's control. Clear caller-owned byte arrays as soon
as practical:

```ts
bestEffortClear(secretBytes);
```

Explicit provider results must be independently owned `Uint8Array` values that
do not overlap caller inputs or sibling result fields. The facade rejects
aliases as `provider-failure` without modifying caller storage. Malformed
provider-owned secret outputs are cleared before the same typed failure is
returned.

AES-KW provider results must have the exact RFC 3394 `plaintext + 8` or
`wrapped - 8` length. The facade wipes and rejects a returned typed array whose
length violates that contract. KMAC keys and customization strings are capped
at 4 KiB, contexts at 64 KiB, and outputs at 64 KiB before WASM copies are
created.

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

## Features

- Platform-agnostic cryptography APIs.
- Consistent key formats and protocol identifiers.
- Shared conformance vectors across Rust, Swift, Kotlin, and TypeScript.
- Native providers where available, WASM-backed implementations where needed.
- Typed errors and fail-closed verification behavior.
- Generated protobuf operations, algorithm identifiers, and typed wire errors
  via `@reallyme/crypto/proto`.
- JWK, multikey, multicodec, HPKE, ML-KEM, ML-DSA, Ed25519, secp256k1, X25519,
  AES-GCM, ChaCha20-Poly1305, and more.

## Protobuf Process Boundary

`processOperationResponse(request)` accepts one generated binary
`CryptoOperationRequest`. `processOperationResponseJson(requestJson)` accepts
the strict generated ProtoJSON view only for non-secret hash, verification,
key-generation, encapsulation, and sender-export requests. Both return binary
`CryptoOperationResponse` bytes, so malformed input, unsupported algorithms,
and resource-limit failures preserve their structured protobuf branch and
reason. This is the single executable structured response contract.

ProtoJSON is request-only. Decode returned binary protobuf with the generated
exports from `@reallyme/crypto/proto`. Secret-bearing operation selectors are
rejected before JSON value deserialization and must use protobuf bytes. Clear
caller-owned `Uint8Array` values after use.

## Documentation

The complete documentation, provider matrix, protocol contracts, and conformance
specifications are available in the main repository:

https://github.com/reallyme/crypto
