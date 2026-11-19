# @reallyme/crypto

[![npm](https://img.shields.io/npm/v/@reallyme/crypto?label=npm&color=2563eb)](https://www.npmjs.com/package/@reallyme/crypto)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/reallyme/crypto/blob/main/LICENSE)

`@reallyme/crypto` is the TypeScript SDK for ReallyMe Crypto. It provides typed,
synchronous APIs for Node.js and browsers, with explicit JavaScript and
package-owned WASM providers.

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
malformed input or an invalid signature.

`ReallyMeP256Ecdsa` normalizes canonical DER or fixed-width 64-byte `r || s`
signatures to low-S form for HSM and platform-keystore integrations. The helper
does not replace verification against the signed message.

KDF facade selectors are family-specific: `deriveKey` accepts only PBKDF2,
`deriveHkdf` accepts only HKDF, and the JWA Concat KDF and KMAC methods accept
their exact selectors. Argon2id uses the dedicated `deriveArgon2id` route with
an immutable profile version rather than an iteration count.

## Post-Quantum and WASM

Hashes and selected classical asymmetric operations use the pinned JavaScript
providers. ML-KEM, ML-DSA, SLH-DSA, X-Wing, Argon2id, HPKE and other
Rust-backed operations require the
bundled WASM module. Initialize it before calling those methods.

Use `installReallyMeWasmProvider` for the package-level facade or
`createReallyMeCrypto` for an isolated instance. Explicit facades reject
structural provider objects, copied hooks and proxies with `provider-failure`.
Only the package's initialized WASM module is accepted. JWK/JWKS helpers also
require the Codec WASM provider.

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

P-256, P-384, and P-521 ECDSA verification accepts standard compressed SEC1
keys (`0x02` or `0x03`) and uncompressed SEC1 keys (`0x04`) at the curve's exact
width. Key generation and public-key derivation continue to emit compressed
keys. Compact (`0x05`) and hybrid (`0x06` or `0x07`) encodings are rejected.

## Raw WASM Module Contract

The raw `@reallyme/crypto/wasm/reallyme_crypto_wasm.js` export is an internal
provider artifact for installing or constructing `ReallyMeWasmProvider`
instances. Direct raw WASM calls are unsupported for application logic. Use the
typed TypeScript facades, which validate caller inputs, numeric ranges, provider
outputs, aliasing, and cleanup before invoking the raw module.

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

## Secret buffers

Rust-owned secret buffers are zeroized by the Rust implementation and WASM
adapters. JavaScript `Uint8Array` values are best-effort only: engines, WASM
marshalling, providers, protobuf codecs, debuggers, and crash reporters can
create copies outside the SDK's control. Clear caller-owned byte arrays as soon
as practical:

```ts
import { bestEffortClear } from "@reallyme/crypto";

bestEffortClear(secretBytes);
```

KMAC keys and customization strings are capped at 4 KiB, contexts and outputs
at 64 KiB.

Do not move private keys, passwords, plaintext, shared secrets, or derived keys
through strings or JSON paths.

## Protobuf Process Boundary

`processOperationResponse(request)` accepts one generated binary
`CryptoOperationRequest`. `processOperationResponseJson(requestJson)` accepts
the strict generated ProtoJSON view only for non-secret hash, verification,
key-generation, encapsulation, and sender-export requests. Both return binary
`CryptoOperationResponse` bytes, so malformed input, unsupported algorithms,
and resource-limit failures preserve their structured protobuf branch and
reason.

ProtoJSON is request-only. Decode returned binary protobuf with the generated
exports from `@reallyme/crypto/proto`. Secret-bearing operation selectors are
rejected before JSON value deserialization and must use protobuf bytes.

## Documentation

See the [provider manifest](https://github.com/reallyme/crypto/blob/main/provider_manifest.json)
and [wire API](https://github.com/reallyme/crypto/blob/main/docs/protobuf.md).

## License

Licensed under either the MIT License or the Apache License, Version 2.0,
at your option. See [LICENSE](https://github.com/reallyme/crypto/blob/main/LICENSE). Third-party components retain
their own licenses and notices.
