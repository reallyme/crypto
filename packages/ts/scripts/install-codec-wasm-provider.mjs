// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { installCodecWasmProvider } from "./codec-wasm-provider.mjs";

// Conformance scripts import the built Crypto facade directly, so they must
// install the same published Codec provider that normal package consumers use.
// Keeping this setup beside the package makes Node resolve the exact Codec
// instance imported by `dist/jwk.js`, rather than a second test-only copy.
const codecWasmBytes = readFileSync(
  new URL(import.meta.resolve("@reallyme/codec/wasm/reallyme_codec_wasm_bg.wasm")),
);
installCodecWasmProvider(codecWasmBytes);
