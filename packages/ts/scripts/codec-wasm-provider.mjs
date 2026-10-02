// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { installReallyMeCodecWasmProvider } from "@reallyme/codec";

const codecWasm = await import("@reallyme/codec/wasm/reallyme_codec_wasm.js");

// Codec validates the generated module's identity and initialization before
// accepting it. Pass the namespace itself so that check cannot be bypassed by
// a structural copy of its exports.
export const installCodecWasmProvider = (wasmBytes) => {
  codecWasm.initSync({ module: wasmBytes });
  installReallyMeCodecWasmProvider(codecWasm);
};
