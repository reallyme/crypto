// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { installReallyMeCodecWasmProvider } from "@reallyme/codec";
import {
  base58btcDecode,
  base58btcEncode,
  base64Decode,
  base64Encode,
  base64urlDecode,
  base64urlEncode,
  bindingTypeMatchesCodec,
  bytesToLowerHex,
  canonicalizeJson,
  dagCborCodecCode,
  dagCborComputeCid,
  dagCborMultihash,
  dagCborSha256ContentHash,
  initSync,
  isValidCidString,
  lowerHexToBytes,
  multibaseBase58btcEncode,
  multibaseBase64urlEncode,
  multibaseDecode,
  multicodecStripPrefix,
  multikeyEncode,
  processOperation,
  processOperationJson,
  requireSupportedMulticodec,
  tryParseCid,
  validateKeyBinding,
} from "@reallyme/codec/wasm/reallyme_codec_wasm.js";

const codecWasmProvider = Object.freeze({
  base58btcDecode,
  base58btcEncode,
  base64Decode,
  base64Encode,
  base64urlDecode,
  base64urlEncode,
  bindingTypeMatchesCodec,
  bytesToLowerHex,
  canonicalizeJson,
  dagCborCodecCode,
  dagCborComputeCid,
  dagCborMultihash,
  dagCborSha256ContentHash,
  isValidCidString,
  lowerHexToBytes,
  multibaseBase58btcEncode,
  multibaseBase64urlEncode,
  multibaseDecode,
  multicodecStripPrefix,
  multikeyEncode,
  processOperation,
  processOperationJson,
  requireSupportedMulticodec,
  tryParseCid,
  validateKeyBinding,
});

// The explicit object prevents newly generated WASM exports from silently
// becoming part of the installed provider surface without review.
export const installCodecWasmProvider = (wasmBytes) => {
  initSync({ module: wasmBytes });
  installReallyMeCodecWasmProvider(codecWasmProvider);
};
