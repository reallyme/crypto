// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import { ensureByteArray } from "./validateBytes.js";

const SEC1_COMPRESSED_EVEN_PREFIX = 0x02;
const SEC1_COMPRESSED_ODD_PREFIX = 0x03;
const SEC1_UNCOMPRESSED_PREFIX = 0x04;

// Keep accepted representations independent of a provider's point parser.
// The caller must still validate curve membership after this shape check.
export function ensureStandardSec1PublicKey(
  value: unknown,
  compressedLength: number,
  uncompressedLength: number,
): asserts value is Uint8Array {
  ensureByteArray(value);
  const prefix = value[0];
  const compressed = value.length === compressedLength &&
    (prefix === SEC1_COMPRESSED_EVEN_PREFIX || prefix === SEC1_COMPRESSED_ODD_PREFIX);
  const uncompressed = value.length === uncompressedLength && prefix === SEC1_UNCOMPRESSED_PREFIX;
  // Admit only standard SEC1 shapes. Curve membership and non-identity checks
  // remain with the provider so accepting uncompressed keys does not also
  // admit hybrid tags, compact aliases, or points on a different curve.
  if (!compressed && !uncompressed) {
    throw new ReallyMeCryptoError("invalid-input");
  }
}
