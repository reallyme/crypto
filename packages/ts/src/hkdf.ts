// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";

export const HKDF_MIN_INPUT_KEY_MATERIAL_LENGTH = 1;
export const HKDF_MAX_INPUT_LENGTH = 4096;
export const HKDF_MIN_OUTPUT_LENGTH = 1;
export const HKDF_MAX_OUTPUT_LENGTH = 4096;

export const ReallyMeHkdf = {
  deriveSha256(
    inputKeyMaterial: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    validate(inputKeyMaterial, salt, info, outputLength);
    return hkdf(sha256, inputKeyMaterial, salt, info, outputLength);
  },
} as const;

function validate(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  outputLength: number,
): void {
  if (
    inputKeyMaterial.length < HKDF_MIN_INPUT_KEY_MATERIAL_LENGTH ||
    inputKeyMaterial.length > HKDF_MAX_INPUT_LENGTH ||
    salt.length > HKDF_MAX_INPUT_LENGTH ||
    info.length > HKDF_MAX_INPUT_LENGTH ||
    !Number.isInteger(outputLength) ||
    outputLength < HKDF_MIN_OUTPUT_LENGTH ||
    outputLength > HKDF_MAX_OUTPUT_LENGTH
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
}
