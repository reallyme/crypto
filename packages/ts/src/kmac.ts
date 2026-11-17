// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureByteArray,
  readIndependentProviderBytes,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider, requireTrustedReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const KMAC256_MIN_KEY_LENGTH = 32;
export const KMAC256_MAX_KEY_LENGTH = 4_096;
export const KMAC256_MAX_CONTEXT_LENGTH = 65_536;
export const KMAC256_MAX_CUSTOMIZATION_LENGTH = 4_096;
export const KMAC256_MIN_OUTPUT_LENGTH = 1;
export const KMAC256_MAX_OUTPUT_LENGTH = 65_536;

const validate = (
  key: Uint8Array,
  context: Uint8Array,
  customization: Uint8Array,
  outputLength: number,
): void => {
  ensureByteArray(key);
  ensureByteArray(context);
  ensureByteArray(customization);
  if (
    key.length < KMAC256_MIN_KEY_LENGTH ||
    key.length > KMAC256_MAX_KEY_LENGTH ||
    context.length > KMAC256_MAX_CONTEXT_LENGTH ||
    customization.length > KMAC256_MAX_CUSTOMIZATION_LENGTH ||
    !Number.isInteger(outputLength) ||
    outputLength < KMAC256_MIN_OUTPUT_LENGTH ||
    outputLength > KMAC256_MAX_OUTPUT_LENGTH
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const requireDerivedKey = (
  value: unknown,
  outputLength: number,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  return readIndependentProviderBytes(value, outputLength, inputs);
};

export const ReallyMeKmac = {
  deriveKmac256(
    key: Uint8Array,
    context: Uint8Array,
    customization: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    validate(key, context, customization, outputLength);
    return requireDerivedKey(
      requireReallyMeWasmProvider().kmac256Derive(
        key,
        context,
        customization,
        outputLength,
      ),
      outputLength,
      [key, context, customization],
    );
  },

  deriveKmac256WithProvider(
    provider: ReallyMeWasmProvider,
    key: Uint8Array,
    context: Uint8Array,
    customization: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    requireTrustedReallyMeWasmProvider(provider);
    validate(key, context, customization, outputLength);
    return requireDerivedKey(
      provider.kmac256Derive(key, context, customization, outputLength),
      outputLength,
      [key, context, customization],
    );
  },
} as const;
