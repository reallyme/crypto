// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureByteArray,
  ensureIndependentByteArray,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
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
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  // A provider result must have independent ownership. Check overlap before
  // clearing malformed output so validation cannot erase caller-owned input.
  ensureIndependentByteArray(value, inputs);
  if (value.length !== outputLength) {
    value.fill(0);
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
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
    validate(key, context, customization, outputLength);
    return requireDerivedKey(
      provider.kmac256Derive(key, context, customization, outputLength),
      outputLength,
      [key, context, customization],
    );
  },
} as const;
