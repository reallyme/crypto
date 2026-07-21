// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureByteArray,
  ensureBytes,
  ensureIndependentByteArray,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeKeyWrapAlgorithm } from "./algorithms.js";

export const AES_128_KW_KEK_LENGTH = 16;
export const AES_192_KW_KEK_LENGTH = 24;
export const AES_256_KW_KEK_LENGTH = 32;
export const AES_KW_BLOCK_LENGTH = 8;
export const AES_KW_INTEGRITY_CHECK_LENGTH = 8;
export const AES_KW_MIN_KEY_DATA_LENGTH = 16;
export const AES_KW_MIN_WRAPPED_KEY_LENGTH =
  AES_KW_MIN_KEY_DATA_LENGTH + AES_KW_INTEGRITY_CHECK_LENGTH;
export const AES_KW_MAX_KEY_DATA_LENGTH = 4_096;

const validateKeyDataLength = (length: number): void => {
  if (
    length < AES_KW_MIN_KEY_DATA_LENGTH ||
    length > AES_KW_MAX_KEY_DATA_LENGTH ||
    length % AES_KW_BLOCK_LENGTH !== 0
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const validateWrappedKeyLength = (length: number): void => {
  const maxWrappedLength = AES_KW_MAX_KEY_DATA_LENGTH + AES_KW_INTEGRITY_CHECK_LENGTH;
  if (
    length < AES_KW_MIN_WRAPPED_KEY_LENGTH ||
    length > maxWrappedLength ||
    length % AES_KW_BLOCK_LENGTH !== 0
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const requireBytesOutput = (
  value: unknown,
  expectedLength: number,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  // Reject aliases before wiping malformed output. Otherwise a provider could
  // return a caller-owned key/input view and make validation erase that input.
  ensureIndependentByteArray(value, inputs);
  if (value.length !== expectedLength) {
    value.fill(0);
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

const kekLengthForAlgorithm = (algorithm: ReallyMeKeyWrapAlgorithm): number => {
  switch (algorithm) {
    case "AES-128-KW":
      return AES_128_KW_KEK_LENGTH;
    case "AES-192-KW":
      return AES_192_KW_KEK_LENGTH;
    case "AES-256-KW":
      return AES_256_KW_KEK_LENGTH;
  }
};

const wrapFunctionForAlgorithm = (
  provider: ReallyMeWasmProvider,
  algorithm: ReallyMeKeyWrapAlgorithm,
): ((wrappingKey: Uint8Array, keyToWrap: Uint8Array) => unknown) => {
  switch (algorithm) {
    case "AES-128-KW":
      return provider.aes128KwWrapKey;
    case "AES-192-KW":
      return provider.aes192KwWrapKey;
    case "AES-256-KW":
      return provider.aes256KwWrapKey;
  }
};

const unwrapFunctionForAlgorithm = (
  provider: ReallyMeWasmProvider,
  algorithm: ReallyMeKeyWrapAlgorithm,
): ((wrappingKey: Uint8Array, wrappedKey: Uint8Array) => unknown) => {
  switch (algorithm) {
    case "AES-128-KW":
      return provider.aes128KwUnwrapKey;
    case "AES-192-KW":
      return provider.aes192KwUnwrapKey;
    case "AES-256-KW":
      return provider.aes256KwUnwrapKey;
  }
};

const wrapKey = (
  algorithm: ReallyMeKeyWrapAlgorithm,
  wrappingKey: Uint8Array,
  keyToWrap: Uint8Array,
): Uint8Array => {
  ensureBytes(wrappingKey, kekLengthForAlgorithm(algorithm));
  ensureByteArray(keyToWrap);
  validateKeyDataLength(keyToWrap.length);
  return requireBytesOutput(
    wrapFunctionForAlgorithm(requireReallyMeWasmProvider(), algorithm)(
      wrappingKey,
      keyToWrap,
    ),
    keyToWrap.length + AES_KW_INTEGRITY_CHECK_LENGTH,
    [wrappingKey, keyToWrap],
  );
};

const wrapKeyWithProvider = (
  algorithm: ReallyMeKeyWrapAlgorithm,
  provider: ReallyMeWasmProvider,
  wrappingKey: Uint8Array,
  keyToWrap: Uint8Array,
): Uint8Array => {
  ensureBytes(wrappingKey, kekLengthForAlgorithm(algorithm));
  ensureByteArray(keyToWrap);
  validateKeyDataLength(keyToWrap.length);
  return requireBytesOutput(
    wrapFunctionForAlgorithm(provider, algorithm)(wrappingKey, keyToWrap),
    keyToWrap.length + AES_KW_INTEGRITY_CHECK_LENGTH,
    [wrappingKey, keyToWrap],
  );
};

const unwrapKey = (
  algorithm: ReallyMeKeyWrapAlgorithm,
  wrappingKey: Uint8Array,
  wrappedKey: Uint8Array,
): Uint8Array => {
  ensureBytes(wrappingKey, kekLengthForAlgorithm(algorithm));
  ensureByteArray(wrappedKey);
  validateWrappedKeyLength(wrappedKey.length);
  return requireBytesOutput(
    unwrapFunctionForAlgorithm(requireReallyMeWasmProvider(), algorithm)(
      wrappingKey,
      wrappedKey,
    ),
    wrappedKey.length - AES_KW_INTEGRITY_CHECK_LENGTH,
    [wrappingKey, wrappedKey],
  );
};

const unwrapKeyWithProvider = (
  algorithm: ReallyMeKeyWrapAlgorithm,
  provider: ReallyMeWasmProvider,
  wrappingKey: Uint8Array,
  wrappedKey: Uint8Array,
): Uint8Array => {
  ensureBytes(wrappingKey, kekLengthForAlgorithm(algorithm));
  ensureByteArray(wrappedKey);
  validateWrappedKeyLength(wrappedKey.length);
  return requireBytesOutput(
    unwrapFunctionForAlgorithm(provider, algorithm)(wrappingKey, wrappedKey),
    wrappedKey.length - AES_KW_INTEGRITY_CHECK_LENGTH,
    [wrappingKey, wrappedKey],
  );
};

export const ReallyMeAesKw = {
  wrapKey,
  wrapKeyWithProvider,
  unwrapKey,
  unwrapKeyWithProvider,
} as const;
