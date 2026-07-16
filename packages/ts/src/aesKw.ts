// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

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

const requireBytesOutput = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

export const ReallyMeAesKw = {
  wrapKey(wrappingKey: Uint8Array, keyToWrap: Uint8Array): Uint8Array {
    ensureBytes(wrappingKey, AES_256_KW_KEK_LENGTH);
    validateKeyDataLength(keyToWrap.length);
    return requireBytesOutput(
      requireReallyMeWasmProvider().aes256KwWrapKey(wrappingKey, keyToWrap),
    );
  },

  wrapKeyWithProvider(
    provider: ReallyMeWasmProvider,
    wrappingKey: Uint8Array,
    keyToWrap: Uint8Array,
  ): Uint8Array {
    ensureBytes(wrappingKey, AES_256_KW_KEK_LENGTH);
    validateKeyDataLength(keyToWrap.length);
    return requireBytesOutput(provider.aes256KwWrapKey(wrappingKey, keyToWrap));
  },

  unwrapKey(wrappingKey: Uint8Array, wrappedKey: Uint8Array): Uint8Array {
    ensureBytes(wrappingKey, AES_256_KW_KEK_LENGTH);
    validateWrappedKeyLength(wrappedKey.length);
    return requireBytesOutput(
      requireReallyMeWasmProvider().aes256KwUnwrapKey(wrappingKey, wrappedKey),
    );
  },

  unwrapKeyWithProvider(
    provider: ReallyMeWasmProvider,
    wrappingKey: Uint8Array,
    wrappedKey: Uint8Array,
  ): Uint8Array {
    ensureBytes(wrappingKey, AES_256_KW_KEK_LENGTH);
    validateWrappedKeyLength(wrappedKey.length);
    return requireBytesOutput(provider.aes256KwUnwrapKey(wrappingKey, wrappedKey));
  },
} as const;
