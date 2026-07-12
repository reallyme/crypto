// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeAeadAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export const AEAD_KEY_LENGTH = 32;
export const AES_128_GCM_KEY_LENGTH = 16;
export const AES_192_GCM_KEY_LENGTH = 24;
export const AES_256_GCM_KEY_LENGTH = 32;
export const AEAD_NONCE_LENGTH = 12;
export const XCHACHA20_POLY1305_NONCE_LENGTH = 24;
export const AEAD_TAG_LENGTH = 16;

type AeadFunction = (
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  text: Uint8Array,
) => unknown;

type AeadSuite = Readonly<{
  keyLength: number;
  nonceLength: number;
  seal: AeadFunction;
  open: AeadFunction;
}>;

const aeadSuite = (algorithm: ReallyMeAeadAlgorithm): AeadSuite => {
  const provider = requireReallyMeWasmProvider();
  switch (algorithm) {
    case "AES-128-GCM":
      return {
        keyLength: AES_128_GCM_KEY_LENGTH,
        nonceLength: AEAD_NONCE_LENGTH,
        seal: provider.aes128GcmSeal,
        open: provider.aes128GcmOpen,
      };
    case "AES-192-GCM":
      return {
        keyLength: AES_192_GCM_KEY_LENGTH,
        nonceLength: AEAD_NONCE_LENGTH,
        seal: provider.aes192GcmSeal,
        open: provider.aes192GcmOpen,
      };
    case "AES-256-GCM":
      return {
        keyLength: AES_256_GCM_KEY_LENGTH,
        nonceLength: AEAD_NONCE_LENGTH,
        seal: provider.aes256GcmSeal,
        open: provider.aes256GcmOpen,
      };
    case "AES-256-GCM-SIV":
      return {
        keyLength: AES_256_GCM_KEY_LENGTH,
        nonceLength: AEAD_NONCE_LENGTH,
        seal: provider.aes256GcmSivSeal,
        open: provider.aes256GcmSivOpen,
      };
    case "ChaCha20-Poly1305":
      return {
        keyLength: AES_256_GCM_KEY_LENGTH,
        nonceLength: AEAD_NONCE_LENGTH,
        seal: provider.chacha20Poly1305Seal,
        open: provider.chacha20Poly1305Open,
      };
    case "XChaCha20-Poly1305":
      return {
        keyLength: AES_256_GCM_KEY_LENGTH,
        nonceLength: XCHACHA20_POLY1305_NONCE_LENGTH,
        seal: provider.xchacha20Poly1305Seal,
        open: provider.xchacha20Poly1305Open,
      };
  }
};

const requireBytesOutput = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

export const ReallyMeAead = {
  seal(
    algorithm: ReallyMeAeadAlgorithm,
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Uint8Array {
    const suite = aeadSuite(algorithm);
    ensureBytes(key, suite.keyLength);
    ensureBytes(nonce, suite.nonceLength);
    return requireBytesOutput(suite.seal(key, nonce, aad, plaintext));
  },

  open(
    algorithm: ReallyMeAeadAlgorithm,
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertextWithTag: Uint8Array,
  ): Uint8Array {
    const suite = aeadSuite(algorithm);
    ensureBytes(key, suite.keyLength);
    ensureBytes(nonce, suite.nonceLength);
    if (ciphertextWithTag.length < AEAD_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return requireBytesOutput(suite.open(key, nonce, aad, ciphertextWithTag));
  },
} as const;
