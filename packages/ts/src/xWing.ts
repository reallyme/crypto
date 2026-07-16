// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeKemAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes, readByteArrayProperty } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const X_WING_SECRET_KEY_LENGTH = 32;
export const X_WING_ENCAPSULATION_SEED_LENGTH = 64;
export const X_WING_SHARED_SECRET_LENGTH = 32;
export const X_WING_768_PUBLIC_KEY_LENGTH = 1_216;
export const X_WING_768_CIPHERTEXT_LENGTH = 1_120;
export const X_WING_1024_PUBLIC_KEY_LENGTH = 1_600;
export const X_WING_1024_CIPHERTEXT_LENGTH = 1_600;

export type ReallyMeXWingKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeXWingEncapsulation = Readonly<{
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}>;

type XWingSuite = Readonly<{
  publicKeyLength: number;
  ciphertextLength: number;
  generateKeypair: () => unknown;
  deriveKeypair: (secretKey: Uint8Array) => unknown;
  encapsulate: (publicKey: Uint8Array) => unknown;
  encapsulateDerand: (publicKey: Uint8Array, seed: Uint8Array) => unknown;
  decapsulate: (ciphertext: Uint8Array, secretKey: Uint8Array) => unknown;
}>;

const xWingSuite = (algorithm: ReallyMeKemAlgorithm): XWingSuite => {
  return xWingSuiteWithProvider(algorithm, requireReallyMeWasmProvider());
};

const xWingSuiteWithProvider = (
  algorithm: ReallyMeKemAlgorithm,
  provider: ReallyMeWasmProvider,
): XWingSuite => {
  switch (algorithm) {
    case "ML-KEM-512":
    case "ML-KEM-768":
    case "ML-KEM-1024":
      throw new ReallyMeCryptoError("unsupported-algorithm");
    case "X-Wing-768": {
      return {
        publicKeyLength: X_WING_768_PUBLIC_KEY_LENGTH,
        ciphertextLength: X_WING_768_CIPHERTEXT_LENGTH,
        generateKeypair: provider.xWing768GenerateKeypair,
        deriveKeypair: provider.xWing768DeriveKeypair,
        encapsulate: provider.xWing768Encapsulate,
        encapsulateDerand: provider.xWing768EncapsulateDerand,
        decapsulate: provider.xWing768Decapsulate,
      };
    }
    case "X-Wing-1024": {
      return {
        publicKeyLength: X_WING_1024_PUBLIC_KEY_LENGTH,
        ciphertextLength: X_WING_1024_CIPHERTEXT_LENGTH,
        generateKeypair: provider.xWing1024GenerateKeypair,
        deriveKeypair: provider.xWing1024DeriveKeypair,
        encapsulate: provider.xWing1024Encapsulate,
        encapsulateDerand: provider.xWing1024EncapsulateDerand,
        decapsulate: provider.xWing1024Decapsulate,
      };
    }
  }
};

const readKeyPair = (value: unknown, suite: XWingSuite): ReallyMeXWingKeyPair => ({
  publicKey: readByteArrayProperty(value, "publicKey", suite.publicKeyLength),
  secretKey: readByteArrayProperty(value, "secretKey", X_WING_SECRET_KEY_LENGTH),
});

const readEncapsulation = (
  value: unknown,
  suite: XWingSuite,
): ReallyMeXWingEncapsulation => ({
  ciphertext: readByteArrayProperty(value, "ciphertext", suite.ciphertextLength),
  sharedSecret: readByteArrayProperty(value, "sharedSecret", X_WING_SHARED_SECRET_LENGTH),
});

export const ReallyMeXWing = {
  generateKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeXWingKeyPair {
    const suite = xWingSuite(algorithm);
    return readKeyPair(suite.generateKeypair(), suite);
  },

  generateKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
  ): ReallyMeXWingKeyPair {
    const suite = xWingSuiteWithProvider(algorithm, provider);
    return readKeyPair(suite.generateKeypair(), suite);
  },

  deriveKeyPair(
    algorithm: ReallyMeKemAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeXWingKeyPair {
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    const suite = xWingSuite(algorithm);
    return readKeyPair(suite.deriveKeypair(secretKey), suite);
  },

  deriveKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeXWingKeyPair {
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    const suite = xWingSuiteWithProvider(algorithm, provider);
    return readKeyPair(suite.deriveKeypair(secretKey), suite);
  },

  encapsulate(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeXWingEncapsulation {
    const suite = xWingSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite);
  },

  encapsulateWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeXWingEncapsulation {
    const suite = xWingSuiteWithProvider(algorithm, provider);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite);
  },

  decapsulate(
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = xWingSuite(algorithm);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    const sharedSecret = suite.decapsulate(ciphertext, secretKey);
    if (!(sharedSecret instanceof Uint8Array)) {
      throw new ReallyMeCryptoError("provider-failure");
    }
    ensureBytes(sharedSecret, X_WING_SHARED_SECRET_LENGTH);
    return sharedSecret;
  },

  decapsulateWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = xWingSuiteWithProvider(algorithm, provider);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    const sharedSecret = suite.decapsulate(ciphertext, secretKey);
    if (!(sharedSecret instanceof Uint8Array)) {
      throw new ReallyMeCryptoError("provider-failure");
    }
    ensureBytes(sharedSecret, X_WING_SHARED_SECRET_LENGTH);
    return sharedSecret;
  },

} as const;

export const encapsulateXWingDeterministicallyForTest = (
  algorithm: ReallyMeKemAlgorithm,
  publicKey: Uint8Array,
  seed: Uint8Array,
): ReallyMeXWingEncapsulation => {
  const suite = xWingSuite(algorithm);
  ensureBytes(publicKey, suite.publicKeyLength);
  ensureBytes(seed, X_WING_ENCAPSULATION_SEED_LENGTH);
  return readEncapsulation(suite.encapsulateDerand(publicKey, seed), suite);
};

export const encapsulateXWingDeterministicallyWithProviderForTest = (
  provider: ReallyMeWasmProvider,
  algorithm: ReallyMeKemAlgorithm,
  publicKey: Uint8Array,
  seed: Uint8Array,
): ReallyMeXWingEncapsulation => {
  const suite = xWingSuiteWithProvider(algorithm, provider);
  ensureBytes(publicKey, suite.publicKeyLength);
  ensureBytes(seed, X_WING_ENCAPSULATION_SEED_LENGTH);
  return readEncapsulation(suite.encapsulateDerand(publicKey, seed), suite);
};
