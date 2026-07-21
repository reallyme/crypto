// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeKemAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureBytes,
  readIndependentByteArrayProperty,
  readIndependentProviderBytes,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const X_WING_SECRET_KEY_LENGTH = 32;
export const X_WING_SHARED_SECRET_LENGTH = 32;
export const X_WING_768_PUBLIC_KEY_LENGTH = 1_216;
export const X_WING_768_CIPHERTEXT_LENGTH = 1_120;

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
        decapsulate: provider.xWing768Decapsulate,
      };
    }
  }
};

const readKeyPair = (
  value: unknown,
  suite: XWingSuite,
  inputs: ReadonlyArray<Uint8Array> = [],
): ReallyMeXWingKeyPair => {
  const publicKey = readIndependentByteArrayProperty(
    value,
    "publicKey",
    suite.publicKeyLength,
    inputs,
  );
  const secretKey = readIndependentByteArrayProperty(
    value,
    "secretKey",
    X_WING_SECRET_KEY_LENGTH,
    [...inputs, publicKey],
  );
  return { publicKey, secretKey };
};

const readEncapsulation = (
  value: unknown,
  suite: XWingSuite,
  inputs: ReadonlyArray<Uint8Array>,
): ReallyMeXWingEncapsulation => {
  const ciphertext = readIndependentByteArrayProperty(
    value,
    "ciphertext",
    suite.ciphertextLength,
    inputs,
  );
  const sharedSecret = readIndependentByteArrayProperty(
    value,
    "sharedSecret",
    X_WING_SHARED_SECRET_LENGTH,
    [...inputs, ciphertext],
  );
  return { ciphertext, sharedSecret };
};

const readSharedSecret = (
  value: unknown,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  return readIndependentProviderBytes(value, X_WING_SHARED_SECRET_LENGTH, inputs);
};

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
    return readKeyPair(suite.deriveKeypair(secretKey), suite, [secretKey]);
  },

  deriveKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeXWingKeyPair {
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    const suite = xWingSuiteWithProvider(algorithm, provider);
    return readKeyPair(suite.deriveKeypair(secretKey), suite, [secretKey]);
  },

  encapsulate(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeXWingEncapsulation {
    const suite = xWingSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite, [publicKey]);
  },

  encapsulateWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeXWingEncapsulation {
    const suite = xWingSuiteWithProvider(algorithm, provider);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite, [publicKey]);
  },

  decapsulate(
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = xWingSuite(algorithm);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, X_WING_SECRET_KEY_LENGTH);
    return readSharedSecret(
      suite.decapsulate(ciphertext, secretKey),
      [ciphertext, secretKey],
    );
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
    return readSharedSecret(
      suite.decapsulate(ciphertext, secretKey),
      [ciphertext, secretKey],
    );
  },
} as const;
