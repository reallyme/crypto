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

export const ML_KEM_512_PUBLIC_KEY_LENGTH = 800;
export const ML_KEM_512_CIPHERTEXT_LENGTH = 768;
export const ML_KEM_768_PUBLIC_KEY_LENGTH = 1_184;
export const ML_KEM_768_CIPHERTEXT_LENGTH = 1_088;
export const ML_KEM_1024_PUBLIC_KEY_LENGTH = 1_568;
export const ML_KEM_1024_CIPHERTEXT_LENGTH = 1_568;
export const ML_KEM_SECRET_KEY_LENGTH = 64;
export const ML_KEM_SHARED_SECRET_LENGTH = 32;

export type ReallyMeMlKemKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeMlKemEncapsulation = Readonly<{
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}>;

type MlKemSuite = Readonly<{
  publicKeyLength: number;
  ciphertextLength: number;
  generateKeyPair: () => unknown;
  deriveKeyPair: (secretKey: Uint8Array) => unknown;
  encapsulate: (publicKey: Uint8Array) => unknown;
  decapsulate: (ciphertext: Uint8Array, secretKey: Uint8Array) => unknown;
}>;

const mlKemSuite = (algorithm: ReallyMeKemAlgorithm): MlKemSuite => {
  const provider = requireReallyMeWasmProvider();
  return mlKemSuiteWithProvider(algorithm, provider);
};

const mlKemSuiteWithProvider = (
  algorithm: ReallyMeKemAlgorithm,
  provider: ReallyMeWasmProvider,
): MlKemSuite => {
  switch (algorithm) {
    case "ML-KEM-512":
      return {
        publicKeyLength: ML_KEM_512_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_512_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem512GenerateKeypair,
        deriveKeyPair: provider.mlKem512DeriveKeypair,
        encapsulate: provider.mlKem512Encapsulate,
        decapsulate: provider.mlKem512Decapsulate,
      };
    case "ML-KEM-768":
      return {
        publicKeyLength: ML_KEM_768_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_768_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem768GenerateKeypair,
        deriveKeyPair: provider.mlKem768DeriveKeypair,
        encapsulate: provider.mlKem768Encapsulate,
        decapsulate: provider.mlKem768Decapsulate,
      };
    case "ML-KEM-1024":
      return {
        publicKeyLength: ML_KEM_1024_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_1024_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem1024GenerateKeypair,
        deriveKeyPair: provider.mlKem1024DeriveKeypair,
        encapsulate: provider.mlKem1024Encapsulate,
        decapsulate: provider.mlKem1024Decapsulate,
      };
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const readKeyPair = (
  value: unknown,
  suite: MlKemSuite,
  inputs: ReadonlyArray<Uint8Array> = [],
): ReallyMeMlKemKeyPair => {
  const publicKey = readIndependentByteArrayProperty(
    value,
    "publicKey",
    suite.publicKeyLength,
    inputs,
  );
  const secretKey = readIndependentByteArrayProperty(
    value,
    "secretKey",
    ML_KEM_SECRET_KEY_LENGTH,
    [...inputs, publicKey],
  );
  return { publicKey, secretKey };
};

const readEncapsulation = (
  value: unknown,
  suite: MlKemSuite,
  inputs: ReadonlyArray<Uint8Array>,
): ReallyMeMlKemEncapsulation => {
  const ciphertext = readIndependentByteArrayProperty(
    value,
    "ciphertext",
    suite.ciphertextLength,
    inputs,
  );
  const sharedSecret = readIndependentByteArrayProperty(
    value,
    "sharedSecret",
    ML_KEM_SHARED_SECRET_LENGTH,
    [...inputs, ciphertext],
  );
  return { ciphertext, sharedSecret };
};

const readSharedSecret = (
  value: unknown,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  return readIndependentProviderBytes(value, ML_KEM_SHARED_SECRET_LENGTH, inputs);
};

export const ReallyMeMlKem = {
  generateKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeMlKemKeyPair {
    const suite = mlKemSuite(algorithm);
    return readKeyPair(suite.generateKeyPair(), suite);
  },

  generateKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
  ): ReallyMeMlKemKeyPair {
    const suite = mlKemSuiteWithProvider(algorithm, provider);
    return readKeyPair(suite.generateKeyPair(), suite);
  },

  deriveKeyPair(algorithm: ReallyMeKemAlgorithm, secretKey: Uint8Array): ReallyMeMlKemKeyPair {
    // Import an existing FIPS 203 seed-form secret and reconstruct its public
    // key. Do not feed passwords or other low-entropy material here.
    const suite = mlKemSuite(algorithm);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
    return readKeyPair(suite.deriveKeyPair(secretKey), suite, [secretKey]);
  },

  deriveKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeMlKemKeyPair {
    const suite = mlKemSuiteWithProvider(algorithm, provider);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
    return readKeyPair(suite.deriveKeyPair(secretKey), suite, [secretKey]);
  },

  encapsulate(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeMlKemEncapsulation {
    const suite = mlKemSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite, [publicKey]);
  },

  encapsulateWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeMlKemEncapsulation {
    const suite = mlKemSuiteWithProvider(algorithm, provider);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite, [publicKey]);
  },

  decapsulate(
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = mlKemSuite(algorithm);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
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
    const suite = mlKemSuiteWithProvider(algorithm, provider);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
    return readSharedSecret(
      suite.decapsulate(ciphertext, secretKey),
      [ciphertext, secretKey],
    );
  },
} as const;
