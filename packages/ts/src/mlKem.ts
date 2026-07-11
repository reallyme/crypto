// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeKemAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes, readByteArrayProperty } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export const ML_KEM_512_PUBLIC_KEY_LENGTH = 800;
export const ML_KEM_512_CIPHERTEXT_LENGTH = 768;
export const ML_KEM_768_PUBLIC_KEY_LENGTH = 1_184;
export const ML_KEM_768_CIPHERTEXT_LENGTH = 1_088;
export const ML_KEM_1024_PUBLIC_KEY_LENGTH = 1_568;
export const ML_KEM_1024_CIPHERTEXT_LENGTH = 1_568;
export const ML_KEM_SECRET_KEY_LENGTH = 64;
export const ML_KEM_ENCAPSULATION_RANDOMNESS_LENGTH = 32;
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
  encapsulateDerand: (publicKey: Uint8Array, randomness: Uint8Array) => unknown;
  decapsulate: (ciphertext: Uint8Array, secretKey: Uint8Array) => unknown;
}>;

const mlKemSuite = (algorithm: ReallyMeKemAlgorithm): MlKemSuite => {
  const provider = requireReallyMeWasmProvider();
  switch (algorithm) {
    case "ML-KEM-512":
      return {
        publicKeyLength: ML_KEM_512_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_512_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem512GenerateKeypair,
        deriveKeyPair: provider.mlKem512DeriveKeypair,
        encapsulate: provider.mlKem512Encapsulate,
        encapsulateDerand: provider.mlKem512EncapsulateDerand,
        decapsulate: provider.mlKem512Decapsulate,
      };
    case "ML-KEM-768":
      return {
        publicKeyLength: ML_KEM_768_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_768_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem768GenerateKeypair,
        deriveKeyPair: provider.mlKem768DeriveKeypair,
        encapsulate: provider.mlKem768Encapsulate,
        encapsulateDerand: provider.mlKem768EncapsulateDerand,
        decapsulate: provider.mlKem768Decapsulate,
      };
    case "ML-KEM-1024":
      return {
        publicKeyLength: ML_KEM_1024_PUBLIC_KEY_LENGTH,
        ciphertextLength: ML_KEM_1024_CIPHERTEXT_LENGTH,
        generateKeyPair: provider.mlKem1024GenerateKeypair,
        deriveKeyPair: provider.mlKem1024DeriveKeypair,
        encapsulate: provider.mlKem1024Encapsulate,
        encapsulateDerand: provider.mlKem1024EncapsulateDerand,
        decapsulate: provider.mlKem1024Decapsulate,
      };
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const readKeyPair = (value: unknown, suite: MlKemSuite): ReallyMeMlKemKeyPair => ({
  publicKey: readByteArrayProperty(value, "publicKey", suite.publicKeyLength),
  secretKey: readByteArrayProperty(value, "secretKey", ML_KEM_SECRET_KEY_LENGTH),
});

const readEncapsulation = (
  value: unknown,
  suite: MlKemSuite,
): ReallyMeMlKemEncapsulation => ({
  ciphertext: readByteArrayProperty(value, "ciphertext", suite.ciphertextLength),
  sharedSecret: readByteArrayProperty(value, "sharedSecret", ML_KEM_SHARED_SECRET_LENGTH),
});

const readSharedSecret = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  ensureBytes(value, ML_KEM_SHARED_SECRET_LENGTH);
  return value;
};

export const ReallyMeMlKem = {
  generateKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeMlKemKeyPair {
    const suite = mlKemSuite(algorithm);
    return readKeyPair(suite.generateKeyPair(), suite);
  },

  deriveKeyPair(algorithm: ReallyMeKemAlgorithm, secretKey: Uint8Array): ReallyMeMlKemKeyPair {
    // Import an existing FIPS 203 seed-form secret and reconstruct its public
    // key. Do not feed passwords or other low-entropy material here.
    const suite = mlKemSuite(algorithm);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
    return readKeyPair(suite.deriveKeyPair(secretKey), suite);
  },

  encapsulate(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeMlKemEncapsulation {
    const suite = mlKemSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    return readEncapsulation(suite.encapsulate(publicKey), suite);
  },

  encapsulateDeterministicallyForTest(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
    randomness: Uint8Array,
  ): ReallyMeMlKemEncapsulation {
    const suite = mlKemSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    ensureBytes(randomness, ML_KEM_ENCAPSULATION_RANDOMNESS_LENGTH);
    return readEncapsulation(suite.encapsulateDerand(publicKey, randomness), suite);
  },

  decapsulate(
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = mlKemSuite(algorithm);
    ensureBytes(ciphertext, suite.ciphertextLength);
    ensureBytes(secretKey, ML_KEM_SECRET_KEY_LENGTH);
    return readSharedSecret(suite.decapsulate(ciphertext, secretKey));
  },
} as const;
