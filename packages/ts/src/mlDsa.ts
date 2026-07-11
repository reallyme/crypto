// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeSignatureAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes, readByteArrayProperty } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export const ML_DSA_44_PUBLIC_KEY_LENGTH = 1_312;
export const ML_DSA_44_SIGNATURE_LENGTH = 2_420;
export const ML_DSA_65_PUBLIC_KEY_LENGTH = 1_952;
export const ML_DSA_65_SIGNATURE_LENGTH = 3_309;
export const ML_DSA_87_PUBLIC_KEY_LENGTH = 2_592;
export const ML_DSA_87_SIGNATURE_LENGTH = 4_627;
export const ML_DSA_SECRET_KEY_LENGTH = 32;

export type ReallyMeMlDsaKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

type MlDsaSuite = Readonly<{
  publicKeyLength: number;
  signatureLength: number;
  generateKeyPair: () => unknown;
  deriveKeyPair: (secretKey: Uint8Array) => unknown;
  sign: (secretKey: Uint8Array, message: Uint8Array) => unknown;
  verify: (publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => unknown;
}>;

const mlDsaSuite = (algorithm: ReallyMeSignatureAlgorithm): MlDsaSuite => {
  const provider = requireReallyMeWasmProvider();
  switch (algorithm) {
    case "ML-DSA-44":
      return {
        publicKeyLength: ML_DSA_44_PUBLIC_KEY_LENGTH,
        signatureLength: ML_DSA_44_SIGNATURE_LENGTH,
        generateKeyPair: provider.mlDsa44GenerateKeypair,
        deriveKeyPair: provider.mlDsa44DeriveKeypair,
        sign: provider.mlDsa44Sign,
        verify: provider.mlDsa44Verify,
      };
    case "ML-DSA-65":
      return {
        publicKeyLength: ML_DSA_65_PUBLIC_KEY_LENGTH,
        signatureLength: ML_DSA_65_SIGNATURE_LENGTH,
        generateKeyPair: provider.mlDsa65GenerateKeypair,
        deriveKeyPair: provider.mlDsa65DeriveKeypair,
        sign: provider.mlDsa65Sign,
        verify: provider.mlDsa65Verify,
      };
    case "ML-DSA-87":
      return {
        publicKeyLength: ML_DSA_87_PUBLIC_KEY_LENGTH,
        signatureLength: ML_DSA_87_SIGNATURE_LENGTH,
        generateKeyPair: provider.mlDsa87GenerateKeypair,
        deriveKeyPair: provider.mlDsa87DeriveKeypair,
        sign: provider.mlDsa87Sign,
        verify: provider.mlDsa87Verify,
      };
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const readKeyPair = (value: unknown, suite: MlDsaSuite): ReallyMeMlDsaKeyPair => ({
  publicKey: readByteArrayProperty(value, "publicKey", suite.publicKeyLength),
  secretKey: readByteArrayProperty(value, "secretKey", ML_DSA_SECRET_KEY_LENGTH),
});

const readSignature = (value: unknown, suite: MlDsaSuite): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  ensureBytes(value, suite.signatureLength);
  return value;
};

const readVoid = (value: unknown): void => {
  if (value !== undefined) {
    throw new ReallyMeCryptoError("provider-failure");
  }
};

export const ReallyMeMlDsa = {
  generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): ReallyMeMlDsaKeyPair {
    const suite = mlDsaSuite(algorithm);
    return readKeyPair(suite.generateKeyPair(), suite);
  },

  deriveKeyPair(
    algorithm: ReallyMeSignatureAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeMlDsaKeyPair {
    const suite = mlDsaSuite(algorithm);
    ensureBytes(secretKey, ML_DSA_SECRET_KEY_LENGTH);
    return readKeyPair(suite.deriveKeyPair(secretKey), suite);
  },

  sign(
    algorithm: ReallyMeSignatureAlgorithm,
    message: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    const suite = mlDsaSuite(algorithm);
    ensureBytes(secretKey, ML_DSA_SECRET_KEY_LENGTH);
    return readSignature(suite.sign(secretKey, message), suite);
  },

  verify(
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    const suite = mlDsaSuite(algorithm);
    ensureBytes(publicKey, suite.publicKeyLength);
    ensureBytes(signature, suite.signatureLength);
    readVoid(suite.verify(publicKey, message, signature));
  },
} as const;
