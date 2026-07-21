// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeSignatureAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureByteArrayAtMost,
  ensureBytes,
  ensureIndependentByteArray,
  MAX_CRYPTO_INPUT_LENGTH,
  readIndependentByteArrayProperty,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH = 32;
export const SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH = 64;
export const SLH_DSA_SHA2_128S_SIGNATURE_LENGTH = 7_856;
export const SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH = 16;

export type ReallyMeSlhDsaKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

const assertSlhDsa = (algorithm: ReallyMeSignatureAlgorithm): void => {
  if (algorithm !== "SLH-DSA-SHA2-128s") {
    throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const readKeyPair = (
  value: unknown,
  inputs: ReadonlyArray<Uint8Array> = [],
): ReallyMeSlhDsaKeyPair => {
  const publicKey = readIndependentByteArrayProperty(
    value,
    "publicKey",
    SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH,
    inputs,
  );
  const secretKey = readIndependentByteArrayProperty(
    value,
    "secretKey",
    SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH,
    [...inputs, publicKey],
  );
  return { publicKey, secretKey };
};

const readSignature = (
  value: unknown,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  // Signature bytes are public, but their shape and ownership are provider
  // postconditions rather than caller validation failures.
  ensureIndependentByteArray(value, inputs);
  if (value.length !== SLH_DSA_SHA2_128S_SIGNATURE_LENGTH) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

const readVoid = (value: unknown): void => {
  if (value !== undefined) {
    throw new ReallyMeCryptoError("provider-failure");
  }
};

export const ReallyMeSlhDsa = {
  generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): ReallyMeSlhDsaKeyPair {
    assertSlhDsa(algorithm);
    return readKeyPair(requireReallyMeWasmProvider().slhDsaSha2128sGenerateKeypair());
  },

  generateKeyPairWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeSignatureAlgorithm,
  ): ReallyMeSlhDsaKeyPair {
    assertSlhDsa(algorithm);
    return readKeyPair(provider.slhDsaSha2128sGenerateKeypair());
  },

  sign(
    algorithm: ReallyMeSignatureAlgorithm,
    message: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    assertSlhDsa(algorithm);
    ensureByteArrayAtMost(message, MAX_CRYPTO_INPUT_LENGTH);
    ensureBytes(secretKey, SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH);
    return readSignature(
      requireReallyMeWasmProvider().slhDsaSha2128sSign(secretKey, message),
      [secretKey, message],
    );
  },

  signWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeSignatureAlgorithm,
    message: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    assertSlhDsa(algorithm);
    ensureByteArrayAtMost(message, MAX_CRYPTO_INPUT_LENGTH);
    ensureBytes(secretKey, SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH);
    return readSignature(
      provider.slhDsaSha2128sSign(secretKey, message),
      [secretKey, message],
    );
  },

  verify(
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    assertSlhDsa(algorithm);
    ensureByteArrayAtMost(message, MAX_CRYPTO_INPUT_LENGTH);
    ensureBytes(publicKey, SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH);
    ensureBytes(signature, SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);
    readVoid(
      requireReallyMeWasmProvider().slhDsaSha2128sVerify(
        publicKey,
        message,
        signature,
      ),
    );
  },

  verifyWithProvider(
    provider: ReallyMeWasmProvider,
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    assertSlhDsa(algorithm);
    ensureByteArrayAtMost(message, MAX_CRYPTO_INPUT_LENGTH);
    ensureBytes(publicKey, SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH);
    ensureBytes(signature, SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);
    readVoid(provider.slhDsaSha2128sVerify(publicKey, message, signature));
  },
} as const;

export const deriveSlhDsaSha2128sKeypairForTest = (
  skSeed: Uint8Array,
  skPrf: Uint8Array,
  pkSeed: Uint8Array,
): ReallyMeSlhDsaKeyPair => {
  ensureBytes(skSeed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  ensureBytes(skPrf, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  ensureBytes(pkSeed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  return readKeyPair(
    requireReallyMeWasmProvider().slhDsaSha2128sDeriveKeypair(
      skSeed,
      skPrf,
      pkSeed,
    ),
    [skSeed, skPrf, pkSeed],
  );
};

export const deriveSlhDsaSha2128sKeypairWithProviderForTest = (
  provider: ReallyMeWasmProvider,
  skSeed: Uint8Array,
  skPrf: Uint8Array,
  pkSeed: Uint8Array,
): ReallyMeSlhDsaKeyPair => {
  ensureBytes(skSeed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  ensureBytes(skPrf, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  ensureBytes(pkSeed, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  return readKeyPair(
    provider.slhDsaSha2128sDeriveKeypair(skSeed, skPrf, pkSeed),
    [skSeed, skPrf, pkSeed],
  );
};
