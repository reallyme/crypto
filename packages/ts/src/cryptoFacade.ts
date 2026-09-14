// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createReallyMeAsymmetricFacade } from "./cryptoFacadeAsymmetric.js";
import { createReallyMeSymmetricFacade } from "./cryptoFacadeSymmetric.js";
import { ReallyMeCryptoError } from "./errors.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export type ReallyMeSignatureKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKemKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKeyAgreementKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKemEncapsulation = Readonly<{
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}>;

export type ReallyMeHpkeSealedMessage = Readonly<{
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}>;

export type ReallyMeCryptoProviders = Readonly<{
  wasmProvider?: ReallyMeWasmProvider;
}>;

/**
 * Generic package facade. Algorithm-specific objects remain available for
 * callers that want direct provider access; this facade gives consumers a
 * stable typed route and rejects algorithm/operation combinations that the
 * selected method does not define.
 */
const createReallyMeCryptoFacade = (
  resolveWasmProvider: () => ReallyMeWasmProvider,
) => ({
  ...createReallyMeSymmetricFacade(resolveWasmProvider),
  ...createReallyMeAsymmetricFacade(resolveWasmProvider),
});

export type ReallyMeCryptoFacade = ReturnType<typeof createReallyMeCryptoFacade>;

export const createReallyMeCrypto = (
  providers: ReallyMeCryptoProviders = {},
): ReallyMeCryptoFacade => {
  const configuredProvider = providers.wasmProvider;
  return createReallyMeCryptoFacade(() => {
    if (configuredProvider === undefined) {
      throw new ReallyMeCryptoError("provider-failure");
    }
    return configuredProvider;
  });
};

export const ReallyMeCrypto = createReallyMeCryptoFacade(requireReallyMeWasmProvider);
