// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeHpkeSuite } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureBytes, readByteArrayProperty } from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const HPKE_P256_PRIVATE_KEY_LENGTH = 32;
export const HPKE_P256_PUBLIC_KEY_LENGTH = 65;
export const HPKE_X25519_PRIVATE_KEY_LENGTH = 32;
export const HPKE_X25519_PUBLIC_KEY_LENGTH = 32;
export const HPKE_AEAD_TAG_LENGTH = 16;

export type ReallyMeHpkeSealedMessage = Readonly<{
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}>;

type HpkeSuiteConfig = Readonly<{
  id: number;
  publicKeyLength: number;
  privateKeyLength: number;
}>;

const hpkeSuite = (suite: ReallyMeHpkeSuite): HpkeSuiteConfig => {
  switch (suite) {
    case "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM":
      return {
        id: 1,
        publicKeyLength: HPKE_P256_PUBLIC_KEY_LENGTH,
        privateKeyLength: HPKE_P256_PRIVATE_KEY_LENGTH,
      };
    case "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305":
      return {
        id: 2,
        publicKeyLength: HPKE_X25519_PUBLIC_KEY_LENGTH,
        privateKeyLength: HPKE_X25519_PRIVATE_KEY_LENGTH,
      };
  }
};

const readSealedMessage = (
  value: unknown,
  suite: HpkeSuiteConfig,
  plaintextLength: number,
): ReallyMeHpkeSealedMessage => ({
  encapsulatedKey: readByteArrayProperty(value, "encapsulatedKey", suite.publicKeyLength),
  ciphertext: readByteArrayProperty(
    value,
    "ciphertext",
    plaintextLength + HPKE_AEAD_TAG_LENGTH,
  ),
});

const requirePlaintext = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

export const ReallyMeHpke = {
  sealBase(
    suite: ReallyMeHpkeSuite,
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): ReallyMeHpkeSealedMessage {
    const config = hpkeSuite(suite);
    ensureBytes(recipientPublicKey, config.publicKeyLength);
    return readSealedMessage(
      requireReallyMeWasmProvider().hpkeSealBase(
        config.id,
        recipientPublicKey,
        info,
        aad,
        plaintext,
      ),
      config,
      plaintext.length,
    );
  },

  sealBaseWithProvider(
    provider: ReallyMeWasmProvider,
    suite: ReallyMeHpkeSuite,
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): ReallyMeHpkeSealedMessage {
    const config = hpkeSuite(suite);
    ensureBytes(recipientPublicKey, config.publicKeyLength);
    return readSealedMessage(
      provider.hpkeSealBase(config.id, recipientPublicKey, info, aad, plaintext),
      config,
      plaintext.length,
    );
  },

  openBase(
    suite: ReallyMeHpkeSuite,
    recipientSecretKey: Uint8Array,
    encapsulatedKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array {
    const config = hpkeSuite(suite);
    ensureBytes(recipientSecretKey, config.privateKeyLength);
    ensureBytes(encapsulatedKey, config.publicKeyLength);
    if (ciphertext.length < HPKE_AEAD_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return requirePlaintext(
      requireReallyMeWasmProvider().hpkeOpenBase(
        config.id,
        recipientSecretKey,
        encapsulatedKey,
        info,
        aad,
        ciphertext,
      ),
    );
  },

  openBaseWithProvider(
    provider: ReallyMeWasmProvider,
    suite: ReallyMeHpkeSuite,
    recipientSecretKey: Uint8Array,
    encapsulatedKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array {
    const config = hpkeSuite(suite);
    ensureBytes(recipientSecretKey, config.privateKeyLength);
    ensureBytes(encapsulatedKey, config.publicKeyLength);
    if (ciphertext.length < HPKE_AEAD_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return requirePlaintext(
      provider.hpkeOpenBase(
        config.id,
        recipientSecretKey,
        encapsulatedKey,
        info,
        aad,
        ciphertext,
      ),
    );
  },
} as const;

export const sealHpkeBaseDeterministicallyForTest = (
  suite: ReallyMeHpkeSuite,
  recipientPublicKey: Uint8Array,
  encapsulationRandomness: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): ReallyMeHpkeSealedMessage => {
  const config = hpkeSuite(suite);
  ensureBytes(recipientPublicKey, config.publicKeyLength);
  ensureBytes(encapsulationRandomness, config.privateKeyLength);
  return readSealedMessage(
    requireReallyMeWasmProvider().hpkeSealBaseDerand(
      config.id,
      recipientPublicKey,
      encapsulationRandomness,
      info,
      aad,
      plaintext,
    ),
    config,
    plaintext.length,
  );
};

export const sealHpkeBaseDeterministicallyWithProviderForTest = (
  provider: ReallyMeWasmProvider,
  suite: ReallyMeHpkeSuite,
  recipientPublicKey: Uint8Array,
  encapsulationRandomness: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): ReallyMeHpkeSealedMessage => {
  const config = hpkeSuite(suite);
  ensureBytes(recipientPublicKey, config.publicKeyLength);
  ensureBytes(encapsulationRandomness, config.privateKeyLength);
  return readSealedMessage(
    provider.hpkeSealBaseDerand(
      config.id,
      recipientPublicKey,
      encapsulationRandomness,
      info,
      aad,
      plaintext,
    ),
    config,
    plaintext.length,
  );
};
