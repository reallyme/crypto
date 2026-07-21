// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeHpkeSuite } from "./algorithms.js";
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

export const HPKE_P256_PRIVATE_KEY_LENGTH = 32;
export const HPKE_P256_PUBLIC_KEY_LENGTH = 65;
export const HPKE_X25519_PRIVATE_KEY_LENGTH = 32;
export const HPKE_X25519_PUBLIC_KEY_LENGTH = 32;
export const HPKE_AEAD_TAG_LENGTH = 16;
export const HPKE_INFO_MAX_LENGTH = 65_530;

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
    default:
      // JavaScript callers can bypass TypeScript's string union at runtime.
      // Reject before a numeric selector can reach wasm-bindgen and truncate.
      throw new ReallyMeCryptoError("invalid-input");
  }
};

const readSealedMessage = (
  value: unknown,
  suite: HpkeSuiteConfig,
  plaintextLength: number,
  inputs: ReadonlyArray<Uint8Array>,
): ReallyMeHpkeSealedMessage => {
  const encapsulatedKey = readIndependentByteArrayProperty(
    value,
    "encapsulatedKey",
    suite.publicKeyLength,
    inputs,
  );
  const ciphertext = readIndependentByteArrayProperty(
    value,
    "ciphertext",
    plaintextLength + HPKE_AEAD_TAG_LENGTH,
    [...inputs, encapsulatedKey],
  );
  return { encapsulatedKey, ciphertext };
};

const requirePlaintext = (
  value: unknown,
  expectedLength: number,
  inputs: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  ensureIndependentByteArray(value, inputs);
  if (value.length !== expectedLength) {
    value.fill(0);
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
    ensureByteArrayAtMost(info, HPKE_INFO_MAX_LENGTH);
    ensureByteArrayAtMost(aad, MAX_CRYPTO_INPUT_LENGTH);
    ensureByteArrayAtMost(plaintext, MAX_CRYPTO_INPUT_LENGTH);
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
      [recipientPublicKey, info, aad, plaintext],
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
    ensureByteArrayAtMost(info, HPKE_INFO_MAX_LENGTH);
    ensureByteArrayAtMost(aad, MAX_CRYPTO_INPUT_LENGTH);
    ensureByteArrayAtMost(plaintext, MAX_CRYPTO_INPUT_LENGTH);
    return readSealedMessage(
      provider.hpkeSealBase(config.id, recipientPublicKey, info, aad, plaintext),
      config,
      plaintext.length,
      [recipientPublicKey, info, aad, plaintext],
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
    ensureByteArrayAtMost(info, HPKE_INFO_MAX_LENGTH);
    ensureByteArrayAtMost(aad, MAX_CRYPTO_INPUT_LENGTH);
    ensureByteArrayAtMost(
      ciphertext,
      MAX_CRYPTO_INPUT_LENGTH + HPKE_AEAD_TAG_LENGTH,
    );
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
      ciphertext.length - HPKE_AEAD_TAG_LENGTH,
      [recipientSecretKey, encapsulatedKey, info, aad, ciphertext],
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
    ensureByteArrayAtMost(info, HPKE_INFO_MAX_LENGTH);
    ensureByteArrayAtMost(aad, MAX_CRYPTO_INPUT_LENGTH);
    ensureByteArrayAtMost(
      ciphertext,
      MAX_CRYPTO_INPUT_LENGTH + HPKE_AEAD_TAG_LENGTH,
    );
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
      ciphertext.length - HPKE_AEAD_TAG_LENGTH,
      [recipientSecretKey, encapsulatedKey, info, aad, ciphertext],
    );
  },
} as const;
