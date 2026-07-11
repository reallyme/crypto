// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export const ARGON2ID_DERIVED_KEY_LENGTH = 32;
export const ARGON2ID_SALT_MIN_LENGTH = 16;
export const ARGON2ID_SALT_MAX_LENGTH = 32;
export const ARGON2ID_V1 = 1;
export const ARGON2ID_V2 = 2;

const validateVersion = (kdfVersion: number): void => {
  if (
    !Number.isInteger(kdfVersion) ||
    (kdfVersion !== ARGON2ID_V1 && kdfVersion !== ARGON2ID_V2)
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const validateSecret = (secret: Uint8Array): void => {
  if (secret.length === 0) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const validateSalt = (salt: Uint8Array): void => {
  if (salt.length < ARGON2ID_SALT_MIN_LENGTH || salt.length > ARGON2ID_SALT_MAX_LENGTH) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const requireDerivedKey = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array) || value.length !== ARGON2ID_DERIVED_KEY_LENGTH) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

export const ReallyMeArgon2id = {
  deriveKey(kdfVersion: number, secret: Uint8Array, salt: Uint8Array): Uint8Array {
    validateVersion(kdfVersion);
    validateSecret(secret);
    validateSalt(salt);
    return requireDerivedKey(
      requireReallyMeWasmProvider().argon2idDeriveKey(kdfVersion, secret, salt),
    );
  },
} as const;
