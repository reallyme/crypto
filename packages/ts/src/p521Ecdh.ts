// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p521 } from "@noble/curves/nist.js";
import { ReallyMeCryptoError } from "./errors.js";

/**
 * P-521 ECDH backed by @noble/curves.
 *
 * Public keys at the SDK boundary are compressed SEC1. The primitive returns
 * the raw 66-byte ECDH x-coordinate; protocols must apply a labelled KDF that
 * binds algorithm and party context before using it as key material.
 */
export const P521_ECDH_SECRET_KEY_LENGTH = 66;
export const P521_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH = 67;
export const P521_ECDH_SHARED_SECRET_LENGTH = 66;

export const ReallyMeP521Ecdh = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = p521.utils.randomSecretKey();
    return {
      publicKey: p521.getPublicKey(secretKey, true),
      secretKey,
    };
  },

  deriveKeyPair(secretKey: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return {
      publicKey: this.derivePublicKey(secretKey),
      secretKey: secretKey.slice(),
    };
  },

  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== P521_ECDH_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p521.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  deriveSharedSecret(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (
      publicKey.length !== P521_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH ||
      secretKey.length !== P521_ECDH_SECRET_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p521.getSharedSecret(secretKey, publicKey, false).slice(1, 67);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },
} as const;
