// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p384 } from "@noble/curves/nist.js";
import { ReallyMeCryptoError } from "./errors.js";
import { bestEffortClear } from "./memory.js";

/**
 * P-384 ECDH backed by @noble/curves.
 *
 * Public keys at the SDK boundary are compressed SEC1. The primitive returns
 * the raw 48-byte ECDH x-coordinate; protocols must apply a labelled KDF that
 * binds algorithm and party context before using it as key material.
 */
export const P384_ECDH_SECRET_KEY_LENGTH = 48;
export const P384_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH = 49;
export const P384_ECDH_SHARED_SECRET_LENGTH = 48;

export const ReallyMeP384Ecdh = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = p384.utils.randomSecretKey();
    return {
      publicKey: p384.getPublicKey(secretKey, true),
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
    if (secretKey.length !== P384_ECDH_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p384.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  deriveSharedSecret(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (
      publicKey.length !== P384_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH ||
      secretKey.length !== P384_ECDH_SECRET_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const uncompressed = p384.getSharedSecret(secretKey, publicKey, false);
      const sharedSecret = uncompressed.slice(1, 49);
      bestEffortClear(uncompressed);
      return sharedSecret;
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },
} as const;
