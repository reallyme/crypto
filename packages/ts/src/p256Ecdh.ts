// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p256 } from "@noble/curves/nist.js";
import { ReallyMeCryptoError } from "./errors.js";
import { bestEffortClear } from "./memory.js";

/**
 * P-256 ECDH backed by @noble/curves.
 *
 * Public keys at the SDK boundary are compressed SEC1. The primitive returns
 * the raw 32-byte ECDH x-coordinate; protocols must apply their own labelled
 * KDF rather than relying on this low-level helper to choose one.
 */
export const P256_ECDH_SECRET_KEY_LENGTH = 32;
export const P256_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH = 33;
export const P256_ECDH_SHARED_SECRET_LENGTH = 32;

export const ReallyMeP256Ecdh = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = p256.utils.randomSecretKey();
    return {
      publicKey: p256.getPublicKey(secretKey, true),
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
    if (secretKey.length !== P256_ECDH_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p256.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  deriveSharedSecret(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (
      publicKey.length !== P256_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH ||
      secretKey.length !== P256_ECDH_SECRET_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const uncompressed = p256.getSharedSecret(secretKey, publicKey, false);
      const sharedSecret = uncompressed.slice(1, 33);
      bestEffortClear(uncompressed);
      return sharedSecret;
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },
} as const;
