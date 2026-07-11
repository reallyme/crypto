// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { x25519 } from "@noble/curves/ed25519.js";
import { ReallyMeCryptoError } from "./errors.js";

/**
 * X25519 key agreement backed by @noble/curves — the same pinned
 * implementation the TypeScript conformance lane proves vectors against.
 *
 * The package returns the raw 32-byte Diffie-Hellman output. Higher-level
 * protocols must bind it through their own KDF transcript; this primitive does
 * not apply HKDF implicitly because HPKE, MLS, and ratchets label transcripts
 * differently.
 */
export const X25519_SECRET_KEY_LENGTH = 32;
export const X25519_PUBLIC_KEY_LENGTH = 32;
export const X25519_SHARED_SECRET_LENGTH = 32;

export const ReallyMeX25519 = {
  /** Generates a random X25519 keypair: 32-byte public key, 32-byte secret. */
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = x25519.utils.randomSecretKey();
    return {
      publicKey: x25519.getPublicKey(secretKey),
      secretKey,
    };
  },

  /** Derives the X25519 keypair from a 32-byte secret. */
  deriveKeyPair(secretKey: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return {
      publicKey: this.derivePublicKey(secretKey),
      secretKey: secretKey.slice(),
    };
  },

  /** Derives the 32-byte X25519 public key from a 32-byte secret. */
  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== X25519_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return x25519.getPublicKey(secretKey);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  /** Derives the raw 32-byte X25519 shared secret. */
  deriveSharedSecret(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (
      publicKey.length !== X25519_PUBLIC_KEY_LENGTH ||
      secretKey.length !== X25519_SECRET_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const sharedSecret = x25519.getSharedSecret(secretKey, publicKey);
      if (!sharedSecret.some((byte) => byte !== 0)) {
        throw new ReallyMeCryptoError("invalid-input");
      }
      return sharedSecret;
    } catch (error) {
      if (error instanceof ReallyMeCryptoError) {
        throw error;
      }
      throw new ReallyMeCryptoError("invalid-input");
    }
  },
} as const;
