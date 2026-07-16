// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ed25519 } from "@noble/curves/ed25519.js";
import { ReallyMeCryptoError } from "./errors.js";

/**
 * Ed25519 signatures backed by @noble/curves — the same pinned implementation
 * the TypeScript conformance lane proves vectors against.
 *
 * The workspace contract uses the plain Ed25519 variant: callers pass the full
 * message, the provider signs that message directly, and signatures are the
 * 64-byte RFC 8032 encoding. Ed25519 is deterministic, so the same key and
 * message must produce the same bytes in every platform lane.
 */
export const ED25519_SECRET_KEY_LENGTH = 32;
export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

export const ReallyMeEd25519 = {
  /** Generates a random Ed25519 keypair: 32-byte public key, 32-byte seed. */
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = ed25519.utils.randomSecretKey();
    return {
      publicKey: ed25519.getPublicKey(secretKey),
      secretKey,
    };
  },

  /**
   * Reconstructs an Ed25519 keypair from stored 32-byte secret material.
   *
   * This is an import path, not password-based key generation. Use
   * `generateKeyPair` for fresh keys.
   */
  deriveKeyPair(secretKey: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return {
      publicKey: this.derivePublicKey(secretKey),
      secretKey: secretKey.slice(),
    };
  },

  /** Derives the 32-byte Ed25519 public key from a 32-byte seed. */
  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== ED25519_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return ed25519.getPublicKey(secretKey);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  /** Signs the full message using plain deterministic Ed25519. */
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== ED25519_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return ed25519.sign(message, secretKey);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  /**
   * Verifies a 64-byte Ed25519 signature against a 32-byte public key.
   *
   * Throws on malformed input shape, undecodable keys, or invalid signatures.
   */
  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (
      signature.length !== ED25519_SIGNATURE_LENGTH ||
      publicKey.length !== ED25519_PUBLIC_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      ed25519.Point.fromBytes(publicKey, false);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
    if (!ed25519.verify(signature, message, publicKey, { zip215: false })) {
      throw new ReallyMeCryptoError("invalid-signature");
    }
  },
} as const;
