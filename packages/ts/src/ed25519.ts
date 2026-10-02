// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, concatBytes } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureByteArray } from "./validateBytes.js";

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

/** Require one canonical prime-subgroup encoding for an Ed25519 identity. */
export const validateEd25519PublicKeyIdentity = (publicKey: Uint8Array): void => {
  ensureByteArray(publicKey);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  try {
    const point = ed25519.Point.fromBytes(publicKey, false);
    const canonical = point.toBytes();
    if (
      !point.isTorsionFree() ||
      point.isSmallOrder() ||
      canonical.some((byte, index) => byte !== publicKey[index])
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
  } catch {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

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
      // Buffer.slice() aliases its input; the returned key must own its bytes.
      secretKey: new Uint8Array(secretKey),
    };
  },

  /** Derives the 32-byte Ed25519 public key from a 32-byte seed. */
  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    ensureByteArray(secretKey);
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
    ensureByteArray(message);
    ensureByteArray(secretKey);
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
    ensureByteArray(signature);
    ensureByteArray(message);
    ensureByteArray(publicKey);
    if (
      signature.length !== ED25519_SIGNATURE_LENGTH ||
      publicKey.length !== ED25519_PUBLIC_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    let point: ReturnType<typeof ed25519.Point.fromBytes>;
    try {
      point = ed25519.Point.fromBytes(publicKey, false);
    } catch {
      throw new ReallyMeCryptoError("invalid-signature");
    }
    try {
      const rBytes = signature.subarray(0, ED25519_PUBLIC_KEY_LENGTH);
      const rPoint = ed25519.Point.fromBytes(rBytes, false);
      const scalar = bytesToNumberLE(signature.subarray(ED25519_PUBLIC_KEY_LENGTH));
      const order = ed25519.Point.Fn.ORDER;
      if (
        scalar >= order ||
        !point.isTorsionFree() ||
        !rPoint.isTorsionFree() ||
        point.isSmallOrder() ||
        rPoint.isSmallOrder()
      ) {
        throw new ReallyMeCryptoError("invalid-signature");
      }
      // Noble's ordinary verify uses a cofactored equation. Rust's verify_strict
      // compares the full Edwards equation, including any torsion component.
      const challenge = bytesToNumberLE(sha512(concatBytes(rBytes, publicKey, message))) % order;
      if (!ed25519.Point.BASE.multiplyUnsafe(scalar).equals(rPoint.add(point.multiplyUnsafe(challenge)))) {
        throw new ReallyMeCryptoError("invalid-signature");
      }
    } catch {
      throw new ReallyMeCryptoError("invalid-signature");
    }
  },
} as const;
