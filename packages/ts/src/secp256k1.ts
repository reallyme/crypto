// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";

/**
 * secp256k1 ECDSA backed by @noble/curves — the same pinned implementation
 * the TypeScript conformance lane proves vectors against.
 *
 * The API follows the workspace secp256k1 contract exactly, so signatures
 * interoperate byte-for-byte with the Rust, Swift, and Kotlin lanes:
 *
 * - Secret keys are 32 bytes; public keys are 33-byte compressed SEC1.
 * - `sign` hashes the full message internally with SHA-256 (callers pass the
 *   message, not a digest), derives the nonce deterministically (RFC 6979),
 *   and emits the 64-byte compact `r ‖ s` form normalized to low-S
 *   (BIP 0062).
 * - `verify` accepts only the 64-byte compact form, rejects the malleated
 *   high-S twin, and throws `invalid-signature` for a well-formed-but-wrong
 *   signature so callers cannot accidentally ignore a failed check.
 */
export const SECP256K1_SECRET_KEY_LENGTH = 32;
export const SECP256K1_COMPRESSED_PUBLIC_KEY_LENGTH = 33;
export const SECP256K1_SIGNATURE_LENGTH = 64;

export const ReallyMeSecp256k1 = {
  /** Generates a random keypair: 33-byte compressed public, 32-byte secret. */
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = secp256k1.utils.randomSecretKey();
    return {
      publicKey: secp256k1.getPublicKey(secretKey, true),
      secretKey,
    };
  },

  /** Derives the secp256k1 ECDSA keypair from a 32-byte secret scalar. */
  deriveKeyPair(secretKey: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    return {
      publicKey: this.derivePublicKey(secretKey),
      secretKey: secretKey.slice(),
    };
  },

  /** Derives the 33-byte compressed SEC1 public key for a 32-byte secret. */
  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== SECP256K1_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return secp256k1.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  /**
   * Signs `message` with deterministic (RFC 6979) ECDSA over
   * SHA-256(message), returning the 64-byte compact low-S signature.
   */
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== SECP256K1_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      // Hash exactly once ourselves; prehash: false stops noble from
      // hashing the digest a second time.
      return secp256k1.sign(sha256(message), secretKey, {
        lowS: true,
        prehash: false,
      });
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  /**
   * Verifies a 64-byte compact signature over SHA-256(message) against a
   * 33-byte compressed SEC1 public key.
   *
   * Throws on malformed input (wrong lengths, undecodable key); returns
   * Throws for a signature that does not verify, including the malleated
   * high-S twin (BIP 0062), which every workspace lane rejects.
   */
  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (
      signature.length !== SECP256K1_SIGNATURE_LENGTH ||
      publicKey.length !== SECP256K1_COMPRESSED_PUBLIC_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      secp256k1.Point.fromBytes(publicKey);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const valid = secp256k1.verify(signature, sha256(message), publicKey, {
        lowS: true,
        prehash: false,
      });
      if (!valid) {
        throw new ReallyMeCryptoError("invalid-signature");
      }
    } catch {
      throw new ReallyMeCryptoError("invalid-signature");
    }
  },
} as const;
