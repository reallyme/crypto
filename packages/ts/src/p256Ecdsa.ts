// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  decodeEcdsaDerSignature,
  encodeEcdsaDerSignature,
} from "./encodeEcdsaDer.js";
import { ReallyMeCryptoError } from "./errors.js";

export const P256_ECDSA_SECRET_KEY_LENGTH = 32;
export const P256_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH = 33;
export const P256_ECDSA_COMPACT_SIGNATURE_LENGTH = 64;
export const P256_ECDSA_DER_SIGNATURE_MAX_LENGTH = 72;

/**
 * P-256 ECDSA backed by @noble/curves.
 *
 * The workspace contract signs SHA-256(message) exactly once and uses DER
 * encoding for signatures because that is what X.509, JOSE, and the Rust
 * P-256 lane expose. We intentionally preserve the Rust vector bytes instead
 * of applying a TypeScript-only low-S normalization policy.
 */
export const ReallyMeP256Ecdsa = {
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
    if (secretKey.length !== P256_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p256.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== P256_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const compactSignature = p256.sign(sha256(message), secretKey, {
        lowS: false,
        prehash: false,
      });
      return encodeEcdsaDerSignature(compactSignature, P256_ECDSA_SECRET_KEY_LENGTH);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (publicKey.length !== P256_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }

    let compactSignature: Uint8Array;
    try {
      p256.Point.fromBytes(publicKey);
      compactSignature = decodeEcdsaDerSignature(
        signature,
        P256_ECDSA_SECRET_KEY_LENGTH,
        P256_ECDSA_DER_SIGNATURE_MAX_LENGTH,
      );
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }

    try {
      const valid = p256.verify(compactSignature, sha256(message), publicKey, {
        lowS: false,
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
