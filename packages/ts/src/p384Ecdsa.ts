// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p384 } from "@noble/curves/nist.js";
import { sha384 } from "@noble/hashes/sha2.js";
import {
  decodeEcdsaDerSignature,
  encodeEcdsaDerSignature,
} from "./encodeEcdsaDer.js";
import { ReallyMeCryptoError } from "./errors.js";

export const P384_ECDSA_SECRET_KEY_LENGTH = 48;
export const P384_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH = 49;
export const P384_ECDSA_COMPACT_SIGNATURE_LENGTH = 96;
export const P384_ECDSA_DER_SIGNATURE_MAX_LENGTH = 104;

/**
 * P-384 ECDSA backed by @noble/curves.
 *
 * The package signs SHA-384(message) exactly once and preserves DER signatures
 * byte-for-byte with the Rust/Swift vector contract.
 */
export const ReallyMeP384Ecdsa = {
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
    if (secretKey.length !== P384_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p384.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== P384_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const compactSignature = p384.sign(sha384(message), secretKey, {
        lowS: false,
        prehash: false,
      });
      return encodeEcdsaDerSignature(compactSignature, P384_ECDSA_SECRET_KEY_LENGTH);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (publicKey.length !== P384_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }

    let compactSignature: Uint8Array;
    try {
      p384.Point.fromBytes(publicKey);
      compactSignature = decodeEcdsaDerSignature(
        signature,
        P384_ECDSA_SECRET_KEY_LENGTH,
        P384_ECDSA_DER_SIGNATURE_MAX_LENGTH,
      );
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }

    try {
      const valid = p384.verify(compactSignature, sha384(message), publicKey, {
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
