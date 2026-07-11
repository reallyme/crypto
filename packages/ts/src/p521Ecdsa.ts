// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p521 } from "@noble/curves/nist.js";
import { sha512 } from "@noble/hashes/sha2.js";
import {
  decodeEcdsaDerSignature,
  encodeEcdsaDerSignature,
} from "./encodeEcdsaDer.js";
import { ReallyMeCryptoError } from "./errors.js";

export const P521_ECDSA_SECRET_KEY_LENGTH = 66;
export const P521_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH = 67;
export const P521_ECDSA_COMPACT_SIGNATURE_LENGTH = 132;
export const P521_ECDSA_DER_SIGNATURE_MAX_LENGTH = 139;

/**
 * P-521 ECDSA backed by @noble/curves.
 *
 * P-521 DER signatures can require long-form sequence lengths; the shared DER
 * helper enforces canonical positive INTEGER encoding before verification.
 */
export const ReallyMeP521Ecdsa = {
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
    if (secretKey.length !== P521_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return p521.getPublicKey(secretKey, true);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (secretKey.length !== P521_ECDSA_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      const compactSignature = p521.sign(sha512(message), secretKey, {
        lowS: false,
        prehash: false,
      });
      return encodeEcdsaDerSignature(compactSignature, P521_ECDSA_SECRET_KEY_LENGTH);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (publicKey.length !== P521_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }

    let compactSignature: Uint8Array;
    try {
      p521.Point.fromBytes(publicKey);
      compactSignature = decodeEcdsaDerSignature(
        signature,
        P521_ECDSA_SECRET_KEY_LENGTH,
        P521_ECDSA_DER_SIGNATURE_MAX_LENGTH,
      );
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }

    try {
      const valid = p521.verify(compactSignature, sha512(message), publicKey, {
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
