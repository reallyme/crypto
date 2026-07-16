// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { ReallyMeCryptoError } from "./errors.js";

export const BIP340_SCHNORR_SECRET_KEY_LENGTH = 32;
export const BIP340_SCHNORR_PUBLIC_KEY_LENGTH = 32;
export const BIP340_SCHNORR_MESSAGE_LENGTH = 32;
export const BIP340_SCHNORR_AUX_RAND_LENGTH = 32;
export const BIP340_SCHNORR_SIGNATURE_LENGTH = 64;

/**
 * BIP-340 Schnorr over secp256k1 backed by @noble/curves.
 *
 * BIP-340 signs a 32-byte message representative and requires 32 bytes of
 * auxiliary randomness. Keeping `auxRand32` explicit matches the Rust, Swift,
 * and Kotlin lanes and avoids a hidden provider-specific randomness policy at
 * the generic facade boundary.
 */
export const ReallyMeBip340Schnorr = {
  generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const secretKey = secp256k1.utils.randomSecretKey();
    return {
      publicKey: schnorr.getPublicKey(secretKey),
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
    if (secretKey.length !== BIP340_SCHNORR_SECRET_KEY_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return schnorr.getPublicKey(secretKey);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  sign(
    message32: Uint8Array,
    secretKey: Uint8Array,
    auxRand32: Uint8Array,
  ): Uint8Array {
    if (
      message32.length !== BIP340_SCHNORR_MESSAGE_LENGTH ||
      secretKey.length !== BIP340_SCHNORR_SECRET_KEY_LENGTH ||
      auxRand32.length !== BIP340_SCHNORR_AUX_RAND_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      return schnorr.sign(message32, secretKey, auxRand32);
    } catch {
      throw new ReallyMeCryptoError("invalid-input");
    }
  },

  verify(
    signature: Uint8Array,
    message32: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (
      signature.length !== BIP340_SCHNORR_SIGNATURE_LENGTH ||
      message32.length !== BIP340_SCHNORR_MESSAGE_LENGTH ||
      publicKey.length !== BIP340_SCHNORR_PUBLIC_KEY_LENGTH
    ) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    try {
      if (!schnorr.verify(signature, message32, publicKey)) {
        throw new ReallyMeCryptoError("invalid-signature");
      }
    } catch {
      throw new ReallyMeCryptoError("invalid-signature");
    }
  },
} as const;
