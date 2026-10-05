// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  decodeEcdsaDerSignature,
  encodeEcdsaDerSignature,
} from "./encodeEcdsaDer.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ensureByteArray } from "./validateBytes.js";

export const P256_ECDSA_SECRET_KEY_LENGTH = 32;
export const P256_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH = 33;
export const P256_ECDSA_COMPACT_SIGNATURE_LENGTH = 64;
export const P256_ECDSA_DER_SIGNATURE_MAX_LENGTH = 72;

const P256_CURVE_ORDER = Uint8Array.from([
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
  0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]);

const P256_HALF_CURVE_ORDER = Uint8Array.from([
  0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
  0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
]);

const compareBigEndian = (left: Uint8Array, right: Uint8Array): number => {
  if (left.length !== right.length) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  for (let index = 0; index < left.length; index += 1) {
    const leftByte = left[index];
    const rightByte = right[index];
    if (leftByte === undefined || rightByte === undefined) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    if (leftByte !== rightByte) {
      return leftByte < rightByte ? -1 : 1;
    }
  }
  return 0;
};

const isZeroScalar = (scalar: Uint8Array): boolean => {
  for (const byte of scalar) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
};

const subtractBigEndian = (left: Uint8Array, right: Uint8Array): Uint8Array => {
  if (left.length !== right.length || compareBigEndian(left, right) < 0) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const result = new Uint8Array(left.length);
  let borrow = 0;
  for (let index = left.length - 1; index >= 0; index -= 1) {
    const leftByte = left[index];
    const rightByte = right[index];
    if (leftByte === undefined || rightByte === undefined) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    const difference = leftByte - rightByte - borrow;
    result[index] = difference < 0 ? difference + 256 : difference;
    borrow = difference < 0 ? 1 : 0;
  }
  if (borrow !== 0) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return result;
};

const normalizeP256JoseSignatureLowS = (signature: Uint8Array): Uint8Array => {
  if (signature.length !== P256_ECDSA_COMPACT_SIGNATURE_LENGTH) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const normalized = new Uint8Array(signature);
  const r = normalized.slice(0, P256_ECDSA_SECRET_KEY_LENGTH);
  const s = normalized.slice(P256_ECDSA_SECRET_KEY_LENGTH);
  if (
    isZeroScalar(r) ||
    isZeroScalar(s) ||
    compareBigEndian(r, P256_CURVE_ORDER) >= 0 ||
    compareBigEndian(s, P256_CURVE_ORDER) >= 0
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  if (compareBigEndian(s, P256_HALF_CURVE_ORDER) > 0) {
    normalized.set(
      subtractBigEndian(P256_CURVE_ORDER, s),
      P256_ECDSA_SECRET_KEY_LENGTH,
    );
  }
  return normalized;
};

/**
 * P-256 ECDSA backed by @noble/curves.
 *
 * The workspace contract signs SHA-256(message) exactly once and uses DER
 * encoding for signatures because that is what X.509, JOSE, and the Rust
 * P-256 lane expose. We intentionally preserve the Rust vector bytes instead
 * of applying a TypeScript-only low-S normalization policy.
 */
export const ReallyMeP256Ecdsa = {
  /**
   * Returns the canonical low-S form of a canonical DER signature.
   *
   * This is a representation transform for signatures returned by HSMs and
   * platform keystores. It does not verify authenticity; callers must still
   * verify the signature against the exact message that was signed.
   */
  normalizeDerSignatureLowS(signature: Uint8Array): Uint8Array {
    ensureByteArray(signature);
    const compact = decodeEcdsaDerSignature(
      signature,
      P256_ECDSA_SECRET_KEY_LENGTH,
      P256_ECDSA_DER_SIGNATURE_MAX_LENGTH,
    );
    return encodeEcdsaDerSignature(
      normalizeP256JoseSignatureLowS(compact),
      P256_ECDSA_SECRET_KEY_LENGTH,
    );
  },

  /** Returns the low-S form of an exact 64-byte JOSE `r || s` signature. */
  normalizeJoseSignatureLowS(signature: Uint8Array): Uint8Array {
    ensureByteArray(signature);
    return normalizeP256JoseSignatureLowS(signature);
  },

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
      // Buffer.slice() aliases its input; the returned key must own its bytes.
      secretKey: new Uint8Array(secretKey),
    };
  },

  derivePublicKey(secretKey: Uint8Array): Uint8Array {
    ensureByteArray(secretKey);
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
    ensureByteArray(message);
    ensureByteArray(secretKey);
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
    ensureByteArray(signature);
    ensureByteArray(message);
    ensureByteArray(publicKey);
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
