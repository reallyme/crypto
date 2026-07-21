// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";

export const HMAC_MAX_KEY_LENGTH = 4096;
export const HMAC_SHA256_TAG_LENGTH = 32;
export const HMAC_SHA384_TAG_LENGTH = 48;
export const HMAC_SHA512_TAG_LENGTH = 64;

export const ReallyMeHmac = {
  authenticateSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
    validateKey(key);
    return hmac(sha256, key, message);
  },

  authenticateSha384(key: Uint8Array, message: Uint8Array): Uint8Array {
    validateKey(key);
    return hmac(sha384, key, message);
  },

  authenticateSha512(key: Uint8Array, message: Uint8Array): Uint8Array {
    validateKey(key);
    return hmac(sha512, key, message);
  },

  verifySha256(tag: Uint8Array, key: Uint8Array, message: Uint8Array): boolean {
    if (tag.length !== HMAC_SHA256_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return verifyAndClearExpectedTag(tag, ReallyMeHmac.authenticateSha256(key, message));
  },

  verifySha384(tag: Uint8Array, key: Uint8Array, message: Uint8Array): boolean {
    if (tag.length !== HMAC_SHA384_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return verifyAndClearExpectedTag(tag, ReallyMeHmac.authenticateSha384(key, message));
  },

  verifySha512(tag: Uint8Array, key: Uint8Array, message: Uint8Array): boolean {
    if (tag.length !== HMAC_SHA512_TAG_LENGTH) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return verifyAndClearExpectedTag(tag, ReallyMeHmac.authenticateSha512(key, message));
  },
} as const;

function validateKey(key: Uint8Array): void {
  if (key.length === 0 || key.length > HMAC_MAX_KEY_LENGTH) {
    throw new ReallyMeCryptoError("invalid-input");
  }
}

function constantTimeEquals(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (const [index, leftByte] of left.entries()) {
    const rightByte = right[index];
    if (rightByte === undefined) {
      return false;
    }
    difference |= leftByte ^ rightByte;
  }
  return difference === 0;
}

function verifyAndClearExpectedTag(tag: Uint8Array, expectedTag: Uint8Array): boolean {
  try {
    return constantTimeEquals(tag, expectedTag);
  } finally {
    // Noble returns a new typed array. Clear it immediately so verification
    // does not retain key-derived authentication material until a GC cycle.
    expectedTag.fill(0);
  }
}
