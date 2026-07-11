// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";

export const PBKDF2_MIN_INPUT_LENGTH = 1;
export const PBKDF2_MAX_INPUT_LENGTH = 4096;
// The primitive accepts any count >= 1 so it can verify PBKDF2 hashes created
// elsewhere at their stored iteration count (a required interop use), matching
// the Rust lane. It is NOT a security floor; see the recommended minimums
// below for deriving *new* password keys.
export const PBKDF2_MIN_ITERATIONS = 1;
export const PBKDF2_MIN_OUTPUT_LENGTH = 1;
export const PBKDF2_MAX_OUTPUT_LENGTH = 4096;

/**
 * OWASP Password Storage Cheat Sheet minimum iteration counts for deriving a
 * *new* password key.
 * The primitive does not enforce these (it must remain able to verify
 * externally created hashes), so callers creating new key material SHOULD
 * pass at least the value for their PRF.
 */
export const PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA256 = 600_000;
export const PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA512 = 220_000;

export const ReallyMePbkdf2 = {
  /**
   * PBKDF2-HMAC-SHA-256. For a new password key pass at least
   * {@link PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA256} iterations; lower counts
   * are accepted only to verify hashes created elsewhere.
   */
  deriveHmacSha256(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    outputLength: number,
  ): Uint8Array {
    validate(password, salt, iterations, outputLength);
    return pbkdf2(sha256, password, salt, { c: iterations, dkLen: outputLength });
  },

  /**
   * PBKDF2-HMAC-SHA-512. For a new password key pass at least
   * {@link PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA512} iterations; lower counts
   * are accepted only to verify hashes created elsewhere.
   */
  deriveHmacSha512(
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    outputLength: number,
  ): Uint8Array {
    validate(password, salt, iterations, outputLength);
    return pbkdf2(sha512, password, salt, { c: iterations, dkLen: outputLength });
  },
} as const;

function validate(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  outputLength: number,
): void {
  if (
    password.length < PBKDF2_MIN_INPUT_LENGTH ||
    password.length > PBKDF2_MAX_INPUT_LENGTH ||
    salt.length < PBKDF2_MIN_INPUT_LENGTH ||
    salt.length > PBKDF2_MAX_INPUT_LENGTH ||
    !Number.isInteger(iterations) ||
    iterations < PBKDF2_MIN_ITERATIONS ||
    !Number.isInteger(outputLength) ||
    outputLength < PBKDF2_MIN_OUTPUT_LENGTH ||
    outputLength > PBKDF2_MAX_OUTPUT_LENGTH
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
}
