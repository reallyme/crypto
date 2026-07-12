// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 } from "@noble/hashes/sha2.js";
import { ReallyMeCryptoError } from "./errors.js";

export const JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH = 32;
export const JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH = 4096;
export const JWA_CONCAT_KDF_MAX_INFO_LENGTH = 4096;
export const JWA_CONCAT_KDF_MIN_OUTPUT_LENGTH = 1;
export const JWA_CONCAT_KDF_MAX_OUTPUT_LENGTH = 4096;

export const ReallyMeJwaConcatKdf = {
  deriveSha256(
    sharedSecret: Uint8Array,
    algorithmId: Uint8Array,
    partyUInfo: Uint8Array,
    partyVInfo: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    validate(sharedSecret, algorithmId, partyUInfo, partyVInfo, outputLength);
    const outputBits = outputLength * 8;
    const otherInfo = buildOtherInfo(algorithmId, partyUInfo, partyVInfo, outputBits);
    const reps = Math.ceil(outputLength / JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH);
    const derived = new Uint8Array(reps * JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH);

    for (let counter = 1; counter <= reps; counter += 1) {
      const counterBytes = uint32be(counter);
      const digest = sha256(concatBytes(counterBytes, sharedSecret, otherInfo));
      derived.set(digest, (counter - 1) * JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH);
      counterBytes.fill(0);
    }

    const output = derived.slice(0, outputLength);
    derived.fill(0);
    otherInfo.fill(0);
    return output;
  },
};

function validate(
  sharedSecret: Uint8Array,
  algorithmId: Uint8Array,
  partyUInfo: Uint8Array,
  partyVInfo: Uint8Array,
  outputLength: number,
): void {
  if (
    sharedSecret.length === 0 ||
    sharedSecret.length > JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH ||
    algorithmId.length === 0 ||
    algorithmId.length > JWA_CONCAT_KDF_MAX_INFO_LENGTH ||
    partyUInfo.length > JWA_CONCAT_KDF_MAX_INFO_LENGTH ||
    partyVInfo.length > JWA_CONCAT_KDF_MAX_INFO_LENGTH ||
    !Number.isInteger(outputLength) ||
    outputLength < JWA_CONCAT_KDF_MIN_OUTPUT_LENGTH ||
    outputLength > JWA_CONCAT_KDF_MAX_OUTPUT_LENGTH
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
}

function buildOtherInfo(
  algorithmId: Uint8Array,
  partyUInfo: Uint8Array,
  partyVInfo: Uint8Array,
  outputBits: number,
): Uint8Array {
  return concatBytes(
    lengthPrefixed(algorithmId),
    lengthPrefixed(partyUInfo),
    lengthPrefixed(partyVInfo),
    uint32be(outputBits),
  );
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(uint32be(bytes.length), bytes);
}

function uint32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const output = new Uint8Array(4);
  output[0] = Math.floor(value / 0x1000000);
  output[1] = Math.floor(value / 0x10000) & 0xff;
  output[2] = Math.floor(value / 0x100) & 0xff;
  output[3] = value & 0xff;
  return output;
}

function concatBytes(...parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let length = 0;
  for (const part of parts) {
    length += part.length;
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
