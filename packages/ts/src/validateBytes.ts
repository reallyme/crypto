// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";

// Match the structured operation boundary so direct primitive facades cannot
// ask a provider to copy or allocate an attacker-controlled unbounded buffer.
export const MAX_CRYPTO_INPUT_LENGTH = 1_048_576;

export const ensureByteArray = (value: Uint8Array): void => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const ensureByteArrayAtMost = (
  value: Uint8Array,
  maximumLength: number,
): void => {
  ensureByteArray(value);
  if (value.length > maximumLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const ensureBytes = (value: Uint8Array, expectedLength: number): void => {
  ensureByteArray(value);
  if (value.length !== expectedLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const byteArraysOverlap = (
  left: Uint8Array,
  right: Uint8Array,
): boolean => {
  if (left.buffer !== right.buffer) {
    return false;
  }
  const leftEnd = left.byteOffset + left.byteLength;
  const rightEnd = right.byteOffset + right.byteLength;
  return left.byteOffset < rightEnd && right.byteOffset < leftEnd;
};

export const ensureIndependentByteArray = (
  value: Uint8Array,
  disallowedViews: ReadonlyArray<Uint8Array>,
): void => {
  // A disjoint view into the same ArrayBuffer is still not independently
  // owned: transferring or detaching the caller's buffer would invalidate the
  // provider output too. Provider results must own separate backing storage.
  if (disallowedViews.some((view) => value.buffer === view.buffer)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
};

const readProviderByteArrayProperty = (
  value: unknown,
  propertyName: string,
): Uint8Array => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("provider-failure");
  }

  let property: unknown;
  try {
    property = Reflect.get(value, propertyName);
  } catch (_error: unknown) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  if (!(property instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

export const readIndependentByteArrayProperty = (
  value: unknown,
  propertyName: string,
  expectedLength: number,
  disallowedViews: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  const property = readProviderByteArrayProperty(value, propertyName);
  // Check ownership before cleanup so a malformed provider cannot make the
  // validator erase a caller-owned input view.
  ensureIndependentByteArray(property, disallowedViews);
  if (property.length !== expectedLength) {
    property.fill(0);
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

export const readIndependentProviderBytes = (
  value: unknown,
  expectedLength: number,
  disallowedViews: ReadonlyArray<Uint8Array>,
): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  // Provider-owned secret outputs are cleared on malformed length, but only
  // after proving the provider did not hand back a caller-owned buffer.
  ensureIndependentByteArray(value, disallowedViews);
  if (value.length !== expectedLength) {
    value.fill(0);
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};
