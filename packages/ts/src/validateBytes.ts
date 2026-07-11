// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";

export const ensureBytes = (value: Uint8Array, expectedLength: number): void => {
  if (value.length !== expectedLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const readByteArrayProperty = (
  value: unknown,
  propertyName: string,
  expectedLength: number,
): Uint8Array => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("provider-failure");
  }

  const property: unknown = Reflect.get(value, propertyName);
  if (!(property instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  ensureBytes(property, expectedLength);
  return property;
};
