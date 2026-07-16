// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";

const DER_SEQUENCE_TAG = 0x30;
const DER_INTEGER_TAG = 0x02;
const DER_SHORT_FORM_LIMIT = 0x7f;
const DER_LONG_FORM_ONE_BYTE = 0x81;

type DerInteger = Readonly<{
  value: Uint8Array;
  nextOffset: number;
}>;

const byteAt = (bytes: Uint8Array, index: number): number => {
  const value = bytes[index];
  if (value === undefined) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return value;
};

const isAllZero = (bytes: Uint8Array): boolean => {
  for (const byte of bytes) {
    if (byte !== 0) {
      return false;
    }
  }
  return true;
};

const derIntegerContent = (component: Uint8Array): Uint8Array => {
  let firstNonZero = 0;
  while (
    firstNonZero < component.length - 1 &&
    byteAt(component, firstNonZero) === 0
  ) {
    firstNonZero += 1;
  }

  const stripped = component.slice(firstNonZero);
  if ((byteAt(stripped, 0) & 0x80) === 0) {
    return stripped;
  }

  const prefixed = new Uint8Array(stripped.length + 1);
  prefixed.set(stripped, 1);
  return prefixed;
};

const sequenceHeaderLength = (payloadLength: number): number => {
  if (payloadLength <= DER_SHORT_FORM_LIMIT) {
    return 2;
  }
  if (payloadLength <= 0xff) {
    return 3;
  }
  throw new ReallyMeCryptoError("invalid-input");
};

const writeSequenceHeader = (der: Uint8Array, payloadLength: number): number => {
  der[0] = DER_SEQUENCE_TAG;
  if (payloadLength <= DER_SHORT_FORM_LIMIT) {
    der[1] = payloadLength;
    return 2;
  }
  der[1] = DER_LONG_FORM_ONE_BYTE;
  der[2] = payloadLength;
  return 3;
};

const readSequenceHeader = (signature: Uint8Array): number => {
  if (byteAt(signature, 0) !== DER_SEQUENCE_TAG) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const firstLengthByte = byteAt(signature, 1);
  if ((firstLengthByte & 0x80) === 0) {
    if (firstLengthByte !== signature.length - 2) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return 2;
  }

  if (
    firstLengthByte !== DER_LONG_FORM_ONE_BYTE ||
    signature.length < 3 ||
    byteAt(signature, 2) <= DER_SHORT_FORM_LIMIT ||
    byteAt(signature, 2) !== signature.length - 3
  ) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return 3;
};

const parseDerInteger = (
  der: Uint8Array,
  offset: number,
  componentLength: number,
): DerInteger => {
  if (byteAt(der, offset) !== DER_INTEGER_TAG) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const length = byteAt(der, offset + 1);
  if (length === 0 || length > componentLength + 1) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const start = offset + 2;
  const end = start + length;
  if (end > der.length) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const content = der.slice(start, end);
  const first = byteAt(content, 0);
  if ((first & 0x80) !== 0) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  if (content.length > 1 && first === 0) {
    const second = byteAt(content, 1);
    if ((second & 0x80) === 0) {
      throw new ReallyMeCryptoError("invalid-input");
    }
  }

  const normalized = first === 0 ? content.slice(1) : content;
  if (normalized.length > componentLength || isAllZero(normalized)) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const value = new Uint8Array(componentLength);
  value.set(normalized, componentLength - normalized.length);
  return { value, nextOffset: end };
};

export const encodeEcdsaDerSignature = (
  compactSignature: Uint8Array,
  componentLength: number,
): Uint8Array => {
  if (compactSignature.length !== componentLength * 2) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const r = derIntegerContent(compactSignature.slice(0, componentLength));
  const s = derIntegerContent(compactSignature.slice(componentLength));
  const payloadLength = 2 + r.length + 2 + s.length;
  const headerLength = sequenceHeaderLength(payloadLength);
  const der = new Uint8Array(headerLength + payloadLength);
  const firstIntegerOffset = writeSequenceHeader(der, payloadLength);

  der[firstIntegerOffset] = DER_INTEGER_TAG;
  der[firstIntegerOffset + 1] = r.length;
  der.set(r, firstIntegerOffset + 2);
  const secondIntegerOffset = firstIntegerOffset + 2 + r.length;
  der[secondIntegerOffset] = DER_INTEGER_TAG;
  der[secondIntegerOffset + 1] = s.length;
  der.set(s, secondIntegerOffset + 2);
  return der;
};

export const decodeEcdsaDerSignature = (
  signature: Uint8Array,
  componentLength: number,
  maxDerLength: number,
): Uint8Array => {
  if (signature.length < 8 || signature.length > maxDerLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const firstIntegerOffset = readSequenceHeader(signature);
  const r = parseDerInteger(signature, firstIntegerOffset, componentLength);
  const s = parseDerInteger(signature, r.nextOffset, componentLength);
  if (s.nextOffset !== signature.length) {
    throw new ReallyMeCryptoError("invalid-input");
  }

  const compact = new Uint8Array(componentLength * 2);
  compact.set(r.value, 0);
  compact.set(s.value, componentLength);
  return compact;
};
