// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export type ReallyMeMulticodecTag =
  | "encryption"
  | "hash"
  | "key"
  | "multihash"
  | "multikey";

export type ReallyMeKeyMaterialKind =
  | "not-key"
  | "public-key"
  | "private-key"
  | "symmetric-key";

export type ReallyMeMulticodecMetadata = Readonly<{
  name: string;
  alg: string;
  tag: ReallyMeMulticodecTag;
  keyMaterial: ReallyMeKeyMaterialKind;
  prefix: Uint8Array;
  expectedKeyLength?: number;
}>;

export type ReallyMeParsedMultikey = Readonly<{
  codecName: string;
  algorithmName: string;
  publicKey: Uint8Array;
  expectedPublicKeyLength?: number;
}>;

export type ReallyMeDagCborCidVerification = Readonly<{
  valid: boolean;
  expectedCid: string;
  actualCid: string;
}>;

const validTags: ReadonlySet<string> = new Set([
  "encryption",
  "hash",
  "key",
  "multihash",
  "multikey",
]);

const validKeyMaterialKinds: ReadonlySet<string> = new Set([
  "not-key",
  "public-key",
  "private-key",
  "symmetric-key",
]);

const ensureStringInput = (value: string): void => {
  if (typeof value !== "string" || value.length === 0) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const ensureBytesInput = (value: Uint8Array): void => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const requireObjectOutput = (value: unknown): object => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

const readStringOutput = (value: unknown): string => {
  if (typeof value !== "string") {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

const readBytesOutput = (value: unknown): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

const readStringProperty = (object: object, propertyName: string): string => {
  const property: unknown = Reflect.get(object, propertyName);
  if (typeof property !== "string" || property.length === 0) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

const readBooleanProperty = (object: object, propertyName: string): boolean => {
  const property: unknown = Reflect.get(object, propertyName);
  if (typeof property !== "boolean") {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

const readBytesProperty = (object: object, propertyName: string): Uint8Array => {
  const property: unknown = Reflect.get(object, propertyName);
  if (!(property instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

const readOptionalLengthProperty = (
  object: object,
  propertyName: string,
): number | undefined => {
  const property: unknown = Reflect.get(object, propertyName);
  if (property === undefined) {
    return undefined;
  }
  if (typeof property !== "number" || !Number.isSafeInteger(property) || property < 0) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return property;
};

const readTagProperty = (object: object): ReallyMeMulticodecTag => {
  const tag = readStringProperty(object, "tag");
  if (!validTags.has(tag)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  switch (tag) {
    case "encryption":
    case "hash":
    case "key":
    case "multihash":
    case "multikey":
      return tag;
    default:
      throw new ReallyMeCryptoError("provider-failure");
  }
};

const readKeyMaterialProperty = (object: object): ReallyMeKeyMaterialKind => {
  const keyMaterial = readStringProperty(object, "keyMaterial");
  if (!validKeyMaterialKinds.has(keyMaterial)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  switch (keyMaterial) {
    case "not-key":
    case "public-key":
    case "private-key":
    case "symmetric-key":
      return keyMaterial;
    default:
      throw new ReallyMeCryptoError("provider-failure");
  }
};

const readMulticodecMetadata = (value: unknown): ReallyMeMulticodecMetadata => {
  const object = requireObjectOutput(value);
  const expectedKeyLength = readOptionalLengthProperty(object, "expectedKeyLength");
  if (expectedKeyLength === undefined) {
    return {
      name: readStringProperty(object, "name"),
      alg: readStringProperty(object, "alg"),
      tag: readTagProperty(object),
      keyMaterial: readKeyMaterialProperty(object),
      prefix: readBytesProperty(object, "prefix"),
    };
  }
  return {
    name: readStringProperty(object, "name"),
    alg: readStringProperty(object, "alg"),
    tag: readTagProperty(object),
    keyMaterial: readKeyMaterialProperty(object),
    prefix: readBytesProperty(object, "prefix"),
    expectedKeyLength,
  };
};

const readParsedMultikey = (value: unknown): ReallyMeParsedMultikey => {
  const object = requireObjectOutput(value);
  const expectedPublicKeyLength = readOptionalLengthProperty(
    object,
    "expectedPublicKeyLength",
  );
  if (expectedPublicKeyLength === undefined) {
    return {
      codecName: readStringProperty(object, "codecName"),
      algorithmName: readStringProperty(object, "algorithmName"),
      publicKey: readBytesProperty(object, "publicKey"),
    };
  }
  return {
    codecName: readStringProperty(object, "codecName"),
    algorithmName: readStringProperty(object, "algorithmName"),
    publicKey: readBytesProperty(object, "publicKey"),
    expectedPublicKeyLength,
  };
};

const readCidVerification = (value: unknown): ReallyMeDagCborCidVerification => {
  const object = requireObjectOutput(value);
  return {
    valid: readBooleanProperty(object, "valid"),
    expectedCid: readStringProperty(object, "expectedCid"),
    actualCid: readStringProperty(object, "actualCid"),
  };
};

const asciiBytesToString = (bytes: Uint8Array): string => {
  let value = "";
  for (const byte of bytes) {
    if (byte > 0x7f) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    value += String.fromCharCode(byte);
  }
  return value;
};

export const ReallyMeCodecs = {
  base64urlEncode(bytes: Uint8Array): string {
    ensureBytesInput(bytes);
    return readStringOutput(requireReallyMeWasmProvider().base64urlEncode(bytes));
  },

  base64urlDecode(encoded: string): Uint8Array {
    ensureStringInput(encoded);
    return readBytesOutput(requireReallyMeWasmProvider().base64urlDecode(encoded));
  },

  base64urlDecodeBytes(encoded: Uint8Array): Uint8Array {
    ensureBytesInput(encoded);
    return readBytesOutput(
      requireReallyMeWasmProvider().base64urlDecode(asciiBytesToString(encoded)),
    );
  },

  multibaseBase64urlEncode(bytes: Uint8Array): string {
    ensureBytesInput(bytes);
    return readStringOutput(
      requireReallyMeWasmProvider().multibaseBase64urlEncode(bytes),
    );
  },

  multibaseBase58btcEncode(bytes: Uint8Array): string {
    ensureBytesInput(bytes);
    return readStringOutput(
      requireReallyMeWasmProvider().multibaseBase58btcEncode(bytes),
    );
  },

  multibaseDecode(encoded: string): Uint8Array {
    ensureStringInput(encoded);
    return readBytesOutput(requireReallyMeWasmProvider().multibaseDecode(encoded));
  },

  multicodecPrefixForName(codecName: string): ReallyMeMulticodecMetadata {
    ensureStringInput(codecName);
    return readMulticodecMetadata(
      requireReallyMeWasmProvider().multicodecPrefixForName(codecName),
    );
  },

  multicodecLookupPrefix(bytes: Uint8Array): ReallyMeMulticodecMetadata {
    ensureBytesInput(bytes);
    return readMulticodecMetadata(
      requireReallyMeWasmProvider().multicodecLookupPrefix(bytes),
    );
  },

  multikeyEncode(codecName: string, publicKey: Uint8Array): string {
    ensureStringInput(codecName);
    ensureBytesInput(publicKey);
    return readStringOutput(
      requireReallyMeWasmProvider().multikeyEncode(codecName, publicKey),
    );
  },

  multikeyParse(multikey: string): ReallyMeParsedMultikey {
    ensureStringInput(multikey);
    return readParsedMultikey(requireReallyMeWasmProvider().multikeyParse(multikey));
  },

  dagCborComputeCid(bytes: Uint8Array): string {
    ensureBytesInput(bytes);
    return readStringOutput(requireReallyMeWasmProvider().dagCborComputeCid(bytes));
  },

  dagCborVerifyCid(cid: string, bytes: Uint8Array): ReallyMeDagCborCidVerification {
    ensureStringInput(cid);
    ensureBytesInput(bytes);
    return readCidVerification(
      requireReallyMeWasmProvider().dagCborVerifyCid(cid, bytes),
    );
  },
} as const;
