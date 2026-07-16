// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  base64urlDecode as codecBase64urlDecodeValue,
  base64urlEncode as codecBase64urlEncodeValue,
  canonicalizeJson as codecCanonicalizeJson,
  ReallyMeCodecError,
} from "@reallyme/codec";
import { ReallyMeCryptoError } from "./errors.js";

export type ReallyMeJwkAlgorithm =
  | "Ed25519"
  | "X25519"
  | "P-256"
  | "secp256k1"
  | "ML-DSA-44"
  | "ML-DSA-65"
  | "ML-DSA-87"
  | "ML-KEM-512"
  | "ML-KEM-768"
  | "ML-KEM-1024"
  | "SLH-DSA-SHA2-128s"
  | "X-Wing-768"
  | "X-Wing-1024";

export type ReallyMeOkpJwk = Readonly<{
  alg: string;
  crv: "Ed25519" | "X25519";
  kty: "OKP";
  use: "enc" | "sig";
  x: string;
}>;

export type ReallyMeAkpJwk = Readonly<{
  alg: string;
  kty: "AKP";
  pub: string;
  use: "enc" | "sig";
}>;

export type ReallyMeEcJwk = Readonly<{
  alg: string;
  crv: "P-256" | "secp256k1";
  kty: "EC";
  use: "sig";
  x: string;
  y: string;
}>;

export type ReallyMeJwk = ReallyMeOkpJwk | ReallyMeAkpJwk | ReallyMeEcJwk;

export type ReallyMeJwkKey = Readonly<{
  algorithm: ReallyMeJwkAlgorithm;
  publicKey: Uint8Array;
  jwk: ReallyMeJwk;
}>;

export type ReallyMeJwks = Readonly<{
  keys: ReadonlyArray<ReallyMeJwk>;
}>;

export type ReallyMeJwksKeySet = Readonly<{
  keys: ReadonlyArray<ReallyMeJwkKey>;
}>;

type JwkSpec = Readonly<{
  alg: string;
  crv?: ReallyMeJwkAlgorithm;
  kty: "AKP" | "EC" | "OKP";
  publicKeyLength: number;
  use: "enc" | "sig";
}>;

const jwkSpec = (algorithm: ReallyMeJwkAlgorithm): JwkSpec => {
  switch (algorithm) {
    case "Ed25519":
      return { alg: "EdDSA", crv: "Ed25519", kty: "OKP", publicKeyLength: 32, use: "sig" };
    case "X25519":
      return { alg: "ECDH-ES", crv: "X25519", kty: "OKP", publicKeyLength: 32, use: "enc" };
    case "P-256":
      return { alg: "ES256", crv: "P-256", kty: "EC", publicKeyLength: 33, use: "sig" };
    case "secp256k1":
      return { alg: "ES256K", crv: "secp256k1", kty: "EC", publicKeyLength: 33, use: "sig" };
    case "ML-DSA-44":
      return { alg: "ML-DSA-44", kty: "AKP", publicKeyLength: 1_312, use: "sig" };
    case "ML-DSA-65":
      return { alg: "ML-DSA-65", kty: "AKP", publicKeyLength: 1_952, use: "sig" };
    case "ML-DSA-87":
      return { alg: "ML-DSA-87", kty: "AKP", publicKeyLength: 2_592, use: "sig" };
    case "ML-KEM-512":
      return { alg: "ML-KEM-512", kty: "AKP", publicKeyLength: 800, use: "enc" };
    case "ML-KEM-768":
      return { alg: "ML-KEM-768", kty: "AKP", publicKeyLength: 1_184, use: "enc" };
    case "ML-KEM-1024":
      return { alg: "ML-KEM-1024", kty: "AKP", publicKeyLength: 1_568, use: "enc" };
    case "SLH-DSA-SHA2-128s":
      return { alg: "SLH-DSA-SHA2-128s", kty: "AKP", publicKeyLength: 32, use: "sig" };
    case "X-Wing-768":
      return { alg: "X-Wing-768", kty: "AKP", publicKeyLength: 1_216, use: "enc" };
    case "X-Wing-1024":
      return { alg: "X-Wing-1024", kty: "AKP", publicKeyLength: 1_600, use: "enc" };
  }
};

const ensureLength = (bytes: Uint8Array, expectedLength: number): void => {
  if (bytes.length !== expectedLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const readString = (value: unknown, name: string): string => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const property = Reflect.get(value, name);
  if (typeof property !== "string") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return property;
};

const privateJwkMemberNames: ReadonlyArray<string> = [
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "k",
  "priv",
  "privateKey",
  "secretKey",
];

const rejectPrivateKeyMaterial = (value: unknown): void => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  for (const name of privateJwkMemberNames) {
    if (Reflect.has(value, name)) {
      throw new ReallyMeCryptoError("invalid-input");
    }
  }
};

const optionalStringMatches = (
  value: unknown,
  name: string,
  expected: string,
): void => {
  if (typeof value !== "object" || value === null) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const property = Reflect.get(value, name);
  if (property !== undefined && property !== expected) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const specFromCurve = (curve: string): JwkSpec => {
  switch (curve) {
    case "Ed25519":
    case "X25519":
    case "P-256":
    case "secp256k1":
      return jwkSpec(curve);
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const specFromAlgorithm = (algorithm: string): JwkSpec => {
  switch (algorithm) {
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87":
    case "ML-KEM-512":
    case "ML-KEM-768":
    case "ML-KEM-1024":
    case "SLH-DSA-SHA2-128s":
    case "X-Wing-768":
    case "X-Wing-1024":
      return jwkSpec(algorithm);
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const decompressEc = (
  algorithm: "P-256" | "secp256k1",
  publicKey: Uint8Array,
): Uint8Array => {
  try {
    const point =
      algorithm === "P-256"
        ? p256.Point.fromBytes(publicKey)
        : secp256k1.Point.fromBytes(publicKey);
    return point.toBytes(false);
  } catch {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const compressEc = (
  algorithm: "P-256" | "secp256k1",
  x: Uint8Array,
  y: Uint8Array,
): Uint8Array => {
  ensureLength(x, 32);
  ensureLength(y, 32);
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  try {
    const point =
      algorithm === "P-256"
        ? p256.Point.fromBytes(uncompressed)
        : secp256k1.Point.fromBytes(uncompressed);
    return point.toBytes(true);
  } catch {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const mapCodecError = (error: unknown): ReallyMeCryptoError => {
  if (error instanceof ReallyMeCodecError && error.code === "provider-failure") {
    return new ReallyMeCryptoError("provider-failure");
  }
  return new ReallyMeCryptoError("invalid-input");
};

const codecBase64urlEncode = (bytes: Uint8Array): string => {
  try {
    return codecBase64urlEncodeValue(bytes);
  } catch (error: unknown) {
    throw mapCodecError(error);
  }
};

const codecBase64urlDecode = (encoded: string): Uint8Array => {
  try {
    return codecBase64urlDecodeValue(encoded);
  } catch (error: unknown) {
    throw mapCodecError(error);
  }
};

const codecBase64urlDecodeCanonical = (encoded: string): Uint8Array => {
  const bytes = codecBase64urlDecode(encoded);
  if (codecBase64urlEncode(bytes) !== encoded) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return bytes;
};

const toJcs = (jwk: ReallyMeJwk): string => {
  const key = ReallyMeJwk.fromJwk(jwk);
  try {
    return codecCanonicalizeJson(key.jwk);
  } catch (error: unknown) {
    throw mapCodecError(error);
  }
};

export const ReallyMeJwk = {
  toJwk(algorithm: ReallyMeJwkAlgorithm, publicKey: Uint8Array): ReallyMeJwk {
    const spec = jwkSpec(algorithm);
    ensureLength(publicKey, spec.publicKeyLength);
    if (spec.kty === "EC") {
      const ecAlgorithm = spec.crv === "P-256" ? "P-256" : "secp256k1";
      const uncompressed = decompressEc(ecAlgorithm, publicKey);
      return {
        alg: spec.alg,
        crv: ecAlgorithm,
        kty: "EC",
        use: "sig",
        x: codecBase64urlEncode(uncompressed.slice(1, 33)),
        y: codecBase64urlEncode(uncompressed.slice(33, 65)),
      };
    }
    if (spec.kty === "AKP") {
      return {
        alg: spec.alg,
        kty: "AKP",
        pub: codecBase64urlEncode(publicKey),
        use: spec.use,
      };
    }

    const crv = spec.crv;
    if (crv !== "Ed25519" && crv !== "X25519") {
      throw new ReallyMeCryptoError("unsupported-algorithm");
    }
    return {
      alg: spec.alg,
      crv,
      kty: "OKP",
      use: spec.use,
      x: codecBase64urlEncode(publicKey),
    };
  },

  fromJwk(value: unknown): ReallyMeJwkKey {
    rejectPrivateKeyMaterial(value);
    const kty = readString(value, "kty");
    const spec =
      kty === "AKP"
        ? specFromAlgorithm(readString(value, "alg"))
        : specFromCurve(readString(value, "crv"));
    if (kty !== spec.kty) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    optionalStringMatches(value, "alg", spec.alg);
    optionalStringMatches(value, "use", spec.use);

    if (spec.kty === "EC") {
      const ecAlgorithm = spec.crv === "P-256" ? "P-256" : "secp256k1";
      const x = codecBase64urlDecodeCanonical(readString(value, "x"));
      const y = codecBase64urlDecodeCanonical(readString(value, "y"));
      const publicKey = compressEc(ecAlgorithm, x, y);
      ensureLength(publicKey, spec.publicKeyLength);
      const jwk = ReallyMeJwk.toJwk(ecAlgorithm, publicKey);
      return { algorithm: ecAlgorithm, publicKey, jwk };
    }

    if (spec.kty === "OKP") {
      const crv = spec.crv;
      if (crv !== "Ed25519" && crv !== "X25519") {
        throw new ReallyMeCryptoError("unsupported-algorithm");
      }
      const publicKey = codecBase64urlDecodeCanonical(readString(value, "x"));
      ensureLength(publicKey, spec.publicKeyLength);
      const jwk = ReallyMeJwk.toJwk(crv, publicKey);
      return { algorithm: crv, publicKey, jwk };
    }

    const algorithm = readString(value, "alg");
    const akpSpec = specFromAlgorithm(algorithm);
    const publicKey = codecBase64urlDecodeCanonical(readString(value, "pub"));
    ensureLength(publicKey, akpSpec.publicKeyLength);
    switch (algorithm) {
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
      case "SLH-DSA-SHA2-128s":
      case "X-Wing-768":
      case "X-Wing-1024": {
        const jwk = ReallyMeJwk.toJwk(algorithm, publicKey);
        return { algorithm, publicKey, jwk };
      }
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  toJwks(keys: ReadonlyArray<ReallyMeJwk>): ReallyMeJwks {
    return { keys: [...keys] };
  },

  fromJwks(value: unknown): ReallyMeJwksKeySet {
    if (typeof value !== "object" || value === null) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    const keys = Reflect.get(value, "keys");
    if (!Array.isArray(keys)) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return { keys: keys.map((key: unknown) => ReallyMeJwk.fromJwk(key)) };
  },

  publicKeyBytes(jwk: ReallyMeJwk): Uint8Array {
    return ReallyMeJwk.fromJwk(jwk).publicKey;
  },

  toJcs(jwk: ReallyMeJwk): string {
    return toJcs(jwk);
  },
} as const;
