// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0


import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ReallyMeCryptoError } from "./errors.js";
import type {
  ReallyMeJwkAlgorithm,
  ReallyMeJwkKey,
  ReallyMeJwksKeySet,
} from "./jwk.js";
import { MAX_JWKS_KEYS, ReallyMeJwk } from "./jwk.js";
import {
  ensureByteArrayAtMost,
  MAX_CRYPTO_INPUT_LENGTH,
} from "./validateBytes.js";
import {
  CryptoAlgorithmIdentifierSchema,
  JsonWebKeySchema,
  JsonWebKeySetSchema,
  KemAlgorithm,
  KeyAgreementAlgorithm,
  SignatureAlgorithm,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import type {
  CryptoAlgorithmIdentifier,
  JsonWebKey,
  JsonWebKeySet,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

const MAX_JWK_CANONICAL_JCS_LENGTH = 8_192;

const asciiToBytes = (value: string): Uint8Array => {
  if (value.length > MAX_JWK_CANONICAL_JCS_LENGTH) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit > 0x7f) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    bytes[index] = codeUnit;
  }
  return bytes;
};

const asciiFromBytes = (value: Uint8Array): string => {
  ensureByteArrayAtMost(value, MAX_JWK_CANONICAL_JCS_LENGTH);
  const characters: string[] = [];
  for (const byte of value) {
    if (byte > 0x7f) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    characters.push(String.fromCharCode(byte));
  }
  return characters.join("");
};

const withJwkProtoBoundaryErrors = <T>(operation: () => T): T => {
  try {
    return operation();
  } catch (error: unknown) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const signatureJwkAlgorithmToProto = (
  value: ReallyMeJwkAlgorithm,
): SignatureAlgorithm => {
  switch (value) {
    case "Ed25519":
      return SignatureAlgorithm.ED25519;
    case "P-256":
      return SignatureAlgorithm.ECDSA_P256_SHA256;
    case "secp256k1":
      return SignatureAlgorithm.ECDSA_SECP256K1_SHA256;
    case "ML-DSA-44":
      return SignatureAlgorithm.ML_DSA_44;
    case "ML-DSA-65":
      return SignatureAlgorithm.ML_DSA_65;
    case "ML-DSA-87":
      return SignatureAlgorithm.ML_DSA_87;
    case "SLH-DSA-SHA2-128s":
      return SignatureAlgorithm.SLH_DSA_SHA2_128S;
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const jwkAlgorithmToProto = (
  value: ReallyMeJwkAlgorithm,
): CryptoAlgorithmIdentifier => {
  switch (value) {
    case "X25519":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "keyAgreement",
          value: KeyAgreementAlgorithm.X25519,
        },
      });
    case "ML-KEM-512":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_512,
        },
      });
    case "ML-KEM-768":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_768,
        },
      });
    case "ML-KEM-1024":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_1024,
        },
      });
    case "X-Wing-768":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.X_WING_768,
        },
      });
    default:
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "signature",
          value: signatureJwkAlgorithmToProto(value),
        },
      });
  }
};

const signatureJwkAlgorithmFromProto = (
  value: SignatureAlgorithm,
): ReallyMeJwkAlgorithm => {
  switch (value) {
    case SignatureAlgorithm.ED25519:
      return "Ed25519";
    case SignatureAlgorithm.ECDSA_P256_SHA256:
      return "P-256";
    case SignatureAlgorithm.ECDSA_SECP256K1_SHA256:
      return "secp256k1";
    case SignatureAlgorithm.ML_DSA_44:
      return "ML-DSA-44";
    case SignatureAlgorithm.ML_DSA_65:
      return "ML-DSA-65";
    case SignatureAlgorithm.ML_DSA_87:
      return "ML-DSA-87";
    case SignatureAlgorithm.SLH_DSA_SHA2_128S:
      return "SLH-DSA-SHA2-128s";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const jwkAlgorithmFromProto = (
  value: CryptoAlgorithmIdentifier,
): ReallyMeJwkAlgorithm => {
  switch (value.algorithm.case) {
    case "signature":
      return signatureJwkAlgorithmFromProto(value.algorithm.value);
    case "keyAgreement":
      if (value.algorithm.value === KeyAgreementAlgorithm.X25519) {
        return "X25519";
      }
      throw new ReallyMeCryptoError("unsupported-algorithm");
    case "kem":
      switch (value.algorithm.value) {
        case KemAlgorithm.ML_KEM_512:
          return "ML-KEM-512";
        case KemAlgorithm.ML_KEM_768:
          return "ML-KEM-768";
        case KemAlgorithm.ML_KEM_1024:
          return "ML-KEM-1024";
        case KemAlgorithm.X_WING_768:
          return "X-Wing-768";
        default:
          throw new ReallyMeCryptoError("unsupported-algorithm");
      }
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const jsonWebKeyToProto = (key: ReallyMeJwkKey): JsonWebKey =>
  create(JsonWebKeySchema, {
    algorithm: jwkAlgorithmToProto(key.algorithm),
    publicKey: key.publicKey,
    canonicalJcs: asciiToBytes(ReallyMeJwk.toJcs(key.jwk)),
  });

export const jsonWebKeyToProtoBytes = (key: ReallyMeJwkKey): Uint8Array =>
  toBinary(JsonWebKeySchema, jsonWebKeyToProto(key));

export const jsonWebKeyFromProto = (value: JsonWebKey): ReallyMeJwkKey =>
  withJwkProtoBoundaryErrors(() => {
    // Read each field once so a hostile message proxy cannot change values
    // between validation and construction.
    const algorithmValue = value.algorithm;
    const publicKey = value.publicKey;
    const canonicalJcs = value.canonicalJcs;
    const algorithm = algorithmValue === undefined
      ? undefined
      : jwkAlgorithmFromProto(algorithmValue);
    if (algorithm === undefined) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    ensureByteArrayAtMost(publicKey, MAX_CRYPTO_INPUT_LENGTH);
    const jwk = ReallyMeJwk.toJwk(algorithm, publicKey);
    if (canonicalJcs.length > 0) {
      const expected = ReallyMeJwk.toJcs(jwk);
      if (asciiFromBytes(canonicalJcs) !== expected) {
        throw new ReallyMeCryptoError("invalid-input");
      }
    }
    return { algorithm, publicKey, jwk };
  });

export const jsonWebKeyFromProtoBytes = (bytes: Uint8Array): ReallyMeJwkKey =>
  withJwkProtoBoundaryErrors(() => {
    ensureByteArrayAtMost(bytes, MAX_CRYPTO_INPUT_LENGTH);
    return jsonWebKeyFromProto(fromBinary(JsonWebKeySchema, bytes));
  });

export const jsonWebKeySetToProto = (
  keySet: ReallyMeJwksKeySet,
): JsonWebKeySet =>
  create(JsonWebKeySetSchema, {
    keys: keySet.keys.map((key) => jsonWebKeyToProto(key)),
  });

export const jsonWebKeySetToProtoBytes = (
  keySet: ReallyMeJwksKeySet,
): Uint8Array => toBinary(JsonWebKeySetSchema, jsonWebKeySetToProto(keySet));

export const jsonWebKeySetFromProto = (
  value: JsonWebKeySet,
): ReallyMeJwksKeySet =>
  withJwkProtoBoundaryErrors(() => {
    const keys = value.keys;
    if (!Array.isArray(keys) || keys.length > MAX_JWKS_KEYS) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    return { keys: keys.map((key) => jsonWebKeyFromProto(key)) };
  });

export const jsonWebKeySetFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeJwksKeySet =>
  withJwkProtoBoundaryErrors(() => {
    ensureByteArrayAtMost(bytes, MAX_CRYPTO_INPUT_LENGTH);
    return jsonWebKeySetFromProto(fromBinary(JsonWebKeySetSchema, bytes));
  });
