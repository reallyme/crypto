// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0


import { create } from "@bufbuild/protobuf";
import type {
  ReallyMeHpkeSuite,
  ReallyMeKemAlgorithm,
  ReallyMeKeyAgreementAlgorithm,
  ReallyMeSignatureAlgorithm,
} from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import {
  hpkeSuiteFromProto,
  hpkeSuiteToProto,
  kemAlgorithmFromProto,
  kemAlgorithmToProto,
  keyAgreementAlgorithmFromProto,
  keyAgreementAlgorithmToProto,
  signatureAlgorithmFromProto,
  signatureAlgorithmToProto,
} from "./protoAlgorithms.js";
import {
  CryptoAlgorithmIdentifierSchema,
  MulticodecKeyAlgorithm,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import type { CryptoAlgorithmIdentifier } from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

export type ReallyMeMulticodecKeyAlgorithm =
  | "ed25519-pub"
  | "x25519-pub"
  | "secp256k1-pub"
  | "p256-pub"
  | "p384-pub"
  | "p521-pub"
  | "ed448-pub"
  | "rsa-pub"
  | "mlkem-512-pub"
  | "mlkem-768-pub"
  | "mlkem-1024-pub"
  | "mldsa-44-pub"
  | "mldsa-65-pub"
  | "mldsa-87-pub";

export const signatureAlgorithmIdentifierToProto = (
  value: ReallyMeSignatureAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "signature", value: signatureAlgorithmToProto(value) },
  });

export const keyAgreementAlgorithmIdentifierToProto = (
  value: ReallyMeKeyAgreementAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "keyAgreement", value: keyAgreementAlgorithmToProto(value) },
  });

export const kemAlgorithmIdentifierToProto = (
  value: ReallyMeKemAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "kem", value: kemAlgorithmToProto(value) },
  });

export const hpkeSuiteIdentifierToProto = (
  value: ReallyMeHpkeSuite,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "hpkeSuite", value: hpkeSuiteToProto(value) },
  });

export const signatureAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeSignatureAlgorithm => {
  if (value?.algorithm.case !== "signature") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return signatureAlgorithmFromProto(value.algorithm.value);
};

export const keyAgreementAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeKeyAgreementAlgorithm => {
  if (value?.algorithm.case !== "keyAgreement") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return keyAgreementAlgorithmFromProto(value.algorithm.value);
};

export const kemAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeKemAlgorithm => {
  if (value?.algorithm.case !== "kem") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return kemAlgorithmFromProto(value.algorithm.value);
};

export const hpkeSuiteFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeHpkeSuite => {
  if (value?.algorithm.case !== "hpkeSuite") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return hpkeSuiteFromProto(value.algorithm.value);
};

export const multicodecKeyAlgorithmFromProto = (
  value: MulticodecKeyAlgorithm,
): ReallyMeMulticodecKeyAlgorithm => {
  switch (value) {
    case MulticodecKeyAlgorithm.ED25519_PUB:
      return "ed25519-pub";
    case MulticodecKeyAlgorithm.X25519_PUB:
      return "x25519-pub";
    case MulticodecKeyAlgorithm.SECP256K1_PUB:
      return "secp256k1-pub";
    case MulticodecKeyAlgorithm.P256_PUB:
      return "p256-pub";
    case MulticodecKeyAlgorithm.P384_PUB:
      return "p384-pub";
    case MulticodecKeyAlgorithm.P521_PUB:
      return "p521-pub";
    case MulticodecKeyAlgorithm.ED448_PUB:
      return "ed448-pub";
    case MulticodecKeyAlgorithm.RSA_PUB:
      return "rsa-pub";
    case MulticodecKeyAlgorithm.ML_KEM_512_PUB:
      return "mlkem-512-pub";
    case MulticodecKeyAlgorithm.ML_KEM_768_PUB:
      return "mlkem-768-pub";
    case MulticodecKeyAlgorithm.ML_KEM_1024_PUB:
      return "mlkem-1024-pub";
    case MulticodecKeyAlgorithm.ML_DSA_44_PUB:
      return "mldsa-44-pub";
    case MulticodecKeyAlgorithm.ML_DSA_65_PUB:
      return "mldsa-65-pub";
    case MulticodecKeyAlgorithm.ML_DSA_87_PUB:
      return "mldsa-87-pub";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const multicodecKeyAlgorithmToProto = (
  value: ReallyMeMulticodecKeyAlgorithm,
): MulticodecKeyAlgorithm => {
  switch (value) {
    case "ed25519-pub":
      return MulticodecKeyAlgorithm.ED25519_PUB;
    case "x25519-pub":
      return MulticodecKeyAlgorithm.X25519_PUB;
    case "secp256k1-pub":
      return MulticodecKeyAlgorithm.SECP256K1_PUB;
    case "p256-pub":
      return MulticodecKeyAlgorithm.P256_PUB;
    case "p384-pub":
      return MulticodecKeyAlgorithm.P384_PUB;
    case "p521-pub":
      return MulticodecKeyAlgorithm.P521_PUB;
    case "ed448-pub":
      return MulticodecKeyAlgorithm.ED448_PUB;
    case "rsa-pub":
      return MulticodecKeyAlgorithm.RSA_PUB;
    case "mlkem-512-pub":
      return MulticodecKeyAlgorithm.ML_KEM_512_PUB;
    case "mlkem-768-pub":
      return MulticodecKeyAlgorithm.ML_KEM_768_PUB;
    case "mlkem-1024-pub":
      return MulticodecKeyAlgorithm.ML_KEM_1024_PUB;
    case "mldsa-44-pub":
      return MulticodecKeyAlgorithm.ML_DSA_44_PUB;
    case "mldsa-65-pub":
      return MulticodecKeyAlgorithm.ML_DSA_65_PUB;
    case "mldsa-87-pub":
      return MulticodecKeyAlgorithm.ML_DSA_87_PUB;
  }
};

// The largest supported canonical JWK is below 4 KiB. Keeping a full factor of
// two for future public-key encodings prevents attacker-controlled allocations
// and guarantees conversion never depends on an engine's argument-count limit.
