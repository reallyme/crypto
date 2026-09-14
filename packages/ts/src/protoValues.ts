// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0


import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type {
  ReallyMeHpkeSuite,
  ReallyMeKemAlgorithm,
  ReallyMeKeyAgreementAlgorithm,
  ReallyMeSignatureAlgorithm,
} from "./algorithms.js";
import type {
  ReallyMeHpkeSealedMessage,
  ReallyMeKemEncapsulation,
  ReallyMeKemKeyPair,
  ReallyMeKeyAgreementKeyPair,
  ReallyMeSignatureKeyPair,
} from "./cryptoFacade.js";
import { ReallyMeCryptoError } from "./errors.js";
import { cryptoErrorToProto } from "./protoErrors.js";
import {
  hpkeSuiteFromIdentifier,
  hpkeSuiteIdentifierToProto,
  kemAlgorithmFromIdentifier,
  kemAlgorithmIdentifierToProto,
  keyAgreementAlgorithmFromIdentifier,
  keyAgreementAlgorithmIdentifierToProto,
  signatureAlgorithmFromIdentifier,
  signatureAlgorithmIdentifierToProto,
} from "./protoIdentifiers.js";
import {
  CryptoAlgorithmFamily,
  CryptoHpkeSealedMessageSchema,
  CryptoKemEncapsulationSchema,
  CryptoKeyPairSchema,
  CryptoProviderCapabilitySchema,
  CryptoProviderCapabilitySetSchema,
  CryptoProviderSupportStatus,
  CryptoVerificationResultSchema,
  CryptoVerificationStatus,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import type {
  CryptoAlgorithmIdentifier,
  CryptoHpkeSealedMessage,
  CryptoKemEncapsulation,
  CryptoKeyPair,
  CryptoProviderCapability,
  CryptoProviderCapabilitySet,
  CryptoVerificationResult,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

export type ReallyMeProviderSupportStatus =
  | "partial"
  | "provider-aware"
  | "supported"
  | "unsupported";

export type ReallyMeProviderCapability = Readonly<{
  algorithm: CryptoAlgorithmIdentifier;
  family: CryptoAlgorithmFamily;
  providerNames: ReadonlyArray<string>;
  status: ReallyMeProviderSupportStatus;
  usesRust: boolean;
}>;

export type ReallyMeSignatureKeyPairProtoValue = Readonly<{
  algorithm: ReallyMeSignatureAlgorithm;
  keyPair: ReallyMeSignatureKeyPair;
}>;

export type ReallyMeKeyAgreementKeyPairProtoValue = Readonly<{
  algorithm: ReallyMeKeyAgreementAlgorithm;
  keyPair: ReallyMeKeyAgreementKeyPair;
}>;

export type ReallyMeKemKeyPairProtoValue = Readonly<{
  algorithm: ReallyMeKemAlgorithm;
  keyPair: ReallyMeKemKeyPair;
}>;

export type ReallyMeKemEncapsulationProtoValue = Readonly<{
  algorithm: ReallyMeKemAlgorithm;
  encapsulation: ReallyMeKemEncapsulation;
}>;

export type ReallyMeHpkeSealedMessageProtoValue = Readonly<{
  sealedMessage: ReallyMeHpkeSealedMessage;
  suite: ReallyMeHpkeSuite;
}>;


const keyPairToProto = (
  algorithm: CryptoAlgorithmIdentifier,
  keyPair:
    | ReallyMeKemKeyPair
    | ReallyMeKeyAgreementKeyPair
    | ReallyMeSignatureKeyPair,
): CryptoKeyPair =>
  create(CryptoKeyPairSchema, {
    algorithm,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  });

export const signatureKeyPairToProto = (
  algorithm: ReallyMeSignatureAlgorithm,
  keyPair: ReallyMeSignatureKeyPair,
): CryptoKeyPair => keyPairToProto(signatureAlgorithmIdentifierToProto(algorithm), keyPair);

export const signatureKeyPairToProtoBytes = (
  algorithm: ReallyMeSignatureAlgorithm,
  keyPair: ReallyMeSignatureKeyPair,
): Uint8Array => toBinary(CryptoKeyPairSchema, signatureKeyPairToProto(algorithm, keyPair));

export const signatureKeyPairFromProto = (
  value: CryptoKeyPair,
): ReallyMeSignatureKeyPairProtoValue => ({
  algorithm: signatureAlgorithmFromIdentifier(value.algorithm),
  keyPair: {
    publicKey: value.publicKey,
    secretKey: value.secretKey,
  },
});

export const signatureKeyPairFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeSignatureKeyPairProtoValue => {
  try {
    return signatureKeyPairFromProto(fromBinary(CryptoKeyPairSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const keyAgreementKeyPairToProto = (
  algorithm: ReallyMeKeyAgreementAlgorithm,
  keyPair: ReallyMeKeyAgreementKeyPair,
): CryptoKeyPair => keyPairToProto(keyAgreementAlgorithmIdentifierToProto(algorithm), keyPair);

export const keyAgreementKeyPairToProtoBytes = (
  algorithm: ReallyMeKeyAgreementAlgorithm,
  keyPair: ReallyMeKeyAgreementKeyPair,
): Uint8Array => toBinary(CryptoKeyPairSchema, keyAgreementKeyPairToProto(algorithm, keyPair));

export const keyAgreementKeyPairFromProto = (
  value: CryptoKeyPair,
): ReallyMeKeyAgreementKeyPairProtoValue => ({
  algorithm: keyAgreementAlgorithmFromIdentifier(value.algorithm),
  keyPair: {
    publicKey: value.publicKey,
    secretKey: value.secretKey,
  },
});

export const keyAgreementKeyPairFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeKeyAgreementKeyPairProtoValue => {
  try {
    return keyAgreementKeyPairFromProto(fromBinary(CryptoKeyPairSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const kemKeyPairToProto = (
  algorithm: ReallyMeKemAlgorithm,
  keyPair: ReallyMeKemKeyPair,
): CryptoKeyPair => keyPairToProto(kemAlgorithmIdentifierToProto(algorithm), keyPair);

export const kemKeyPairToProtoBytes = (
  algorithm: ReallyMeKemAlgorithm,
  keyPair: ReallyMeKemKeyPair,
): Uint8Array => toBinary(CryptoKeyPairSchema, kemKeyPairToProto(algorithm, keyPair));

export const kemKeyPairFromProto = (value: CryptoKeyPair): ReallyMeKemKeyPairProtoValue => ({
  algorithm: kemAlgorithmFromIdentifier(value.algorithm),
  keyPair: {
    publicKey: value.publicKey,
    secretKey: value.secretKey,
  },
});

export const kemKeyPairFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeKemKeyPairProtoValue => {
  try {
    return kemKeyPairFromProto(fromBinary(CryptoKeyPairSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const kemEncapsulationToProto = (
  algorithm: ReallyMeKemAlgorithm,
  encapsulation: ReallyMeKemEncapsulation,
): CryptoKemEncapsulation =>
  create(CryptoKemEncapsulationSchema, {
    algorithm: kemAlgorithmIdentifierToProto(algorithm),
    ciphertext: encapsulation.ciphertext,
    sharedSecret: encapsulation.sharedSecret,
  });

export const kemEncapsulationToProtoBytes = (
  algorithm: ReallyMeKemAlgorithm,
  encapsulation: ReallyMeKemEncapsulation,
): Uint8Array =>
  toBinary(CryptoKemEncapsulationSchema, kemEncapsulationToProto(algorithm, encapsulation));

export const kemEncapsulationFromProto = (
  value: CryptoKemEncapsulation,
): ReallyMeKemEncapsulationProtoValue => ({
  algorithm: kemAlgorithmFromIdentifier(value.algorithm),
  encapsulation: {
    ciphertext: value.ciphertext,
    sharedSecret: value.sharedSecret,
  },
});

export const kemEncapsulationFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeKemEncapsulationProtoValue => {
  try {
    return kemEncapsulationFromProto(fromBinary(CryptoKemEncapsulationSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const hpkeSealedMessageToProto = (
  suite: ReallyMeHpkeSuite,
  sealedMessage: ReallyMeHpkeSealedMessage,
): CryptoHpkeSealedMessage =>
  create(CryptoHpkeSealedMessageSchema, {
    algorithm: hpkeSuiteIdentifierToProto(suite),
    encapsulatedKey: sealedMessage.encapsulatedKey,
    ciphertext: sealedMessage.ciphertext,
  });

export const hpkeSealedMessageToProtoBytes = (
  suite: ReallyMeHpkeSuite,
  sealedMessage: ReallyMeHpkeSealedMessage,
): Uint8Array =>
  toBinary(CryptoHpkeSealedMessageSchema, hpkeSealedMessageToProto(suite, sealedMessage));

export const hpkeSealedMessageFromProto = (
  value: CryptoHpkeSealedMessage,
): ReallyMeHpkeSealedMessageProtoValue => ({
  suite: hpkeSuiteFromIdentifier(value.algorithm),
  sealedMessage: {
    encapsulatedKey: value.encapsulatedKey,
    ciphertext: value.ciphertext,
  },
});

export const hpkeSealedMessageFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeHpkeSealedMessageProtoValue => {
  try {
    return hpkeSealedMessageFromProto(fromBinary(CryptoHpkeSealedMessageSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const verificationResultToProto = (
  algorithm: CryptoAlgorithmIdentifier,
  valid: boolean,
): CryptoVerificationResult =>
  create(CryptoVerificationResultSchema, {
    algorithm,
    status: valid ? CryptoVerificationStatus.VALID : CryptoVerificationStatus.INVALID,
  });

export const verificationErrorToProto = (
  algorithm: CryptoAlgorithmIdentifier,
  error: ReallyMeCryptoError,
): CryptoVerificationResult =>
  create(CryptoVerificationResultSchema, {
    algorithm,
    status: CryptoVerificationStatus.ERROR,
    error: cryptoErrorToProto(error),
  });

export const verificationResultToProtoBytes = (
  value: CryptoVerificationResult,
): Uint8Array => toBinary(CryptoVerificationResultSchema, value);

export const verificationResultFromProtoBytes = (
  bytes: Uint8Array,
): CryptoVerificationResult => {
  try {
    return fromBinary(CryptoVerificationResultSchema, bytes);
  } catch {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const providerSupportStatusToProto = (
  value: ReallyMeProviderSupportStatus,
): CryptoProviderSupportStatus => {
  switch (value) {
    case "partial":
      return CryptoProviderSupportStatus.PARTIAL;
    case "provider-aware":
      return CryptoProviderSupportStatus.PROVIDER_AWARE;
    case "supported":
      return CryptoProviderSupportStatus.SUPPORTED;
    case "unsupported":
      return CryptoProviderSupportStatus.UNSUPPORTED;
  }
};

const providerSupportStatusFromProto = (
  value: CryptoProviderSupportStatus,
): ReallyMeProviderSupportStatus => {
  switch (value) {
    case CryptoProviderSupportStatus.PARTIAL:
      return "partial";
    case CryptoProviderSupportStatus.PROVIDER_AWARE:
      return "provider-aware";
    case CryptoProviderSupportStatus.SUPPORTED:
      return "supported";
    case CryptoProviderSupportStatus.UNSUPPORTED:
      return "unsupported";
    default:
      throw new ReallyMeCryptoError("invalid-input");
  }
};

export const providerCapabilityToProto = (
  value: ReallyMeProviderCapability,
): CryptoProviderCapability =>
  create(CryptoProviderCapabilitySchema, {
    algorithm: value.algorithm,
    family: value.family,
    providerNames: [...value.providerNames],
    status: providerSupportStatusToProto(value.status),
    usesRust: value.usesRust,
  });

export const providerCapabilityFromProto = (
  value: CryptoProviderCapability,
): ReallyMeProviderCapability => {
  if (value.algorithm === undefined || value.family === CryptoAlgorithmFamily.UNSPECIFIED) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return {
    algorithm: value.algorithm,
    family: value.family,
    providerNames: [...value.providerNames],
    status: providerSupportStatusFromProto(value.status),
    usesRust: value.usesRust,
  };
};

export const providerCapabilitySetToProto = (
  values: ReadonlyArray<ReallyMeProviderCapability>,
): CryptoProviderCapabilitySet =>
  create(CryptoProviderCapabilitySetSchema, {
    capabilities: values.map((value) => providerCapabilityToProto(value)),
  });

export const providerCapabilitySetToProtoBytes = (
  values: ReadonlyArray<ReallyMeProviderCapability>,
): Uint8Array => toBinary(CryptoProviderCapabilitySetSchema, providerCapabilitySetToProto(values));

export const providerCapabilitySetFromProto = (
  value: CryptoProviderCapabilitySet,
): readonly ReallyMeProviderCapability[] =>
  value.capabilities.map((capability) => providerCapabilityFromProto(capability));

export const providerCapabilitySetFromProtoBytes = (
  bytes: Uint8Array,
): readonly ReallyMeProviderCapability[] => {
  try {
    return providerCapabilitySetFromProto(fromBinary(CryptoProviderCapabilitySetSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};
