// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0


import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ReallyMeCryptoError } from "./errors.js";
import {
  CryptoBackendErrorSchema,
  CryptoErrorReason,
  CryptoErrorSchema,
  CryptoPrimitiveErrorSchema,
  CryptoProviderErrorSchema,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import type { CryptoError } from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

export type ReallyMeCryptoWireErrorBranch = "primitive" | "provider" | "backend";

export type ReallyMeCryptoWireError = Readonly<{
  branch: ReallyMeCryptoWireErrorBranch;
  reason: CryptoErrorReason;
  reasonCode?: number;
}>;

export type ReallyMeCryptoWireErrorValidationCode =
  | "unspecified-reason"
  | "branch-reason-mismatch"
  | "reason-code-out-of-range";

export type ReallyMeCryptoWireErrorValidationResult =
  | Readonly<{ ok: true; value: ReallyMeCryptoWireError }>
  | Readonly<{ ok: false; error: ReallyMeCryptoWireErrorValidationCode }>;


const cryptoErrorReasonToFacadeError = (
  reason: CryptoErrorReason,
): ReallyMeCryptoError => {
  switch (reason) {
    case CryptoErrorReason.PRIMITIVE_INVALID_SIGNATURE:
    case CryptoErrorReason.PRIMITIVE_VERIFICATION_FAILED:
      return new ReallyMeCryptoError("invalid-signature");
    case CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM:
    case CryptoErrorReason.PROVIDER_UNSUPPORTED_BACKEND:
      return new ReallyMeCryptoError("unsupported-algorithm");
    case CryptoErrorReason.PROVIDER_UNAVAILABLE:
    case CryptoErrorReason.PROVIDER_RANDOMNESS_UNAVAILABLE:
    case CryptoErrorReason.PROVIDER_KEY_EXISTS:
    case CryptoErrorReason.PROVIDER_KEY_NOT_FOUND:
    case CryptoErrorReason.PROVIDER_ACCESS_DENIED:
    case CryptoErrorReason.PROVIDER_USER_AUTHENTICATION_REQUIRED:
    case CryptoErrorReason.PROVIDER_USER_CANCELED:
    case CryptoErrorReason.PROVIDER_HARDWARE_UNAVAILABLE:
    case CryptoErrorReason.PROVIDER_HARDWARE_REJECTED_KEY:
    case CryptoErrorReason.BACKEND_INVALID_STATE:
    case CryptoErrorReason.BACKEND_INTERNAL:
      return new ReallyMeCryptoError("provider-failure");
    case CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER:
    case CryptoErrorReason.PRIMITIVE_INVALID_LENGTH:
    case CryptoErrorReason.PRIMITIVE_INVALID_KEY:
    case CryptoErrorReason.PRIMITIVE_INVALID_PUBLIC_KEY:
    case CryptoErrorReason.PRIMITIVE_INVALID_PRIVATE_KEY:
    case CryptoErrorReason.PRIMITIVE_INVALID_NONCE:
    case CryptoErrorReason.PRIMITIVE_INVALID_SALT:
    case CryptoErrorReason.PRIMITIVE_INVALID_PASSWORD:
    case CryptoErrorReason.PRIMITIVE_INVALID_ENCODING:
    case CryptoErrorReason.PRIMITIVE_INVALID_SHARED_SECRET:
    case CryptoErrorReason.PRIMITIVE_MALFORMED_CIPHERTEXT:
    case CryptoErrorReason.PRIMITIVE_INVALID_TAG:
    case CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF:
    case CryptoErrorReason.PRIMITIVE_MALFORMED_JSON:
    case CryptoErrorReason.PRIMITIVE_RESOURCE_LIMIT_EXCEEDED:
    case CryptoErrorReason.PRIMITIVE_MISSING_OPERATION:
      return new ReallyMeCryptoError("invalid-input");
    case CryptoErrorReason.PRIMITIVE_AUTHENTICATION_FAILED:
      return new ReallyMeCryptoError("authentication-failed");
    default:
      return new ReallyMeCryptoError("invalid-input");
  }
};

const invalidInputReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER,
  CryptoErrorReason.PRIMITIVE_INVALID_LENGTH,
  CryptoErrorReason.PRIMITIVE_INVALID_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_PUBLIC_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_PRIVATE_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_NONCE,
  CryptoErrorReason.PRIMITIVE_INVALID_SALT,
  CryptoErrorReason.PRIMITIVE_INVALID_PASSWORD,
  CryptoErrorReason.PRIMITIVE_INVALID_ENCODING,
  CryptoErrorReason.PRIMITIVE_INVALID_SHARED_SECRET,
  CryptoErrorReason.PRIMITIVE_MALFORMED_CIPHERTEXT,
  CryptoErrorReason.PRIMITIVE_INVALID_TAG,
  CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF,
  CryptoErrorReason.PRIMITIVE_MALFORMED_JSON,
  CryptoErrorReason.PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
  CryptoErrorReason.PRIMITIVE_MISSING_OPERATION,
]);

export const cryptoWireErrorToProto = (
  error: ReallyMeCryptoWireError,
): CryptoError => {
  switch (error.branch) {
    case "primitive":
      return create(CryptoErrorSchema, {
        error: {
          case: "primitive",
          value: create(CryptoPrimitiveErrorSchema, {
            reason: error.reason,
          }),
        },
      });
    case "provider":
      return create(CryptoErrorSchema, {
        error: {
          case: "provider",
          value: create(CryptoProviderErrorSchema, {
            reason: error.reason,
          }),
        },
      });
    case "backend":
      return create(CryptoErrorSchema, {
        error: {
          case: "backend",
          value: create(CryptoBackendErrorSchema, {
            reason: error.reason,
          }),
        },
      });
  }
};

export const cryptoWireErrorFromProto = (
  value: CryptoError,
): ReallyMeCryptoWireError => {
  switch (value.error.case) {
    case "primitive":
      return strictCryptoWireError("primitive", value.error.value.reason);
    case "provider":
      return strictCryptoWireError("provider", value.error.value.reason);
    case "backend":
      return strictCryptoWireError("backend", value.error.value.reason);
    default:
      return malformedCryptoErrorEnvelope();
  }
};

export const cryptoWireErrorToProtoBytes = (
  error: ReallyMeCryptoWireError,
): Uint8Array => toBinary(CryptoErrorSchema, cryptoWireErrorToProto(error));

export const cryptoWireErrorFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeCryptoWireError => {
  try {
    return cryptoWireErrorFromProto(fromBinary(CryptoErrorSchema, bytes));
  } catch {
    return malformedCryptoErrorEnvelope();
  }
};

const strictCryptoWireError = (
  branch: ReallyMeCryptoWireErrorBranch,
  reason: CryptoErrorReason,
): ReallyMeCryptoWireError => {
  const result = cryptoWireErrorTryNew(branch, reason);
  return result.ok ? result.value : malformedCryptoErrorEnvelope();
};

export const cryptoWireErrorTryNew = (
  branch: ReallyMeCryptoWireErrorBranch,
  reason: CryptoErrorReason,
): ReallyMeCryptoWireErrorValidationResult => {
  if (reason === CryptoErrorReason.UNSPECIFIED) {
    return { ok: false, error: "unspecified-reason" };
  }
  if (knownCryptoErrorReasons.has(reason) && !cryptoErrorReasonMatchesBranch(branch, reason)) {
    return { ok: false, error: "branch-reason-mismatch" };
  }
  if (!cryptoErrorReasonCodeMatchesBranch(branch, reason)) {
    return { ok: false, error: "reason-code-out-of-range" };
  }
  return { ok: true, value: { branch, reason, reasonCode: reason } };
};

const malformedCryptoErrorEnvelope = (): ReallyMeCryptoWireError => ({
  branch: "primitive",
  reason: CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF,
  reasonCode: CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF,
});

const cryptoErrorReasonCodeMatchesBranch = (
  branch: ReallyMeCryptoWireErrorBranch,
  reasonCode: number,
): boolean => {
  switch (branch) {
    case "primitive":
      return reasonCode >= 100 && reasonCode <= 199;
    case "provider":
      return reasonCode >= 200 && reasonCode <= 299;
    case "backend":
      return reasonCode >= 300 && reasonCode <= 399;
  }
};

const cryptoErrorReasonMatchesBranch = (
  branch: ReallyMeCryptoWireErrorBranch,
  reason: CryptoErrorReason,
): boolean => {
  switch (branch) {
    case "primitive":
      return primitiveCryptoErrorReasons.has(reason);
    case "provider":
      return providerCryptoErrorReasons.has(reason);
    case "backend":
      return backendCryptoErrorReasons.has(reason);
  }
};

const primitiveCryptoErrorReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER,
  CryptoErrorReason.PRIMITIVE_INVALID_LENGTH,
  CryptoErrorReason.PRIMITIVE_INVALID_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_PUBLIC_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_PRIVATE_KEY,
  CryptoErrorReason.PRIMITIVE_INVALID_NONCE,
  CryptoErrorReason.PRIMITIVE_INVALID_SALT,
  CryptoErrorReason.PRIMITIVE_INVALID_PASSWORD,
  CryptoErrorReason.PRIMITIVE_INVALID_ENCODING,
  CryptoErrorReason.PRIMITIVE_INVALID_SIGNATURE,
  CryptoErrorReason.PRIMITIVE_VERIFICATION_FAILED,
  CryptoErrorReason.PRIMITIVE_AUTHENTICATION_FAILED,
  CryptoErrorReason.PRIMITIVE_MALFORMED_CIPHERTEXT,
  CryptoErrorReason.PRIMITIVE_INVALID_TAG,
  CryptoErrorReason.PRIMITIVE_INVALID_SHARED_SECRET,
  CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF,
  CryptoErrorReason.PRIMITIVE_MALFORMED_JSON,
  CryptoErrorReason.PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
  CryptoErrorReason.PRIMITIVE_MISSING_OPERATION,
]);

const providerCryptoErrorReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM,
  CryptoErrorReason.PROVIDER_UNSUPPORTED_BACKEND,
  CryptoErrorReason.PROVIDER_UNAVAILABLE,
  CryptoErrorReason.PROVIDER_RANDOMNESS_UNAVAILABLE,
  CryptoErrorReason.PROVIDER_KEY_EXISTS,
  CryptoErrorReason.PROVIDER_KEY_NOT_FOUND,
  CryptoErrorReason.PROVIDER_ACCESS_DENIED,
  CryptoErrorReason.PROVIDER_USER_AUTHENTICATION_REQUIRED,
  CryptoErrorReason.PROVIDER_USER_CANCELED,
  CryptoErrorReason.PROVIDER_HARDWARE_UNAVAILABLE,
  CryptoErrorReason.PROVIDER_HARDWARE_REJECTED_KEY,
]);

const backendCryptoErrorReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.BACKEND_INVALID_STATE,
  CryptoErrorReason.BACKEND_INTERNAL,
]);

const knownCryptoErrorReasons = new Set<CryptoErrorReason>([
  ...primitiveCryptoErrorReasons,
  ...providerCryptoErrorReasons,
  ...backendCryptoErrorReasons,
]);

export const cryptoWireErrorToFacadeError = (
  error: ReallyMeCryptoWireError,
): ReallyMeCryptoError => {
  if (!knownCryptoErrorReasons.has(error.reason)) {
    return new ReallyMeCryptoError("provider-failure");
  }
  const facadeError = cryptoErrorReasonToFacadeError(error.reason);
  if (facadeError.code !== "invalid-input" || invalidInputReasons.has(error.reason)) {
    return facadeError;
  }
  switch (error.branch) {
    case "primitive":
      return facadeError;
    case "provider":
    case "backend":
      return new ReallyMeCryptoError("provider-failure");
  }
};

export const cryptoErrorToProto = (error: ReallyMeCryptoError): CryptoError => {
  switch (error.code) {
    case "invalid-input":
      return create(CryptoErrorSchema, {
        error: {
          case: "primitive",
          value: create(CryptoPrimitiveErrorSchema, {
            reason: CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER,
          }),
        },
      });
    case "invalid-signature":
      return create(CryptoErrorSchema, {
        error: {
          case: "primitive",
          value: create(CryptoPrimitiveErrorSchema, {
            reason: CryptoErrorReason.PRIMITIVE_INVALID_SIGNATURE,
          }),
        },
      });
    case "authentication-failed":
      return create(CryptoErrorSchema, {
        error: {
          case: "primitive",
          value: create(CryptoPrimitiveErrorSchema, {
            reason: CryptoErrorReason.PRIMITIVE_AUTHENTICATION_FAILED,
          }),
        },
      });
    case "provider-failure":
      return create(CryptoErrorSchema, {
        error: {
          case: "backend",
          value: create(CryptoBackendErrorSchema, {
            reason: CryptoErrorReason.BACKEND_INTERNAL,
          }),
        },
      });
    case "unsupported-algorithm":
      return create(CryptoErrorSchema, {
        error: {
          case: "provider",
          value: create(CryptoProviderErrorSchema, {
            reason: CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM,
          }),
        },
      });
  }
};

export const cryptoErrorToProtoBytes = (error: ReallyMeCryptoError): Uint8Array =>
  toBinary(CryptoErrorSchema, cryptoErrorToProto(error));

export const cryptoErrorFromProto = (value: CryptoError): ReallyMeCryptoError => {
  return cryptoWireErrorToFacadeError(cryptoWireErrorFromProto(value));
};

export const cryptoErrorFromProtoBytes = (bytes: Uint8Array): ReallyMeCryptoError => {
  return cryptoWireErrorToFacadeError(cryptoWireErrorFromProtoBytes(bytes));
};
