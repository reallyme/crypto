// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0


import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ReallyMeCryptoError } from "./errors.js";
import type { ReallyMeCryptoErrorCode } from "./errors.js";
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


type KnownErrorReason = Exclude<CryptoErrorReason, CryptoErrorReason.UNSPECIFIED>;

// The public SDK categories predate the wire contract. This exhaustive projection
// keeps them stable while the wire adapter retains the original reason code.
const facadeErrorCodes: Readonly<Record<KnownErrorReason, ReallyMeCryptoErrorCode>> = {
  [CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_LENGTH]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_KEY]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_PUBLIC_KEY]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_PRIVATE_KEY]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_NONCE]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_SALT]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_PASSWORD]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_ENCODING]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_SIGNATURE]: "invalid-signature",
  [CryptoErrorReason.PRIMITIVE_VERIFICATION_FAILED]: "invalid-signature",
  [CryptoErrorReason.PRIMITIVE_AUTHENTICATION_FAILED]: "authentication-failed",
  [CryptoErrorReason.PRIMITIVE_MALFORMED_CIPHERTEXT]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_TAG]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_INVALID_SHARED_SECRET]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_MALFORMED_PROTOBUF]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_MALFORMED_JSON]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_RESOURCE_LIMIT_EXCEEDED]: "invalid-input",
  [CryptoErrorReason.PRIMITIVE_MISSING_OPERATION]: "invalid-input",
  [CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM]: "unsupported-algorithm",
  [CryptoErrorReason.PROVIDER_UNSUPPORTED_BACKEND]: "unsupported-algorithm",
  [CryptoErrorReason.PROVIDER_UNAVAILABLE]: "provider-failure",
  [CryptoErrorReason.PROVIDER_RANDOMNESS_UNAVAILABLE]: "provider-failure",
  [CryptoErrorReason.PROVIDER_KEY_EXISTS]: "provider-failure",
  [CryptoErrorReason.PROVIDER_KEY_NOT_FOUND]: "provider-failure",
  [CryptoErrorReason.PROVIDER_ACCESS_DENIED]: "provider-failure",
  [CryptoErrorReason.PROVIDER_USER_AUTHENTICATION_REQUIRED]: "provider-failure",
  [CryptoErrorReason.PROVIDER_USER_CANCELED]: "provider-failure",
  [CryptoErrorReason.PROVIDER_HARDWARE_UNAVAILABLE]: "provider-failure",
  [CryptoErrorReason.PROVIDER_HARDWARE_REJECTED_KEY]: "provider-failure",
  [CryptoErrorReason.BACKEND_INVALID_STATE]: "provider-failure",
  [CryptoErrorReason.BACKEND_INTERNAL]: "provider-failure",
};

const isKnownErrorReason = (reason: unknown): reason is KnownErrorReason =>
  typeof reason === "number" && Number.isInteger(reason) && Object.hasOwn(facadeErrorCodes, reason);

const facadeErrorReasons: Readonly<Record<ReallyMeCryptoErrorCode, ReallyMeCryptoWireError>> = {
  "invalid-input": { branch: "primitive", reason: CryptoErrorReason.PRIMITIVE_INVALID_PARAMETER },
  "invalid-signature": { branch: "primitive", reason: CryptoErrorReason.PRIMITIVE_INVALID_SIGNATURE },
  "authentication-failed": { branch: "primitive", reason: CryptoErrorReason.PRIMITIVE_AUTHENTICATION_FAILED },
  "provider-failure": { branch: "backend", reason: CryptoErrorReason.BACKEND_INTERNAL },
  "unsupported-algorithm": { branch: "provider", reason: CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM },
};

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
  if (!Number.isInteger(reason) || !cryptoErrorReasonCodeMatchesBranch(branch, reason)) {
    return {
      ok: false,
      error: isKnownErrorReason(reason) ? "branch-reason-mismatch" : "reason-code-out-of-range",
    };
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

export const cryptoWireErrorToFacadeError = (
  error: ReallyMeCryptoWireError,
): ReallyMeCryptoError => new ReallyMeCryptoError(
  isKnownErrorReason(error.reason) ? facadeErrorCodes[error.reason] : "provider-failure",
);

export const cryptoErrorToProto = (error: ReallyMeCryptoError): CryptoError => {
  const code = error.code;
  if (typeof code !== "string" || !Object.hasOwn(facadeErrorReasons, code)) {
    return cryptoWireErrorToProto(facadeErrorReasons["invalid-input"]);
  }
  return cryptoWireErrorToProto(facadeErrorReasons[code]);
};

export const cryptoErrorToProtoBytes = (error: ReallyMeCryptoError): Uint8Array =>
  toBinary(CryptoErrorSchema, cryptoErrorToProto(error));

export const cryptoErrorFromProto = (value: CryptoError): ReallyMeCryptoError => {
  return cryptoWireErrorToFacadeError(cryptoWireErrorFromProto(value));
};

export const cryptoErrorFromProtoBytes = (bytes: Uint8Array): ReallyMeCryptoError => {
  return cryptoWireErrorToFacadeError(cryptoWireErrorFromProtoBytes(bytes));
};
