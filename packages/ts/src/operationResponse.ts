// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import {
  ensureByteArray,
  ensureIndependentByteArray,
} from "./validateBytes.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

const MAX_CRYPTO_OPERATION_RESPONSE_BYTES = 1_048_608;

const readOperationResponse = (
  value: unknown,
  request: Uint8Array,
): Uint8Array => {
  if (!(value instanceof Uint8Array)) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  ensureIndependentByteArray(value, [request]);
  if (
    value.length === 0 ||
    value.length > MAX_CRYPTO_OPERATION_RESPONSE_BYTES
  ) {
    value.fill(0);
    throw new ReallyMeCryptoError("provider-failure");
  }
  return value;
};

/**
 * Execute one generated binary protobuf request.
 *
 * The returned bytes are always a generated `CryptoOperationResponse` with a
 * typed `result` or typed `error` outcome.
 */
export const processOperationResponse = (
  requestBytes: Uint8Array,
): Uint8Array => {
  ensureByteArray(requestBytes);
  return processOperationResponseWithProvider(
    requireReallyMeWasmProvider(),
    requestBytes,
  );
};

export const processOperationResponseWithProvider = (
  provider: ReallyMeWasmProvider,
  requestBytes: Uint8Array,
): Uint8Array => {
  ensureByteArray(requestBytes);
  return readOperationResponse(
    provider.processOperationResponse(requestBytes),
    requestBytes,
  );
};

/**
 * Execute one permitted non-secret generated ProtoJSON request and return the
 * same binary `CryptoOperationResponse` used by `processOperationResponse`.
 * Secret-bearing selectors fail before JSON value deserialization.
 */
export const processOperationResponseJson = (
  requestJson: Uint8Array,
): Uint8Array => {
  ensureByteArray(requestJson);
  return processOperationResponseJsonWithProvider(
    requireReallyMeWasmProvider(),
    requestJson,
  );
};

export const processOperationResponseJsonWithProvider = (
  provider: ReallyMeWasmProvider,
  requestJson: Uint8Array,
): Uint8Array => {
  ensureByteArray(requestJson);
  return readOperationResponse(
    provider.processOperationResponseJson(requestJson),
    requestJson,
  );
};
