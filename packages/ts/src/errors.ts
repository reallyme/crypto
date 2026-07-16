// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Typed SDK error codes. Errors intentionally carry no secret or
 * user-provided bytes so callers can log them without leaking key material
 * or PII.
 */
export type ReallyMeCryptoErrorCode =
  | "invalid-input"
  | "invalid-signature"
  | "authentication-failed"
  | "provider-failure"
  | "unsupported-algorithm";

export class ReallyMeCryptoError extends Error {
  readonly code: ReallyMeCryptoErrorCode;

  constructor(code: ReallyMeCryptoErrorCode) {
    super(code);
    this.name = "ReallyMeCryptoError";
    this.code = code;
  }
}
