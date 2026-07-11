// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type { ReallyMeSignatureAlgorithm } from "./algorithms.js";
import { ReallyMeCryptoError } from "./errors.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";

export type ReallyMeRsaPublicKeyDerEncoding = "PKCS1" | "SPKI";

export const RSA_PUBLIC_KEY_DER_MAX_LENGTH = 4_096;
export const RSA_SIGNATURE_MAX_LENGTH = 1_024;

const RSA_HASH_SHA1 = 1;
const RSA_HASH_SHA256 = 2;
const RSA_HASH_SHA384 = 3;
const RSA_HASH_SHA512 = 4;
const RSA_PUBLIC_KEY_ENCODING_PKCS1_DER = 1;
const RSA_PUBLIC_KEY_ENCODING_SPKI_DER = 2;

type RsaPkcs1v15Suite = Readonly<{
  hashSuite: number;
}>;

type RsaPssSuite = Readonly<{
  messageHashSuite: number;
  mgf1HashSuite: number;
  saltLength: number;
}>;

const validateBytes = (bytes: Uint8Array, maxLength: number): void => {
  if (bytes.length === 0 || bytes.length > maxLength) {
    throw new ReallyMeCryptoError("invalid-input");
  }
};

const encodingId = (encoding: ReallyMeRsaPublicKeyDerEncoding): number => {
  switch (encoding) {
    case "PKCS1":
      return RSA_PUBLIC_KEY_ENCODING_PKCS1_DER;
    case "SPKI":
      return RSA_PUBLIC_KEY_ENCODING_SPKI_DER;
    default:
      throw new ReallyMeCryptoError("invalid-input");
  }
};

const pkcs1v15Suite = (
  algorithm: ReallyMeSignatureAlgorithm,
): RsaPkcs1v15Suite | undefined => {
  switch (algorithm) {
    case "RSA-PKCS1v15-SHA1":
      return { hashSuite: RSA_HASH_SHA1 };
    case "RSA-PKCS1v15-SHA256":
      return { hashSuite: RSA_HASH_SHA256 };
    case "RSA-PKCS1v15-SHA384":
      return { hashSuite: RSA_HASH_SHA384 };
    case "RSA-PKCS1v15-SHA512":
      return { hashSuite: RSA_HASH_SHA512 };
    default:
      return undefined;
  }
};

const pssSuite = (algorithm: ReallyMeSignatureAlgorithm): RsaPssSuite | undefined => {
  switch (algorithm) {
    case "RSA-PSS-SHA1-MGF1-SHA1":
      return {
        messageHashSuite: RSA_HASH_SHA1,
        mgf1HashSuite: RSA_HASH_SHA1,
        saltLength: 20,
      };
    case "RSA-PSS-SHA256-MGF1-SHA256":
      return {
        messageHashSuite: RSA_HASH_SHA256,
        mgf1HashSuite: RSA_HASH_SHA256,
        saltLength: 32,
      };
    case "RSA-PSS-SHA384-MGF1-SHA384":
      return {
        messageHashSuite: RSA_HASH_SHA384,
        mgf1HashSuite: RSA_HASH_SHA384,
        saltLength: 48,
      };
    case "RSA-PSS-SHA512-MGF1-SHA512":
      return {
        messageHashSuite: RSA_HASH_SHA512,
        mgf1HashSuite: RSA_HASH_SHA512,
        saltLength: 64,
      };
    default:
      return undefined;
  }
};

const readVoid = (value: unknown): void => {
  if (value !== undefined) {
    throw new ReallyMeCryptoError("provider-failure");
  }
};

/**
 * RSA signature verification through the ReallyMe Rust WASM provider.
 *
 * RSA is verification-only in this SDK. It exists for X.509, eMRTD passive
 * authentication, and legacy interoperability; no RSA signing API is exposed.
 */
export const ReallyMeRsa = {
  verify(
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKeyDer: Uint8Array,
    publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
  ): void {
    validateBytes(publicKeyDer, RSA_PUBLIC_KEY_DER_MAX_LENGTH);
    validateBytes(signature, RSA_SIGNATURE_MAX_LENGTH);
    const encoding = encodingId(publicKeyEncoding);
    const pkcs1 = pkcs1v15Suite(algorithm);
    const provider = requireReallyMeWasmProvider();
    if (pkcs1 !== undefined) {
      readVoid(
        provider.rsaVerifyPkcs1v15(
          publicKeyDer,
          encoding,
          pkcs1.hashSuite,
          message,
          signature,
        ),
      );
      return;
    }

    const pss = pssSuite(algorithm);
    if (pss !== undefined) {
      readVoid(
        provider.rsaVerifyPss(
          publicKeyDer,
          encoding,
          pss.messageHashSuite,
          pss.mgf1HashSuite,
          pss.saltLength,
          message,
          signature,
        ),
      );
      return;
    }

    throw new ReallyMeCryptoError("unsupported-algorithm");
  },
} as const;
