// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import type {
  ReallyMeAeadAlgorithm,
  ReallyMeHashAlgorithm,
  ReallyMeHkdfAlgorithm,
  ReallyMeJwaConcatKdfAlgorithm,
  ReallyMeKeyWrapAlgorithm,
  ReallyMeKmacKdfAlgorithm,
  ReallyMeMacAlgorithm,
  ReallyMePbkdf2Algorithm,
} from "./algorithms.js";
import { ReallyMeAead } from "./aead.js";
import { ReallyMeAesKw } from "./aesKw.js";
import { ReallyMeArgon2id } from "./argon2id.js";
import { ReallyMeDigest } from "./digest.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ReallyMeHkdf } from "./hkdf.js";
import { ReallyMeHmac } from "./hmac.js";
import { ReallyMeJwaConcatKdf } from "./jwaConcatKdf.js";
import { ReallyMeKmac } from "./kmac.js";
import {
  processOperationResponseJsonWithProvider,
  processOperationResponseWithProvider,
} from "./operationResponse.js";
import { ReallyMePbkdf2 } from "./pbkdf2.js";
import { ensureByteArray } from "./validateBytes.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";

export const createReallyMeSymmetricFacade = (
  resolveWasmProvider: () => ReallyMeWasmProvider,
) => ({
  /**
   * Executes a generated binary request and returns a binary
   * `CryptoOperationResponse`.
   */
  processOperationResponse(request: Uint8Array): Uint8Array {
    ensureByteArray(request);
    return processOperationResponseWithProvider(resolveWasmProvider(), request);
  },

  /**
   * Executes a permitted non-secret generated ProtoJSON request and returns
   * the same binary `CryptoOperationResponse`. Secret-bearing selectors fail
   * before JSON value deserialization.
   */
  processOperationResponseJson(requestJson: Uint8Array): Uint8Array {
    ensureByteArray(requestJson);
    return processOperationResponseJsonWithProvider(
      resolveWasmProvider(),
      requestJson,
    );
  },

  hash(algorithm: ReallyMeHashAlgorithm, bytes: Uint8Array): Uint8Array {
    switch (algorithm) {
      case "SHA2-256":
        return ReallyMeDigest.sha256(bytes);
      case "SHA2-384":
        return ReallyMeDigest.sha384(bytes);
      case "SHA2-512":
        return ReallyMeDigest.sha512(bytes);
      case "SHA3-224":
        return ReallyMeDigest.sha3_224(bytes);
      case "SHA3-256":
        return ReallyMeDigest.sha3_256(bytes);
      case "SHA3-384":
        return ReallyMeDigest.sha3_384(bytes);
      case "SHA3-512":
        return ReallyMeDigest.sha3_512(bytes);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  seal(
    algorithm: ReallyMeAeadAlgorithm,
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "AES-128-GCM":
      case "AES-192-GCM":
      case "AES-256-GCM":
      case "AES-256-GCM-SIV":
      case "ChaCha20-Poly1305":
      case "XChaCha20-Poly1305":
        return ReallyMeAead.sealWithProvider(
          resolveWasmProvider(),
          algorithm,
          key,
          nonce,
          aad,
          plaintext,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  open(
    algorithm: ReallyMeAeadAlgorithm,
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertextWithTag: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "AES-128-GCM":
      case "AES-192-GCM":
      case "AES-256-GCM":
      case "AES-256-GCM-SIV":
      case "ChaCha20-Poly1305":
      case "XChaCha20-Poly1305":
        return ReallyMeAead.openWithProvider(
          resolveWasmProvider(),
          algorithm,
          key,
          nonce,
          aad,
          ciphertextWithTag,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  authenticate(
    algorithm: ReallyMeMacAlgorithm,
    key: Uint8Array,
    message: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "HMAC-SHA-256":
        return ReallyMeHmac.authenticateSha256(key, message);
      case "HMAC-SHA-384":
        return ReallyMeHmac.authenticateSha384(key, message);
      case "HMAC-SHA-512":
        return ReallyMeHmac.authenticateSha512(key, message);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  verifyMac(
    algorithm: ReallyMeMacAlgorithm,
    tag: Uint8Array,
    key: Uint8Array,
    message: Uint8Array,
  ): boolean {
    switch (algorithm) {
      case "HMAC-SHA-256":
        return ReallyMeHmac.verifySha256(tag, key, message);
      case "HMAC-SHA-384":
        return ReallyMeHmac.verifySha384(tag, key, message);
      case "HMAC-SHA-512":
        return ReallyMeHmac.verifySha512(tag, key, message);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveArgon2id(
    kdfVersion: number,
    secret: Uint8Array,
    salt: Uint8Array,
  ): Uint8Array {
    return ReallyMeArgon2id.deriveKeyWithProvider(
      resolveWasmProvider(),
      kdfVersion,
      secret,
      salt,
    );
  },

  deriveKey(
    algorithm: ReallyMePbkdf2Algorithm,
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "PBKDF2-HMAC-SHA-256":
        return ReallyMePbkdf2.deriveHmacSha256(password, salt, iterations, outputLength);
      case "PBKDF2-HMAC-SHA-512":
        return ReallyMePbkdf2.deriveHmacSha512(password, salt, iterations, outputLength);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveHkdf(
    algorithm: ReallyMeHkdfAlgorithm,
    inputKeyMaterial: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "HKDF-SHA256":
        return ReallyMeHkdf.deriveSha256(inputKeyMaterial, salt, info, outputLength);
      case "HKDF-SHA384":
        return ReallyMeHkdf.deriveSha384(inputKeyMaterial, salt, info, outputLength);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveJwaConcatKdfSha256(
    algorithm: ReallyMeJwaConcatKdfAlgorithm,
    sharedSecret: Uint8Array,
    algorithmId: Uint8Array,
    partyUInfo: Uint8Array,
    partyVInfo: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "JWA-CONCAT-KDF-SHA256":
        return ReallyMeJwaConcatKdf.deriveSha256(
          sharedSecret,
          algorithmId,
          partyUInfo,
          partyVInfo,
          outputLength,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveKmac256(
    algorithm: ReallyMeKmacKdfAlgorithm,
    key: Uint8Array,
    context: Uint8Array,
    customization: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "KMAC256":
        return ReallyMeKmac.deriveKmac256WithProvider(
          resolveWasmProvider(),
          key,
          context,
          customization,
          outputLength,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  wrapKey(
    algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: Uint8Array,
    keyToWrap: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "AES-128-KW":
      case "AES-192-KW":
      case "AES-256-KW":
        return ReallyMeAesKw.wrapKeyWithProvider(
          algorithm,
          resolveWasmProvider(),
          wrappingKey,
          keyToWrap,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  unwrapKey(
    algorithm: ReallyMeKeyWrapAlgorithm,
    wrappingKey: Uint8Array,
    wrappedKey: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "AES-128-KW":
      case "AES-192-KW":
      case "AES-256-KW":
        return ReallyMeAesKw.unwrapKeyWithProvider(
          algorithm,
          resolveWasmProvider(),
          wrappingKey,
          wrappedKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },
});
