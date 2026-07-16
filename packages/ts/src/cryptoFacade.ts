// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import type {
  ReallyMeAeadAlgorithm,
  ReallyMeHashAlgorithm,
  ReallyMeHpkeSuite,
  ReallyMeKdfAlgorithm,
  ReallyMeKemAlgorithm,
  ReallyMeKeyAgreementAlgorithm,
  ReallyMeKeyWrapAlgorithm,
  ReallyMeMacAlgorithm,
  ReallyMeSignatureAlgorithm,
} from "./algorithms.js";
import type { ReallyMeRsaPublicKeyDerEncoding } from "./rsa.js";
import { ReallyMeAead } from "./aead.js";
import { ReallyMeAesKw } from "./aesKw.js";
import { ARGON2ID_DERIVED_KEY_LENGTH, ReallyMeArgon2id } from "./argon2id.js";
import { ReallyMeBip340Schnorr } from "./bip340Schnorr.js";
import { ReallyMeDigest } from "./digest.js";
import { ReallyMeEd25519 } from "./ed25519.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ReallyMeHkdf } from "./hkdf.js";
import { ReallyMeHmac } from "./hmac.js";
import { ReallyMeHpke } from "./hpke.js";
import { ReallyMeJwaConcatKdf } from "./jwaConcatKdf.js";
import { ReallyMeMlDsa } from "./mlDsa.js";
import { ReallyMeMlKem } from "./mlKem.js";
import { ReallyMeP256Ecdsa } from "./p256Ecdsa.js";
import { ReallyMeP256Ecdh } from "./p256Ecdh.js";
import { ReallyMeP384Ecdsa } from "./p384Ecdsa.js";
import { ReallyMeP384Ecdh } from "./p384Ecdh.js";
import { ReallyMeP521Ecdsa } from "./p521Ecdsa.js";
import { ReallyMeP521Ecdh } from "./p521Ecdh.js";
import { ReallyMePbkdf2 } from "./pbkdf2.js";
import { ReallyMeRsa } from "./rsa.js";
import { ReallyMeSecp256k1 } from "./secp256k1.js";
import { ReallyMeSlhDsa } from "./slhDsa.js";
import { requireReallyMeWasmProvider } from "./wasmProvider.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";
import { ReallyMeX25519 } from "./x25519.js";
import { ReallyMeXWing } from "./xWing.js";

export type ReallyMeSignatureKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKemKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKeyAgreementKeyPair = Readonly<{
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}>;

export type ReallyMeKemEncapsulation = Readonly<{
  sharedSecret: Uint8Array;
  ciphertext: Uint8Array;
}>;

export type ReallyMeHpkeSealedMessage = Readonly<{
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}>;

const SECP256K1_ECDSA: ReallyMeSignatureAlgorithm =
  "ECDSA-secp256k1-SHA256";
const P256_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P256-SHA256";
const P384_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P384-SHA384";
const P521_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P521-SHA512";
const BIP340_SCHNORR: ReallyMeSignatureAlgorithm =
  "BIP340-Schnorr-secp256k1-SHA256";
const ED25519: ReallyMeSignatureAlgorithm = "Ed25519";

export type ReallyMeCryptoProviders = Readonly<{
  wasmProvider?: ReallyMeWasmProvider;
}>;

/**
 * Generic package facade. Algorithm-specific objects remain available for
 * callers that want direct provider access; this facade gives consumers a
 * stable typed route that fails closed for not-yet-exposed algorithms.
 */
const createReallyMeCryptoFacade = (
  resolveWasmProvider: () => ReallyMeWasmProvider,
) => ({
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
    algorithm: ReallyMeKdfAlgorithm,
    password: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "Argon2id":
        if (outputLength !== ARGON2ID_DERIVED_KEY_LENGTH) {
          throw new ReallyMeCryptoError("invalid-input");
        }
        // Argon2id is governed by fixed ReallyMe profile versions, not by
        // caller-selected iteration counts. This legacy generic KDF shape
        // preserves the existing facade contract; new code should call
        // deriveArgon2id(kdfVersion, secret, salt) so the profile selector is
        // explicit at the API boundary.
        return ReallyMeArgon2id.deriveKeyWithProvider(
          resolveWasmProvider(),
          iterations,
          password,
          salt,
        );
      case "PBKDF2-HMAC-SHA-256":
        return ReallyMePbkdf2.deriveHmacSha256(password, salt, iterations, outputLength);
      case "PBKDF2-HMAC-SHA-512":
        return ReallyMePbkdf2.deriveHmacSha512(password, salt, iterations, outputLength);
      case "HKDF-SHA256":
        throw new ReallyMeCryptoError("unsupported-algorithm");
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveHkdf(
    algorithm: ReallyMeKdfAlgorithm,
    inputKeyMaterial: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    outputLength: number,
  ): Uint8Array {
    switch (algorithm) {
      case "HKDF-SHA256":
        return ReallyMeHkdf.deriveSha256(inputKeyMaterial, salt, info, outputLength);
      case "Argon2id":
      case "PBKDF2-HMAC-SHA-256":
      case "PBKDF2-HMAC-SHA-512":
      case "JWA-CONCAT-KDF-SHA256":
        throw new ReallyMeCryptoError("unsupported-algorithm");
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveJwaConcatKdfSha256(
    algorithm: ReallyMeKdfAlgorithm,
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
      case "Argon2id":
      case "HKDF-SHA256":
      case "PBKDF2-HMAC-SHA-256":
      case "PBKDF2-HMAC-SHA-512":
        throw new ReallyMeCryptoError("unsupported-algorithm");
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
      case "AES-256-KW":
        return ReallyMeAesKw.wrapKeyWithProvider(
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
      case "AES-256-KW":
        return ReallyMeAesKw.unwrapKeyWithProvider(
          resolveWasmProvider(),
          wrappingKey,
          wrappedKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  generateKeyPair(algorithm: ReallyMeSignatureAlgorithm): ReallyMeSignatureKeyPair {
    if (algorithm === ED25519) {
      return ReallyMeEd25519.generateKeyPair();
    }
    switch (algorithm) {
      case P256_ECDSA:
        return ReallyMeP256Ecdsa.generateKeyPair();
      case P384_ECDSA:
        return ReallyMeP384Ecdsa.generateKeyPair();
      case P521_ECDSA:
        return ReallyMeP521Ecdsa.generateKeyPair();
      case SECP256K1_ECDSA:
        return ReallyMeSecp256k1.generateKeyPair();
      case BIP340_SCHNORR:
        return ReallyMeBip340Schnorr.generateKeyPair();
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
        return ReallyMeMlDsa.generateKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
        );
      case "SLH-DSA-SHA2-128s":
        return ReallyMeSlhDsa.generateKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveKeyPair(
    algorithm: ReallyMeSignatureAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeSignatureKeyPair {
    // Import an existing secret and reconstruct its public key. Do not use
    // this as key generation from passwords or other low-entropy input; use
    // generateKeyPair for new keys, or a protocol-approved KDF before import.
    if (algorithm === ED25519) {
      return ReallyMeEd25519.deriveKeyPair(secretKey);
    }
    switch (algorithm) {
      case P256_ECDSA:
        return ReallyMeP256Ecdsa.deriveKeyPair(secretKey);
      case P384_ECDSA:
        return ReallyMeP384Ecdsa.deriveKeyPair(secretKey);
      case P521_ECDSA:
        return ReallyMeP521Ecdsa.deriveKeyPair(secretKey);
      case SECP256K1_ECDSA:
        return ReallyMeSecp256k1.deriveKeyPair(secretKey);
      case BIP340_SCHNORR:
        return ReallyMeBip340Schnorr.deriveKeyPair(secretKey);
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
        return ReallyMeMlDsa.deriveKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
          secretKey,
        );
      case "SLH-DSA-SHA2-128s":
        // SLH-DSA deterministic derivation uses three FIPS seed components,
        // so it deliberately does not fit this single-secret import shape.
        throw new ReallyMeCryptoError("unsupported-algorithm");
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  sign(
    algorithm: ReallyMeSignatureAlgorithm,
    message: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    if (algorithm === ED25519) {
      return ReallyMeEd25519.sign(message, secretKey);
    }
    switch (algorithm) {
      case P256_ECDSA:
        return ReallyMeP256Ecdsa.sign(message, secretKey);
      case P384_ECDSA:
        return ReallyMeP384Ecdsa.sign(message, secretKey);
      case P521_ECDSA:
        return ReallyMeP521Ecdsa.sign(message, secretKey);
      case SECP256K1_ECDSA:
        return ReallyMeSecp256k1.sign(message, secretKey);
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
        return ReallyMeMlDsa.signWithProvider(
          resolveWasmProvider(),
          algorithm,
          message,
          secretKey,
        );
      case "SLH-DSA-SHA2-128s":
        return ReallyMeSlhDsa.signWithProvider(
          resolveWasmProvider(),
          algorithm,
          message,
          secretKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  signBip340Schnorr(
    message32: Uint8Array,
    secretKey: Uint8Array,
    auxRand32: Uint8Array,
  ): Uint8Array {
    return ReallyMeBip340Schnorr.sign(message32, secretKey, auxRand32);
  },

  verify(
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): void {
    if (algorithm === ED25519) {
      ReallyMeEd25519.verify(signature, message, publicKey);
      return;
    }
    switch (algorithm) {
      case P256_ECDSA:
        ReallyMeP256Ecdsa.verify(signature, message, publicKey);
        return;
      case P384_ECDSA:
        ReallyMeP384Ecdsa.verify(signature, message, publicKey);
        return;
      case P521_ECDSA:
        ReallyMeP521Ecdsa.verify(signature, message, publicKey);
        return;
      case SECP256K1_ECDSA:
        ReallyMeSecp256k1.verify(signature, message, publicKey);
        return;
      case BIP340_SCHNORR:
        ReallyMeBip340Schnorr.verify(signature, message, publicKey);
        return;
      case "ML-DSA-44":
      case "ML-DSA-65":
      case "ML-DSA-87":
        ReallyMeMlDsa.verifyWithProvider(
          resolveWasmProvider(),
          algorithm,
          signature,
          message,
          publicKey,
        );
        return;
      case "SLH-DSA-SHA2-128s":
        ReallyMeSlhDsa.verifyWithProvider(
          resolveWasmProvider(),
          algorithm,
          signature,
          message,
          publicKey,
        );
        return;
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  verifyRsa(
    algorithm: ReallyMeSignatureAlgorithm,
    signature: Uint8Array,
    message: Uint8Array,
    publicKeyDer: Uint8Array,
    publicKeyEncoding: ReallyMeRsaPublicKeyDerEncoding,
  ): void {
    switch (algorithm) {
      case "RSA-PKCS1v15-SHA1":
      case "RSA-PKCS1v15-SHA256":
      case "RSA-PKCS1v15-SHA384":
      case "RSA-PKCS1v15-SHA512":
      case "RSA-PSS-SHA1-MGF1-SHA1":
      case "RSA-PSS-SHA256-MGF1-SHA256":
      case "RSA-PSS-SHA384-MGF1-SHA384":
      case "RSA-PSS-SHA512-MGF1-SHA512":
        ReallyMeRsa.verifyWithProvider(
          resolveWasmProvider(),
          algorithm,
          signature,
          message,
          publicKeyDer,
          publicKeyEncoding,
        );
        return;
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveSharedSecret(
    algorithm: ReallyMeKeyAgreementAlgorithm,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "X25519":
        return ReallyMeX25519.deriveSharedSecret(publicKey, secretKey);
      case "P-256-ECDH":
        return ReallyMeP256Ecdh.deriveSharedSecret(publicKey, secretKey);
      case "P-384-ECDH":
        return ReallyMeP384Ecdh.deriveSharedSecret(publicKey, secretKey);
      case "P-521-ECDH":
        return ReallyMeP521Ecdh.deriveSharedSecret(publicKey, secretKey);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveKeyAgreementKeyPair(
    algorithm: ReallyMeKeyAgreementAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeKeyAgreementKeyPair {
    switch (algorithm) {
      case "X25519":
        return ReallyMeX25519.deriveKeyPair(secretKey);
      case "P-256-ECDH":
        return ReallyMeP256Ecdh.deriveKeyPair(secretKey);
      case "P-384-ECDH":
        return ReallyMeP384Ecdh.deriveKeyPair(secretKey);
      case "P-521-ECDH":
        return ReallyMeP521Ecdh.deriveKeyPair(secretKey);
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  generateKemKeyPair(algorithm: ReallyMeKemAlgorithm): ReallyMeKemKeyPair {
    switch (algorithm) {
      case "X-Wing-768":
      case "X-Wing-1024":
        return ReallyMeXWing.generateKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
        );
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
        return ReallyMeMlKem.generateKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  deriveKemKeyPair(
    algorithm: ReallyMeKemAlgorithm,
    secretKey: Uint8Array,
  ): ReallyMeKemKeyPair {
    switch (algorithm) {
      case "X-Wing-768":
      case "X-Wing-1024":
        return ReallyMeXWing.deriveKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
          secretKey,
        );
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
        return ReallyMeMlKem.deriveKeyPairWithProvider(
          resolveWasmProvider(),
          algorithm,
          secretKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  encapsulate(
    algorithm: ReallyMeKemAlgorithm,
    publicKey: Uint8Array,
  ): ReallyMeKemEncapsulation {
    switch (algorithm) {
      case "X-Wing-768":
      case "X-Wing-1024":
        return ReallyMeXWing.encapsulateWithProvider(
          resolveWasmProvider(),
          algorithm,
          publicKey,
        );
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
        return ReallyMeMlKem.encapsulateWithProvider(
          resolveWasmProvider(),
          algorithm,
          publicKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  decapsulate(
    algorithm: ReallyMeKemAlgorithm,
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    switch (algorithm) {
      case "X-Wing-768":
      case "X-Wing-1024":
        return ReallyMeXWing.decapsulateWithProvider(
          resolveWasmProvider(),
          algorithm,
          ciphertext,
          secretKey,
        );
      case "ML-KEM-512":
      case "ML-KEM-768":
      case "ML-KEM-1024":
        return ReallyMeMlKem.decapsulateWithProvider(
          resolveWasmProvider(),
          algorithm,
          ciphertext,
          secretKey,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  sealHpke(
    suite: ReallyMeHpkeSuite,
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): ReallyMeHpkeSealedMessage {
    switch (suite) {
      case "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM":
      case "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305":
        return ReallyMeHpke.sealBaseWithProvider(
          resolveWasmProvider(),
          suite,
          recipientPublicKey,
          info,
          aad,
          plaintext,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },

  openHpke(
    suite: ReallyMeHpkeSuite,
    recipientSecretKey: Uint8Array,
    encapsulatedKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
  ): Uint8Array {
    switch (suite) {
      case "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM":
      case "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305":
        return ReallyMeHpke.openBaseWithProvider(
          resolveWasmProvider(),
          suite,
          recipientSecretKey,
          encapsulatedKey,
          info,
          aad,
          ciphertext,
        );
      default:
        throw new ReallyMeCryptoError("unsupported-algorithm");
    }
  },
} as const);

export type ReallyMeCryptoFacade = ReturnType<typeof createReallyMeCryptoFacade>;

export const createReallyMeCrypto = (
  providers: ReallyMeCryptoProviders = {},
): ReallyMeCryptoFacade => {
  const configuredProvider = providers.wasmProvider;
  return createReallyMeCryptoFacade(() => {
    if (configuredProvider === undefined) {
      throw new ReallyMeCryptoError("provider-failure");
    }
    return configuredProvider;
  });
};

export const ReallyMeCrypto = createReallyMeCryptoFacade(requireReallyMeWasmProvider);
