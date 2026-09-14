// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import type {
  ReallyMeHpkeSuite,
  ReallyMeKemAlgorithm,
  ReallyMeKeyAgreementAlgorithm,
  ReallyMeSignatureAlgorithm,
} from "./algorithms.js";
import { ReallyMeBip340Schnorr } from "./bip340Schnorr.js";
import type {
  ReallyMeHpkeSealedMessage,
  ReallyMeKemEncapsulation,
  ReallyMeKemKeyPair,
  ReallyMeKeyAgreementKeyPair,
  ReallyMeSignatureKeyPair,
} from "./cryptoFacade.js";
import { ReallyMeEd25519 } from "./ed25519.js";
import { ReallyMeCryptoError } from "./errors.js";
import { ReallyMeHpke } from "./hpke.js";
import { ReallyMeMlDsa } from "./mlDsa.js";
import { ReallyMeMlKem } from "./mlKem.js";
import { ReallyMeP256Ecdh } from "./p256Ecdh.js";
import { ReallyMeP256Ecdsa } from "./p256Ecdsa.js";
import { ReallyMeP384Ecdh } from "./p384Ecdh.js";
import { ReallyMeP384Ecdsa } from "./p384Ecdsa.js";
import { ReallyMeP521Ecdh } from "./p521Ecdh.js";
import { ReallyMeP521Ecdsa } from "./p521Ecdsa.js";
import { ReallyMeRsa } from "./rsa.js";
import type { ReallyMeRsaPublicKeyDerEncoding } from "./rsa.js";
import { ReallyMeSecp256k1 } from "./secp256k1.js";
import { ReallyMeSlhDsa } from "./slhDsa.js";
import type { ReallyMeWasmProvider } from "./wasmProvider.js";
import { ReallyMeX25519 } from "./x25519.js";
import { ReallyMeXWing } from "./xWing.js";

const SECP256K1_ECDSA: ReallyMeSignatureAlgorithm =
  "ECDSA-secp256k1-SHA256";
const P256_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P256-SHA256";
const P384_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P384-SHA384";
const P521_ECDSA: ReallyMeSignatureAlgorithm = "ECDSA-P521-SHA512";
const BIP340_SCHNORR: ReallyMeSignatureAlgorithm =
  "BIP340-Schnorr-secp256k1-SHA256";
const ED25519: ReallyMeSignatureAlgorithm = "Ed25519";

export const createReallyMeAsymmetricFacade = (
  resolveWasmProvider: () => ReallyMeWasmProvider,
) => ({
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
});
