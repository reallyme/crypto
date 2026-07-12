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
import { ReallyMeCryptoError } from "./errors.js";
export {
  AeadAlgorithm,
  AeadAlgorithmSchema,
  CryptoAlgorithmFamily,
  CryptoAlgorithmIdentifierSchema,
  CryptoAlgorithmFamilySchema,
  HashAlgorithm,
  HashAlgorithmSchema,
  HpkeSuite,
  HpkeSuiteSchema,
  JsonWebKeySchema,
  JsonWebKeySetSchema,
  KdfAlgorithm,
  KdfAlgorithmSchema,
  KemAlgorithm,
  KemAlgorithmSchema,
  KeyAgreementAlgorithm,
  KeyAgreementAlgorithmSchema,
  KeyWrapAlgorithm,
  KeyWrapAlgorithmSchema,
  MacAlgorithm,
  MacAlgorithmSchema,
  MulticodecKeyAlgorithm,
  MulticodecKeyAlgorithmSchema,
  SignatureAlgorithm,
  SignatureAlgorithmSchema,
  file_reallyme_crypto_v1_crypto,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
export type {
  CryptoAlgorithmIdentifier,
  JsonWebKey,
  JsonWebKeySet,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import {
  AeadAlgorithm,
  HashAlgorithm,
  HpkeSuite,
  KdfAlgorithm,
  KemAlgorithm,
  KeyAgreementAlgorithm,
  KeyWrapAlgorithm,
  MacAlgorithm,
  MulticodecKeyAlgorithm,
  SignatureAlgorithm,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

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

export const signatureAlgorithmFromProto = (
  value: SignatureAlgorithm,
): ReallyMeSignatureAlgorithm => {
  switch (value) {
    case SignatureAlgorithm.ED25519:
      return "Ed25519";
    case SignatureAlgorithm.ECDSA_P256_SHA256:
      return "ECDSA-P256-SHA256";
    case SignatureAlgorithm.ECDSA_P384_SHA384:
      return "ECDSA-P384-SHA384";
    case SignatureAlgorithm.ECDSA_P521_SHA512:
      return "ECDSA-P521-SHA512";
    case SignatureAlgorithm.ECDSA_SECP256K1_SHA256:
      return "ECDSA-secp256k1-SHA256";
    case SignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256:
      return "BIP340-Schnorr-secp256k1-SHA256";
    case SignatureAlgorithm.RSA_PKCS1V15_SHA1:
      return "RSA-PKCS1v15-SHA1";
    case SignatureAlgorithm.RSA_PKCS1V15_SHA256:
      return "RSA-PKCS1v15-SHA256";
    case SignatureAlgorithm.RSA_PKCS1V15_SHA384:
      return "RSA-PKCS1v15-SHA384";
    case SignatureAlgorithm.RSA_PKCS1V15_SHA512:
      return "RSA-PKCS1v15-SHA512";
    case SignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1:
      return "RSA-PSS-SHA1-MGF1-SHA1";
    case SignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256:
      return "RSA-PSS-SHA256-MGF1-SHA256";
    case SignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384:
      return "RSA-PSS-SHA384-MGF1-SHA384";
    case SignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512:
      return "RSA-PSS-SHA512-MGF1-SHA512";
    case SignatureAlgorithm.ML_DSA_44:
      return "ML-DSA-44";
    case SignatureAlgorithm.ML_DSA_65:
      return "ML-DSA-65";
    case SignatureAlgorithm.ML_DSA_87:
      return "ML-DSA-87";
    case SignatureAlgorithm.SLH_DSA_SHA2_128S:
      return "SLH-DSA-SHA2-128s";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const signatureAlgorithmToProto = (
  value: ReallyMeSignatureAlgorithm,
): SignatureAlgorithm => {
  switch (value) {
    case "Ed25519":
      return SignatureAlgorithm.ED25519;
    case "ECDSA-P256-SHA256":
      return SignatureAlgorithm.ECDSA_P256_SHA256;
    case "ECDSA-P384-SHA384":
      return SignatureAlgorithm.ECDSA_P384_SHA384;
    case "ECDSA-P521-SHA512":
      return SignatureAlgorithm.ECDSA_P521_SHA512;
    case "ECDSA-secp256k1-SHA256":
      return SignatureAlgorithm.ECDSA_SECP256K1_SHA256;
    case "BIP340-Schnorr-secp256k1-SHA256":
      return SignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256;
    case "RSA-PKCS1v15-SHA1":
      return SignatureAlgorithm.RSA_PKCS1V15_SHA1;
    case "RSA-PKCS1v15-SHA256":
      return SignatureAlgorithm.RSA_PKCS1V15_SHA256;
    case "RSA-PKCS1v15-SHA384":
      return SignatureAlgorithm.RSA_PKCS1V15_SHA384;
    case "RSA-PKCS1v15-SHA512":
      return SignatureAlgorithm.RSA_PKCS1V15_SHA512;
    case "RSA-PSS-SHA1-MGF1-SHA1":
      return SignatureAlgorithm.RSA_PSS_SHA1_MGF1_SHA1;
    case "RSA-PSS-SHA256-MGF1-SHA256":
      return SignatureAlgorithm.RSA_PSS_SHA256_MGF1_SHA256;
    case "RSA-PSS-SHA384-MGF1-SHA384":
      return SignatureAlgorithm.RSA_PSS_SHA384_MGF1_SHA384;
    case "RSA-PSS-SHA512-MGF1-SHA512":
      return SignatureAlgorithm.RSA_PSS_SHA512_MGF1_SHA512;
    case "ML-DSA-44":
      return SignatureAlgorithm.ML_DSA_44;
    case "ML-DSA-65":
      return SignatureAlgorithm.ML_DSA_65;
    case "ML-DSA-87":
      return SignatureAlgorithm.ML_DSA_87;
    case "SLH-DSA-SHA2-128s":
      return SignatureAlgorithm.SLH_DSA_SHA2_128S;
  }
};

export const hashAlgorithmFromProto = (
  value: HashAlgorithm,
): ReallyMeHashAlgorithm => {
  switch (value) {
    case HashAlgorithm.SHA2_256:
      return "SHA2-256";
    case HashAlgorithm.SHA2_384:
      return "SHA2-384";
    case HashAlgorithm.SHA2_512:
      return "SHA2-512";
    case HashAlgorithm.SHA3_224:
      return "SHA3-224";
    case HashAlgorithm.SHA3_256:
      return "SHA3-256";
    case HashAlgorithm.SHA3_384:
      return "SHA3-384";
    case HashAlgorithm.SHA3_512:
      return "SHA3-512";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const hashAlgorithmToProto = (value: ReallyMeHashAlgorithm): HashAlgorithm => {
  switch (value) {
    case "SHA2-256":
      return HashAlgorithm.SHA2_256;
    case "SHA2-384":
      return HashAlgorithm.SHA2_384;
    case "SHA2-512":
      return HashAlgorithm.SHA2_512;
    case "SHA3-224":
      return HashAlgorithm.SHA3_224;
    case "SHA3-256":
      return HashAlgorithm.SHA3_256;
    case "SHA3-384":
      return HashAlgorithm.SHA3_384;
    case "SHA3-512":
      return HashAlgorithm.SHA3_512;
  }
};

export const aeadAlgorithmFromProto = (
  value: AeadAlgorithm,
): ReallyMeAeadAlgorithm => {
  switch (value) {
    case AeadAlgorithm.AES_128_GCM:
      return "AES-128-GCM";
    case AeadAlgorithm.AES_192_GCM:
      return "AES-192-GCM";
    case AeadAlgorithm.AES_256_GCM:
      return "AES-256-GCM";
    case AeadAlgorithm.AES_256_GCM_SIV:
      return "AES-256-GCM-SIV";
    case AeadAlgorithm.CHACHA20_POLY1305:
      return "ChaCha20-Poly1305";
    case AeadAlgorithm.XCHACHA20_POLY1305:
      return "XChaCha20-Poly1305";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const aeadAlgorithmToProto = (value: ReallyMeAeadAlgorithm): AeadAlgorithm => {
  switch (value) {
    case "AES-128-GCM":
      return AeadAlgorithm.AES_128_GCM;
    case "AES-192-GCM":
      return AeadAlgorithm.AES_192_GCM;
    case "AES-256-GCM":
      return AeadAlgorithm.AES_256_GCM;
    case "AES-256-GCM-SIV":
      return AeadAlgorithm.AES_256_GCM_SIV;
    case "ChaCha20-Poly1305":
      return AeadAlgorithm.CHACHA20_POLY1305;
    case "XChaCha20-Poly1305":
      return AeadAlgorithm.XCHACHA20_POLY1305;
  }
};

export const kemAlgorithmFromProto = (value: KemAlgorithm): ReallyMeKemAlgorithm => {
  switch (value) {
    case KemAlgorithm.ML_KEM_512:
      return "ML-KEM-512";
    case KemAlgorithm.ML_KEM_768:
      return "ML-KEM-768";
    case KemAlgorithm.ML_KEM_1024:
      return "ML-KEM-1024";
    case KemAlgorithm.X_WING_768:
      return "X-Wing-768";
    case KemAlgorithm.X_WING_1024:
      return "X-Wing-1024";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const kemAlgorithmToProto = (value: ReallyMeKemAlgorithm): KemAlgorithm => {
  switch (value) {
    case "ML-KEM-512":
      return KemAlgorithm.ML_KEM_512;
    case "ML-KEM-768":
      return KemAlgorithm.ML_KEM_768;
    case "ML-KEM-1024":
      return KemAlgorithm.ML_KEM_1024;
    case "X-Wing-768":
      return KemAlgorithm.X_WING_768;
    case "X-Wing-1024":
      return KemAlgorithm.X_WING_1024;
  }
};

export const keyAgreementAlgorithmFromProto = (
  value: KeyAgreementAlgorithm,
): ReallyMeKeyAgreementAlgorithm => {
  switch (value) {
    case KeyAgreementAlgorithm.X25519:
      return "X25519";
    case KeyAgreementAlgorithm.P256_ECDH:
      return "P-256-ECDH";
    case KeyAgreementAlgorithm.P384_ECDH:
      return "P-384-ECDH";
    case KeyAgreementAlgorithm.P521_ECDH:
      return "P-521-ECDH";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const keyAgreementAlgorithmToProto = (
  value: ReallyMeKeyAgreementAlgorithm,
): KeyAgreementAlgorithm => {
  switch (value) {
    case "X25519":
      return KeyAgreementAlgorithm.X25519;
    case "P-256-ECDH":
      return KeyAgreementAlgorithm.P256_ECDH;
    case "P-384-ECDH":
      return KeyAgreementAlgorithm.P384_ECDH;
    case "P-521-ECDH":
      return KeyAgreementAlgorithm.P521_ECDH;
  }
};

export const macAlgorithmFromProto = (value: MacAlgorithm): ReallyMeMacAlgorithm => {
  switch (value) {
    case MacAlgorithm.HMAC_SHA256:
      return "HMAC-SHA-256";
    case MacAlgorithm.HMAC_SHA512:
      return "HMAC-SHA-512";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const macAlgorithmToProto = (value: ReallyMeMacAlgorithm): MacAlgorithm => {
  switch (value) {
    case "HMAC-SHA-256":
      return MacAlgorithm.HMAC_SHA256;
    case "HMAC-SHA-512":
      return MacAlgorithm.HMAC_SHA512;
  }
};

export const kdfAlgorithmFromProto = (value: KdfAlgorithm): ReallyMeKdfAlgorithm => {
  switch (value) {
    case KdfAlgorithm.HKDF_SHA256:
      return "HKDF-SHA256";
    case KdfAlgorithm.ARGON2ID:
      return "Argon2id";
    case KdfAlgorithm.PBKDF2_HMAC_SHA256:
      return "PBKDF2-HMAC-SHA-256";
    case KdfAlgorithm.PBKDF2_HMAC_SHA512:
      return "PBKDF2-HMAC-SHA-512";
    case KdfAlgorithm.JWA_CONCAT_KDF_SHA256:
      return "JWA-CONCAT-KDF-SHA256";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const kdfAlgorithmToProto = (value: ReallyMeKdfAlgorithm): KdfAlgorithm => {
  switch (value) {
    case "HKDF-SHA256":
      return KdfAlgorithm.HKDF_SHA256;
    case "Argon2id":
      return KdfAlgorithm.ARGON2ID;
    case "PBKDF2-HMAC-SHA-256":
      return KdfAlgorithm.PBKDF2_HMAC_SHA256;
    case "PBKDF2-HMAC-SHA-512":
      return KdfAlgorithm.PBKDF2_HMAC_SHA512;
    case "JWA-CONCAT-KDF-SHA256":
      return KdfAlgorithm.JWA_CONCAT_KDF_SHA256;
  }
};

export const keyWrapAlgorithmFromProto = (
  value: KeyWrapAlgorithm,
): ReallyMeKeyWrapAlgorithm => {
  switch (value) {
    case KeyWrapAlgorithm.AES_256_KW:
      return "AES-256-KW";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const keyWrapAlgorithmToProto = (
  value: ReallyMeKeyWrapAlgorithm,
): KeyWrapAlgorithm => {
  switch (value) {
    case "AES-256-KW":
      return KeyWrapAlgorithm.AES_256_KW;
  }
};

export const hpkeSuiteFromProto = (value: HpkeSuite): ReallyMeHpkeSuite => {
  switch (value) {
    case HpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM:
      return "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM";
    case HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305:
      return "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305";
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const hpkeSuiteToProto = (value: ReallyMeHpkeSuite): HpkeSuite => {
  switch (value) {
    case "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM":
      return HpkeSuite.DHKEM_P256_HKDF_SHA256_HKDF_SHA256_AES_256_GCM;
    case "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305":
      return HpkeSuite.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305;
  }
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
