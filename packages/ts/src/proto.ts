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
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ReallyMeCryptoError } from "./errors.js";
import type {
  ReallyMeHpkeSealedMessage,
  ReallyMeKemEncapsulation,
  ReallyMeKemKeyPair,
  ReallyMeKeyAgreementKeyPair,
  ReallyMeSignatureKeyPair,
} from "./cryptoFacade.js";
import type {
  ReallyMeJwkAlgorithm,
  ReallyMeJwkKey,
  ReallyMeJwksKeySet,
} from "./jwk.js";
import { ReallyMeJwk } from "./jwk.js";
export {
  AeadAlgorithm,
  AeadAlgorithmSchema,
  CryptoAlgorithmFamily,
  CryptoAlgorithmFamilySchema,
  CryptoAlgorithmIdentifierSchema,
  CryptoAeadOpenRequestSchema,
  CryptoAeadOpenResultSchema,
  CryptoAeadSealRequestSchema,
  CryptoAeadSealResultSchema,
  CryptoBackendErrorSchema,
  CryptoBip340SchnorrSignRequestSchema,
  CryptoErrorSchema,
  CryptoErrorReason,
  CryptoErrorReasonSchema,
  CryptoHashRequestSchema,
  CryptoHashResultSchema,
  CryptoHkdfDeriveRequestSchema,
  CryptoHkdfDeriveResultSchema,
  CryptoHpkeOpenRequestSchema,
  CryptoHpkeOpenResultSchema,
  CryptoHpkeSealRequestSchema,
  CryptoHpkeSealedMessageSchema,
  CryptoJwaConcatKdfSha256DeriveRequestSchema,
  CryptoJwaConcatKdfSha256DeriveResultSchema,
  CryptoKdfDeriveKeyRequestSchema,
  CryptoKdfDeriveKeyResultSchema,
  CryptoKemEncapsulationSchema,
  CryptoKemDecapsulateRequestSchema,
  CryptoKemDecapsulateResultSchema,
  CryptoKemEncapsulateRequestSchema,
  CryptoKemGenerateKeyPairRequestSchema,
  CryptoKeyAgreementDeriveKeyPairRequestSchema,
  CryptoKeyAgreementDeriveSharedSecretRequestSchema,
  CryptoKeyAgreementDeriveSharedSecretResultSchema,
  CryptoKeyPairSchema,
  CryptoKeyUnwrapRequestSchema,
  CryptoKeyUnwrapResultSchema,
  CryptoKeyWrapRequestSchema,
  CryptoKeyWrapResultSchema,
  CryptoMacAuthenticateRequestSchema,
  CryptoMacAuthenticateResultSchema,
  CryptoMacVerifyRequestSchema,
  CryptoPrimitiveErrorSchema,
  CryptoProviderErrorSchema,
  CryptoProviderCapabilitySchema,
  CryptoProviderCapabilitySetSchema,
  CryptoProviderSupportStatus,
  CryptoProviderSupportStatusSchema,
  CryptoRsaVerifyRequestSchema,
  CryptoSignatureDeriveKeyPairRequestSchema,
  CryptoSignatureGenerateKeyPairRequestSchema,
  CryptoSignatureSignRequestSchema,
  CryptoSignatureSignResultSchema,
  CryptoSignatureVerifyRequestSchema,
  CryptoVerificationResultSchema,
  CryptoVerificationStatus,
  CryptoVerificationStatusSchema,
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
  CryptoAeadOpenRequest,
  CryptoAeadOpenResult,
  CryptoAeadSealRequest,
  CryptoAeadSealResult,
  CryptoBackendError,
  CryptoBip340SchnorrSignRequest,
  CryptoError,
  CryptoHashRequest,
  CryptoHashResult,
  CryptoHkdfDeriveRequest,
  CryptoHkdfDeriveResult,
  CryptoHpkeOpenRequest,
  CryptoHpkeOpenResult,
  CryptoHpkeSealRequest,
  CryptoHpkeSealedMessage,
  CryptoJwaConcatKdfSha256DeriveRequest,
  CryptoJwaConcatKdfSha256DeriveResult,
  CryptoKdfDeriveKeyRequest,
  CryptoKdfDeriveKeyResult,
  CryptoKemEncapsulation,
  CryptoKemDecapsulateRequest,
  CryptoKemDecapsulateResult,
  CryptoKemEncapsulateRequest,
  CryptoKemGenerateKeyPairRequest,
  CryptoKeyAgreementDeriveKeyPairRequest,
  CryptoKeyAgreementDeriveSharedSecretRequest,
  CryptoKeyAgreementDeriveSharedSecretResult,
  CryptoKeyPair,
  CryptoKeyUnwrapRequest,
  CryptoKeyUnwrapResult,
  CryptoKeyWrapRequest,
  CryptoKeyWrapResult,
  CryptoMacAuthenticateRequest,
  CryptoMacAuthenticateResult,
  CryptoMacVerifyRequest,
  CryptoPrimitiveError,
  CryptoProviderCapability,
  CryptoProviderCapabilitySet,
  CryptoProviderError,
  CryptoRsaVerifyRequest,
  CryptoSignatureDeriveKeyPairRequest,
  CryptoSignatureGenerateKeyPairRequest,
  CryptoSignatureSignRequest,
  CryptoSignatureSignResult,
  CryptoSignatureVerifyRequest,
  CryptoVerificationResult,
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
  CryptoAlgorithmIdentifierSchema,
  CryptoAlgorithmFamily,
  CryptoBackendErrorSchema,
  CryptoErrorReason,
  CryptoErrorSchema,
  CryptoHpkeSealedMessageSchema,
  CryptoKemEncapsulationSchema,
  CryptoKeyPairSchema,
  CryptoPrimitiveErrorSchema,
  CryptoProviderCapabilitySchema,
  CryptoProviderCapabilitySetSchema,
  CryptoProviderErrorSchema,
  CryptoProviderSupportStatus,
  CryptoVerificationResultSchema,
  CryptoVerificationStatus,
  JsonWebKeySchema,
  JsonWebKeySetSchema,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";
import type {
  CryptoAlgorithmIdentifier,
  CryptoError,
  CryptoHpkeSealedMessage,
  CryptoKemEncapsulation,
  CryptoKeyPair,
  CryptoProviderCapability,
  CryptoProviderCapabilitySet,
  CryptoVerificationResult,
  JsonWebKey,
  JsonWebKeySet,
} from "./proto/generated/reallyme/crypto/v1/crypto_pb.js";

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

export type ReallyMeCryptoProtoStatus = "result" | "crypto-error";

export class ReallyMeCryptoProtoResult {
  readonly #bytes: Uint8Array;
  public readonly status: ReallyMeCryptoProtoStatus;

  public constructor(status: ReallyMeCryptoProtoStatus, bytes: Uint8Array) {
    this.status = status;
    this.#bytes = bytes.slice();
  }

  public get bytes(): Uint8Array {
    return this.#bytes.slice();
  }

  public get isCryptoError(): boolean {
    return this.status === "crypto-error";
  }

  public bestEffortClear(): void {
    this.#bytes.fill(0);
  }

  public toString(): string {
    return `ReallyMeCryptoProtoResult(status=${this.status}, bytes=<redacted>)`;
  }

  public toJSON(): Readonly<{ status: ReallyMeCryptoProtoStatus; bytes: "<redacted>" }> {
    return { status: this.status, bytes: "<redacted>" };
  }
}

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

const signatureAlgorithmIdentifierToProto = (
  value: ReallyMeSignatureAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "signature", value: signatureAlgorithmToProto(value) },
  });

const keyAgreementAlgorithmIdentifierToProto = (
  value: ReallyMeKeyAgreementAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "keyAgreement", value: keyAgreementAlgorithmToProto(value) },
  });

const kemAlgorithmIdentifierToProto = (
  value: ReallyMeKemAlgorithm,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "kem", value: kemAlgorithmToProto(value) },
  });

const hpkeSuiteIdentifierToProto = (
  value: ReallyMeHpkeSuite,
): CryptoAlgorithmIdentifier =>
  create(CryptoAlgorithmIdentifierSchema, {
    algorithm: { case: "hpke", value: hpkeSuiteToProto(value) },
  });

const signatureAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeSignatureAlgorithm => {
  if (value?.algorithm.case !== "signature") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return signatureAlgorithmFromProto(value.algorithm.value);
};

const keyAgreementAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeKeyAgreementAlgorithm => {
  if (value?.algorithm.case !== "keyAgreement") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return keyAgreementAlgorithmFromProto(value.algorithm.value);
};

const kemAlgorithmFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeKemAlgorithm => {
  if (value?.algorithm.case !== "kem") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return kemAlgorithmFromProto(value.algorithm.value);
};

const hpkeSuiteFromIdentifier = (
  value: CryptoAlgorithmIdentifier | undefined,
): ReallyMeHpkeSuite => {
  if (value?.algorithm.case !== "hpke") {
    throw new ReallyMeCryptoError("invalid-input");
  }
  return hpkeSuiteFromProto(value.algorithm.value);
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

const asciiToBytes = (value: string): Uint8Array => {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit > 0x7f) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    bytes[index] = codeUnit;
  }
  return bytes;
};

const asciiFromBytes = (value: Uint8Array): string => {
  const codeUnits: number[] = [];
  for (const byte of value) {
    if (byte > 0x7f) {
      throw new ReallyMeCryptoError("invalid-input");
    }
    codeUnits.push(byte);
  }
  return String.fromCharCode(...codeUnits);
};

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
    case CryptoErrorReason.BACKEND_INVALID_STATE:
    case CryptoErrorReason.BACKEND_INTERNAL:
    case CryptoErrorReason.BACKEND_MALFORMED_PROTOBUF:
    case CryptoErrorReason.BACKEND_MALFORMED_JSON:
    case CryptoErrorReason.BACKEND_RESOURCE_LIMIT_EXCEEDED:
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
  branch: "backend",
  reason: CryptoErrorReason.BACKEND_MALFORMED_PROTOBUF,
  reasonCode: CryptoErrorReason.BACKEND_MALFORMED_PROTOBUF,
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
]);

const providerCryptoErrorReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.PROVIDER_UNSUPPORTED_ALGORITHM,
  CryptoErrorReason.PROVIDER_UNSUPPORTED_BACKEND,
  CryptoErrorReason.PROVIDER_UNAVAILABLE,
  CryptoErrorReason.PROVIDER_RANDOMNESS_UNAVAILABLE,
]);

const backendCryptoErrorReasons = new Set<CryptoErrorReason>([
  CryptoErrorReason.BACKEND_INVALID_STATE,
  CryptoErrorReason.BACKEND_INTERNAL,
  CryptoErrorReason.BACKEND_MALFORMED_PROTOBUF,
  CryptoErrorReason.BACKEND_MALFORMED_JSON,
  CryptoErrorReason.BACKEND_RESOURCE_LIMIT_EXCEEDED,
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

export const cryptoProtoResult = (bytes: Uint8Array): ReallyMeCryptoProtoResult =>
  new ReallyMeCryptoProtoResult("result", bytes);

export const cryptoProtoErrorResult = (
  error: CryptoError | ReallyMeCryptoWireError | ReallyMeCryptoError,
): ReallyMeCryptoProtoResult => {
  const bytes = error instanceof ReallyMeCryptoError
    ? cryptoErrorToProtoBytes(error)
    : "branch" in error
      ? cryptoWireErrorToProtoBytes(error)
      : toBinary(CryptoErrorSchema, error);
  return new ReallyMeCryptoProtoResult("crypto-error", bytes);
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

const signatureJwkAlgorithmToProto = (
  value: ReallyMeJwkAlgorithm,
): SignatureAlgorithm => {
  switch (value) {
    case "Ed25519":
      return SignatureAlgorithm.ED25519;
    case "P-256":
      return SignatureAlgorithm.ECDSA_P256_SHA256;
    case "secp256k1":
      return SignatureAlgorithm.ECDSA_SECP256K1_SHA256;
    case "ML-DSA-44":
      return SignatureAlgorithm.ML_DSA_44;
    case "ML-DSA-65":
      return SignatureAlgorithm.ML_DSA_65;
    case "ML-DSA-87":
      return SignatureAlgorithm.ML_DSA_87;
    case "SLH-DSA-SHA2-128s":
      return SignatureAlgorithm.SLH_DSA_SHA2_128S;
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

const jwkAlgorithmToProto = (
  value: ReallyMeJwkAlgorithm,
): CryptoAlgorithmIdentifier => {
  switch (value) {
    case "X25519":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "keyAgreement",
          value: KeyAgreementAlgorithm.X25519,
        },
      });
    case "ML-KEM-512":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_512,
        },
      });
    case "ML-KEM-768":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_768,
        },
      });
    case "ML-KEM-1024":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.ML_KEM_1024,
        },
      });
    case "X-Wing-768":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.X_WING_768,
        },
      });
    case "X-Wing-1024":
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "kem",
          value: KemAlgorithm.X_WING_1024,
        },
      });
    default:
      return create(CryptoAlgorithmIdentifierSchema, {
        algorithm: {
          case: "signature",
          value: signatureJwkAlgorithmToProto(value),
        },
      });
  }
};

const signatureJwkAlgorithmFromProto = (
  value: SignatureAlgorithm,
): ReallyMeJwkAlgorithm => {
  switch (value) {
    case SignatureAlgorithm.ED25519:
      return "Ed25519";
    case SignatureAlgorithm.ECDSA_P256_SHA256:
      return "P-256";
    case SignatureAlgorithm.ECDSA_SECP256K1_SHA256:
      return "secp256k1";
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

const jwkAlgorithmFromProto = (
  value: CryptoAlgorithmIdentifier,
): ReallyMeJwkAlgorithm => {
  switch (value.algorithm.case) {
    case "signature":
      return signatureJwkAlgorithmFromProto(value.algorithm.value);
    case "keyAgreement":
      if (value.algorithm.value === KeyAgreementAlgorithm.X25519) {
        return "X25519";
      }
      throw new ReallyMeCryptoError("unsupported-algorithm");
    case "kem":
      switch (value.algorithm.value) {
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
    default:
      throw new ReallyMeCryptoError("unsupported-algorithm");
  }
};

export const jsonWebKeyToProto = (key: ReallyMeJwkKey): JsonWebKey =>
  create(JsonWebKeySchema, {
    algorithm: jwkAlgorithmToProto(key.algorithm),
    publicKey: key.publicKey,
    canonicalJcs: asciiToBytes(ReallyMeJwk.toJcs(key.jwk)),
  });

export const jsonWebKeyToProtoBytes = (key: ReallyMeJwkKey): Uint8Array =>
  toBinary(JsonWebKeySchema, jsonWebKeyToProto(key));

export const jsonWebKeyFromProto = (value: JsonWebKey): ReallyMeJwkKey => {
  const algorithm = value.algorithm === undefined
    ? undefined
    : jwkAlgorithmFromProto(value.algorithm);
  if (algorithm === undefined) {
    throw new ReallyMeCryptoError("invalid-input");
  }
  const jwk = ReallyMeJwk.toJwk(algorithm, value.publicKey);
  if (value.canonicalJcs.length > 0) {
    const expected = ReallyMeJwk.toJcs(jwk);
    if (asciiFromBytes(value.canonicalJcs) !== expected) {
      throw new ReallyMeCryptoError("invalid-input");
    }
  }
  return { algorithm, publicKey: value.publicKey, jwk };
};

export const jsonWebKeyFromProtoBytes = (bytes: Uint8Array): ReallyMeJwkKey => {
  try {
    return jsonWebKeyFromProto(fromBinary(JsonWebKeySchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

export const jsonWebKeySetToProto = (
  keySet: ReallyMeJwksKeySet,
): JsonWebKeySet =>
  create(JsonWebKeySetSchema, {
    keys: keySet.keys.map((key) => jsonWebKeyToProto(key)),
  });

export const jsonWebKeySetToProtoBytes = (
  keySet: ReallyMeJwksKeySet,
): Uint8Array => toBinary(JsonWebKeySetSchema, jsonWebKeySetToProto(keySet));

export const jsonWebKeySetFromProto = (
  value: JsonWebKeySet,
): ReallyMeJwksKeySet => ({
  keys: value.keys.map((key) => jsonWebKeyFromProto(key)),
});

export const jsonWebKeySetFromProtoBytes = (
  bytes: Uint8Array,
): ReallyMeJwksKeySet => {
  try {
    return jsonWebKeySetFromProto(fromBinary(JsonWebKeySetSchema, bytes));
  } catch (error) {
    if (error instanceof ReallyMeCryptoError) {
      throw error;
    }
    throw new ReallyMeCryptoError("invalid-input");
  }
};

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
