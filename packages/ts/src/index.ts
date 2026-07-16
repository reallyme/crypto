// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export { ReallyMeCryptoError } from "./errors.js";
export type { ReallyMeCryptoErrorCode } from "./errors.js";
export {
  REALLYME_AEAD_ALGORITHMS,
  REALLYME_HASH_ALGORITHMS,
  REALLYME_HPKE_SUITES,
  REALLYME_KDF_ALGORITHMS,
  REALLYME_KEM_ALGORITHMS,
  REALLYME_KEY_AGREEMENT_ALGORITHMS,
  REALLYME_KEY_WRAP_ALGORITHMS,
  REALLYME_MAC_ALGORITHMS,
  REALLYME_SIGNATURE_ALGORITHMS,
} from "./algorithms.js";
export type {
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
export {
  AEAD_KEY_LENGTH,
  AEAD_NONCE_LENGTH,
  AEAD_TAG_LENGTH,
  AES_128_GCM_KEY_LENGTH,
  AES_192_GCM_KEY_LENGTH,
  AES_256_GCM_KEY_LENGTH,
  CHACHA20_POLY1305_KEY_LENGTH,
  ReallyMeAead,
  XCHACHA20_POLY1305_NONCE_LENGTH,
} from "./aead.js";
export {
  AES_256_KW_KEK_LENGTH,
  AES_KW_BLOCK_LENGTH,
  AES_KW_INTEGRITY_CHECK_LENGTH,
  AES_KW_MAX_KEY_DATA_LENGTH,
  AES_KW_MIN_KEY_DATA_LENGTH,
  AES_KW_MIN_WRAPPED_KEY_LENGTH,
  ReallyMeAesKw,
} from "./aesKw.js";
export {
  ARGON2ID_DERIVED_KEY_LENGTH,
  ARGON2ID_SALT_MAX_LENGTH,
  ARGON2ID_SALT_MIN_LENGTH,
  ARGON2ID_V1,
  ARGON2ID_V2,
  ReallyMeArgon2id,
} from "./argon2id.js";
export {
  BIP340_SCHNORR_AUX_RAND_LENGTH,
  BIP340_SCHNORR_MESSAGE_LENGTH,
  BIP340_SCHNORR_PUBLIC_KEY_LENGTH,
  BIP340_SCHNORR_SECRET_KEY_LENGTH,
  BIP340_SCHNORR_SIGNATURE_LENGTH,
  ReallyMeBip340Schnorr,
} from "./bip340Schnorr.js";
export {
  HPKE_AEAD_TAG_LENGTH,
  HPKE_P256_PRIVATE_KEY_LENGTH,
  HPKE_P256_PUBLIC_KEY_LENGTH,
  HPKE_X25519_PRIVATE_KEY_LENGTH,
  HPKE_X25519_PUBLIC_KEY_LENGTH,
  ReallyMeHpke,
} from "./hpke.js";
export type { ReallyMeHpkeSealedMessage as ReallyMeHpkeProviderSealedMessage } from "./hpke.js";
export { ReallyMeJwk } from "./jwk.js";
export type {
  ReallyMeAkpJwk,
  ReallyMeEcJwk,
  ReallyMeJwk as ReallyMeJsonWebKey,
  ReallyMeJwkAlgorithm,
  ReallyMeJwkKey,
  ReallyMeJwks,
  ReallyMeJwksKeySet,
  ReallyMeOkpJwk,
} from "./jwk.js";
export {
  ML_KEM_1024_CIPHERTEXT_LENGTH,
  ML_KEM_1024_PUBLIC_KEY_LENGTH,
  ML_KEM_512_CIPHERTEXT_LENGTH,
  ML_KEM_512_PUBLIC_KEY_LENGTH,
  ML_KEM_768_CIPHERTEXT_LENGTH,
  ML_KEM_768_PUBLIC_KEY_LENGTH,
  ML_KEM_ENCAPSULATION_RANDOMNESS_LENGTH,
  ML_KEM_SECRET_KEY_LENGTH,
  ML_KEM_SHARED_SECRET_LENGTH,
  ReallyMeMlKem,
} from "./mlKem.js";
export type { ReallyMeMlKemEncapsulation, ReallyMeMlKemKeyPair } from "./mlKem.js";
export {
  ML_DSA_44_PUBLIC_KEY_LENGTH,
  ML_DSA_44_SIGNATURE_LENGTH,
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  ML_DSA_87_PUBLIC_KEY_LENGTH,
  ML_DSA_87_SIGNATURE_LENGTH,
  ML_DSA_SECRET_KEY_LENGTH,
  ReallyMeMlDsa,
} from "./mlDsa.js";
export type { ReallyMeMlDsaKeyPair } from "./mlDsa.js";
export {
  ReallyMeSlhDsa,
  SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH,
  SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH,
  SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH,
  SLH_DSA_SHA2_128S_SIGNATURE_LENGTH,
} from "./slhDsa.js";
export type { ReallyMeSlhDsaKeyPair } from "./slhDsa.js";
export { compiledProviders, REALLYME_CRYPTO_PROVIDERS } from "./providerCatalog.js";
export type { ReallyMeCryptoProvider } from "./providerCatalog.js";
export { createReallyMeCrypto, ReallyMeCrypto } from "./cryptoFacade.js";
export type {
  ReallyMeCryptoFacade,
  ReallyMeCryptoProviders,
  ReallyMeHpkeSealedMessage,
  ReallyMeKeyAgreementKeyPair,
  ReallyMeKemEncapsulation,
  ReallyMeKemKeyPair,
  ReallyMeSignatureKeyPair,
} from "./cryptoFacade.js";
export { ReallyMeDigest } from "./digest.js";
export {
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SECRET_KEY_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  ReallyMeEd25519,
} from "./ed25519.js";
export {
  HKDF_MAX_INPUT_LENGTH,
  HKDF_MAX_OUTPUT_LENGTH,
  HKDF_MIN_INPUT_KEY_MATERIAL_LENGTH,
  HKDF_MIN_OUTPUT_LENGTH,
  ReallyMeHkdf,
} from "./hkdf.js";
export {
  JWA_CONCAT_KDF_MAX_INFO_LENGTH,
  JWA_CONCAT_KDF_MAX_OUTPUT_LENGTH,
  JWA_CONCAT_KDF_MAX_SHARED_SECRET_LENGTH,
  JWA_CONCAT_KDF_MIN_OUTPUT_LENGTH,
  JWA_CONCAT_KDF_SHA256_DIGEST_LENGTH,
  ReallyMeJwaConcatKdf,
} from "./jwaConcatKdf.js";
export { bestEffortClear } from "./memory.js";
export {
  HMAC_MAX_KEY_LENGTH,
  HMAC_SHA256_TAG_LENGTH,
  HMAC_SHA512_TAG_LENGTH,
  ReallyMeHmac,
} from "./hmac.js";
export {
  P256_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH,
  P256_ECDH_SECRET_KEY_LENGTH,
  P256_ECDH_SHARED_SECRET_LENGTH,
  ReallyMeP256Ecdh,
} from "./p256Ecdh.js";
export {
  P256_ECDSA_COMPACT_SIGNATURE_LENGTH,
  P256_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH,
  P256_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P256_ECDSA_SECRET_KEY_LENGTH,
  ReallyMeP256Ecdsa,
} from "./p256Ecdsa.js";
export {
  P384_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH,
  P384_ECDH_SECRET_KEY_LENGTH,
  P384_ECDH_SHARED_SECRET_LENGTH,
  ReallyMeP384Ecdh,
} from "./p384Ecdh.js";
export {
  P384_ECDSA_COMPACT_SIGNATURE_LENGTH,
  P384_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH,
  P384_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P384_ECDSA_SECRET_KEY_LENGTH,
  ReallyMeP384Ecdsa,
} from "./p384Ecdsa.js";
export {
  P521_ECDH_COMPRESSED_PUBLIC_KEY_LENGTH,
  P521_ECDH_SECRET_KEY_LENGTH,
  P521_ECDH_SHARED_SECRET_LENGTH,
  ReallyMeP521Ecdh,
} from "./p521Ecdh.js";
export {
  P521_ECDSA_COMPACT_SIGNATURE_LENGTH,
  P521_ECDSA_COMPRESSED_PUBLIC_KEY_LENGTH,
  P521_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P521_ECDSA_SECRET_KEY_LENGTH,
  ReallyMeP521Ecdsa,
} from "./p521Ecdsa.js";
export {
  PBKDF2_MAX_INPUT_LENGTH,
  PBKDF2_MAX_OUTPUT_LENGTH,
  PBKDF2_MIN_INPUT_LENGTH,
  PBKDF2_MIN_ITERATIONS,
  PBKDF2_MIN_OUTPUT_LENGTH,
  PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA256,
  PBKDF2_RECOMMENDED_MIN_ITERATIONS_SHA512,
  ReallyMePbkdf2,
} from "./pbkdf2.js";
export {
  ReallyMeSecp256k1,
  SECP256K1_COMPRESSED_PUBLIC_KEY_LENGTH,
  SECP256K1_SECRET_KEY_LENGTH,
  SECP256K1_SIGNATURE_LENGTH,
} from "./secp256k1.js";
export {
  ReallyMeRsa,
  RSA_PUBLIC_KEY_DER_MAX_LENGTH,
  RSA_SIGNATURE_MAX_LENGTH,
} from "./rsa.js";
export type { ReallyMeRsaPublicKeyDerEncoding } from "./rsa.js";
export {
  ReallyMeX25519,
  X25519_PUBLIC_KEY_LENGTH,
  X25519_SECRET_KEY_LENGTH,
  X25519_SHARED_SECRET_LENGTH,
} from "./x25519.js";
export { createReallyMeWasmProvider, installReallyMeWasmProvider } from "./wasmProvider.js";
export type { ReallyMeWasmProvider } from "./wasmProvider.js";
export {
  ReallyMeXWing,
  X_WING_1024_CIPHERTEXT_LENGTH,
  X_WING_1024_PUBLIC_KEY_LENGTH,
  X_WING_768_CIPHERTEXT_LENGTH,
  X_WING_768_PUBLIC_KEY_LENGTH,
  X_WING_ENCAPSULATION_SEED_LENGTH,
  X_WING_SECRET_KEY_LENGTH,
  X_WING_SHARED_SECRET_LENGTH,
} from "./xWing.js";
export type { ReallyMeXWingEncapsulation, ReallyMeXWingKeyPair } from "./xWing.js";
