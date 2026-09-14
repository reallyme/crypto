// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if REALLYME_CRYPTO_LINKED_FFI
  typealias LinkedAeadFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?
    ) -> Int32
  typealias LinkedArgon2idFunction =
    @convention(c) (
      UInt32,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedKmac256Function =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedGenerateKeyPairFunction =
    @convention(c) (
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedDeriveKeyPairFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedSignFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedVerifyFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedEcdsaSignFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt>?
    ) -> Int32
  typealias LinkedBip340SignFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedBip340SchnorrDerivePublicKeyFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedXWingDeriveKeyPairFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedAesKwFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?
    ) -> Int32
  typealias LinkedHpkeSealFunction =
    @convention(c) (
      UInt32,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?
    ) -> Int32
  typealias LinkedHpkeOpenFunction =
    @convention(c) (
      UInt32,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?
    ) -> Int32
  typealias LinkedRsaPkcs1v15VerifyFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UInt32,
      UInt32,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedRsaPssVerifyFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UInt32,
      UInt32,
      UInt32,
      Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedSlhDsaDeriveKeyPairFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedKemEncapsulateFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int
    ) -> Int32
  typealias LinkedOperationResponseFunction =
    @convention(c) (
      UnsafePointer<UInt8>?, Int,
      UnsafeMutablePointer<UInt8>?, Int,
      UnsafeMutablePointer<Int>?
    ) -> Int32

  enum LinkedRustCAbiSymbol: String, CaseIterable {
    case processOperationResponse = "rm_crypto_process_operation_response"
    case processOperationResponseJson = "rm_crypto_process_operation_response_json"
    case aes192GcmEncrypt = "rm_crypto_aes192_gcm_encrypt"
    case aes192GcmDecrypt = "rm_crypto_aes192_gcm_decrypt"
    case aes256GcmSivEncrypt = "rm_crypto_aes256_gcm_siv_encrypt"
    case aes256GcmSivDecrypt = "rm_crypto_aes256_gcm_siv_decrypt"
    case xchacha20Poly1305Encrypt = "rm_crypto_xchacha20_poly1305_encrypt"
    case xchacha20Poly1305Decrypt = "rm_crypto_xchacha20_poly1305_decrypt"
    case argon2idDeriveKey = "rm_crypto_argon2id_derive_key"
    case kmac256Derive = "rm_crypto_kmac256_derive"
    case ed25519GenerateKeypair = "rm_crypto_ed25519_generate_keypair"
    case ed25519GenerateKeypairFromSeed = "rm_crypto_ed25519_generate_keypair_from_seed"
    case ed25519Sign = "rm_crypto_ed25519_sign"
    case ed25519Verify = "rm_crypto_ed25519_verify"
    case p256GenerateKeypair = "rm_crypto_p256_generate_keypair"
    case p256GenerateKeypairFromSecretKey = "rm_crypto_p256_generate_keypair_from_secret_key"
    case p256SignDerPrehash = "rm_crypto_p256_sign_der_prehash"
    case p256VerifyDerPrehash = "rm_crypto_p256_verify_der_prehash"
    case p384GenerateKeypair = "rm_crypto_p384_generate_keypair"
    case p384GenerateKeypairFromSecretKey = "rm_crypto_p384_generate_keypair_from_secret_key"
    case p384SignDerPrehash = "rm_crypto_p384_sign_der_prehash"
    case p384VerifyDerPrehash = "rm_crypto_p384_verify_der_prehash"
    case p521GenerateKeypair = "rm_crypto_p521_generate_keypair"
    case p521GenerateKeypairFromSecretKey = "rm_crypto_p521_generate_keypair_from_secret_key"
    case p521SignDerPrehash = "rm_crypto_p521_sign_der_prehash"
    case p521VerifyDerPrehash = "rm_crypto_p521_verify_der_prehash"
    case bip340SchnorrDerivePublicKey = "rm_crypto_bip340_schnorr_derive_public_key"
    case bip340SchnorrSign = "rm_crypto_bip340_schnorr_sign"
    case bip340SchnorrVerify = "rm_crypto_bip340_schnorr_verify"
    case aes128KwWrapKey = "rm_crypto_aes128_kw_wrap_key"
    case aes128KwUnwrapKey = "rm_crypto_aes128_kw_unwrap_key"
    case aes192KwWrapKey = "rm_crypto_aes192_kw_wrap_key"
    case aes192KwUnwrapKey = "rm_crypto_aes192_kw_unwrap_key"
    case aes256KwWrapKey = "rm_crypto_aes256_kw_wrap_key"
    case aes256KwUnwrapKey = "rm_crypto_aes256_kw_unwrap_key"
    case hpkeSealBase = "rm_crypto_hpke_seal_base"
    case hpkeOpenBase = "rm_crypto_hpke_open_base"
    case rsaVerifyPkcs1v15 = "rm_crypto_rsa_verify_pkcs1v15"
    case rsaVerifyPss = "rm_crypto_rsa_verify_pss"
    case mlDsa44GenerateKeypair = "rm_crypto_ml_dsa_44_generate_keypair"
    case mlDsa44GenerateKeypairFromSeed = "rm_crypto_ml_dsa_44_generate_keypair_from_seed"
    case mlDsa44Sign = "rm_crypto_ml_dsa_44_sign"
    case mlDsa44Verify = "rm_crypto_ml_dsa_44_verify"
    case mlDsa65GenerateKeypair = "rm_crypto_ml_dsa_65_generate_keypair"
    case mlDsa65GenerateKeypairFromSeed = "rm_crypto_ml_dsa_65_generate_keypair_from_seed"
    case mlDsa65Sign = "rm_crypto_ml_dsa_65_sign"
    case mlDsa65Verify = "rm_crypto_ml_dsa_65_verify"
    case mlDsa87GenerateKeypair = "rm_crypto_ml_dsa_87_generate_keypair"
    case mlDsa87GenerateKeypairFromSeed = "rm_crypto_ml_dsa_87_generate_keypair_from_seed"
    case mlDsa87Sign = "rm_crypto_ml_dsa_87_sign"
    case mlDsa87Verify = "rm_crypto_ml_dsa_87_verify"
    case slhDsaSha2128sGenerateKeypair = "rm_crypto_slh_dsa_sha2_128s_generate_keypair"
    case slhDsaSha2128sDeriveKeypair = "rm_crypto_slh_dsa_sha2_128s_derive_keypair"
    case slhDsaSha2128sSign = "rm_crypto_slh_dsa_sha2_128s_sign"
    case slhDsaSha2128sVerify = "rm_crypto_slh_dsa_sha2_128s_verify"
    case mlKem512GenerateKeypair = "rm_crypto_ml_kem_512_generate_keypair"
    case mlKem512GenerateKeypairFromSeed = "rm_crypto_ml_kem_512_generate_keypair_from_seed"
    case mlKem512Encapsulate = "rm_crypto_ml_kem_512_encapsulate"
    case mlKem512Decapsulate = "rm_crypto_ml_kem_512_decapsulate"
    case mlKem768GenerateKeypair = "rm_crypto_ml_kem_768_generate_keypair"
    case mlKem768GenerateKeypairFromSeed = "rm_crypto_ml_kem_768_generate_keypair_from_seed"
    case mlKem768Encapsulate = "rm_crypto_ml_kem_768_encapsulate"
    case mlKem768Decapsulate = "rm_crypto_ml_kem_768_decapsulate"
    case mlKem1024GenerateKeypair = "rm_crypto_ml_kem_1024_generate_keypair"
    case mlKem1024GenerateKeypairFromSeed = "rm_crypto_ml_kem_1024_generate_keypair_from_seed"
    case mlKem1024Encapsulate = "rm_crypto_ml_kem_1024_encapsulate"
    case mlKem1024Decapsulate = "rm_crypto_ml_kem_1024_decapsulate"
    case xWing768GenerateKeypair = "rm_crypto_x_wing_768_generate_keypair"
    case xWing768GenerateKeypairDerand = "rm_crypto_x_wing_768_generate_keypair_derand"
    case xWing768Encapsulate = "rm_crypto_x_wing_768_encapsulate"
    case xWing768Decapsulate = "rm_crypto_x_wing_768_decapsulate"

    init?(_ symbol: StaticString) {
      self.init(rawValue: symbol.description)
    }
  }
#endif
