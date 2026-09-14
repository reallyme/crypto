// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if REALLYME_CRYPTO_LINKED_FFI
  @_silgen_name("rm_crypto_hpke_seal_base")
  func rmCryptoHpkeSealBaseLinked(
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_hpke_open_base")
  func rmCryptoHpkeOpenBaseLinked(
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32

  @_silgen_name("rm_crypto_rsa_verify_pkcs1v15")
  func rmCryptoRsaVerifyPkcs1v15Linked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UInt32,
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_rsa_verify_pss")
  func rmCryptoRsaVerifyPssLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UInt32,
    _: UInt32,
    _: UInt32,
    _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_ml_dsa_44_generate_keypair")
  func rmCryptoMlDsa44GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_44_generate_keypair_from_seed")
  func rmCryptoMlDsa44GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_44_sign")
  func rmCryptoMlDsa44SignLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_44_verify")
  func rmCryptoMlDsa44VerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?,
    _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_65_generate_keypair")
  func rmCryptoMlDsa65GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_65_generate_keypair_from_seed")
  func rmCryptoMlDsa65GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_65_sign")
  func rmCryptoMlDsa65SignLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_65_verify")
  func rmCryptoMlDsa65VerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?,
    _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_87_generate_keypair")
  func rmCryptoMlDsa87GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_87_generate_keypair_from_seed")
  func rmCryptoMlDsa87GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_87_sign")
  func rmCryptoMlDsa87SignLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_dsa_87_verify")
  func rmCryptoMlDsa87VerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?,
    _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_slh_dsa_sha2_128s_generate_keypair")
  func rmCryptoSlhDsaSha2128sGenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_slh_dsa_sha2_128s_derive_keypair")
  func rmCryptoSlhDsaSha2128sDeriveKeypairLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_slh_dsa_sha2_128s_sign")
  func rmCryptoSlhDsaSha2128sSignLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_slh_dsa_sha2_128s_verify")
  func rmCryptoSlhDsaSha2128sVerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?,
    _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_ml_kem_512_generate_keypair")
  func rmCryptoMlKem512GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_512_generate_keypair_from_seed")
  func rmCryptoMlKem512GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_512_encapsulate")
  func rmCryptoMlKem512EncapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_512_decapsulate")
  func rmCryptoMlKem512DecapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_768_generate_keypair")
  func rmCryptoMlKem768GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_768_generate_keypair_from_seed")
  func rmCryptoMlKem768GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_768_encapsulate")
  func rmCryptoMlKem768EncapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_768_decapsulate")
  func rmCryptoMlKem768DecapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_1024_generate_keypair")
  func rmCryptoMlKem1024GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_1024_generate_keypair_from_seed")
  func rmCryptoMlKem1024GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_1024_encapsulate")
  func rmCryptoMlKem1024EncapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ml_kem_1024_decapsulate")
  func rmCryptoMlKem1024DecapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_x_wing_768_generate_keypair")
  func rmCryptoXWing768GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_x_wing_768_generate_keypair_derand")
  func rmCryptoXWing768GenerateKeypairDerandLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_x_wing_768_encapsulate")
  func rmCryptoXWing768EncapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_x_wing_768_decapsulate")
  func rmCryptoXWing768DecapsulateLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_process_operation_response")
  func rmCryptoProcessOperationResponseLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32

  @_silgen_name("rm_crypto_process_operation_response_json")
  func rmCryptoProcessOperationResponseJsonLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
#endif
