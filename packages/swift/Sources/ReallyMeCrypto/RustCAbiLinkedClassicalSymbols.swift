// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

#if REALLYME_CRYPTO_LINKED_FFI
  @_silgen_name("rm_crypto_aes192_gcm_encrypt")
  func rmCryptoAes192GcmEncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes192_gcm_decrypt")
  func rmCryptoAes192GcmDecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes256_gcm_siv_encrypt")
  func rmCryptoAes256GcmSivEncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes256_gcm_siv_decrypt")
  func rmCryptoAes256GcmSivDecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_xchacha20_poly1305_encrypt")
  func rmCryptoXChaCha20Poly1305EncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_xchacha20_poly1305_decrypt")
  func rmCryptoXChaCha20Poly1305DecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
  ) -> Int32

  @_silgen_name("rm_crypto_argon2id_derive_key")
  func rmCryptoArgon2idDeriveKeyLinked(
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_kmac256_derive")
  func rmCryptoKmac256DeriveLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_ed25519_generate_keypair")
  func rmCryptoEd25519GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ed25519_generate_keypair_from_seed")
  func rmCryptoEd25519GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ed25519_sign")
  func rmCryptoEd25519SignLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_ed25519_verify")
  func rmCryptoEd25519VerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_p256_generate_keypair")
  func rmCryptoP256GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p256_generate_keypair_from_secret_key")
  func rmCryptoP256GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p256_sign_der_prehash")
  func rmCryptoP256SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
  ) -> Int32
  @_silgen_name("rm_crypto_p256_verify_der_prehash")
  func rmCryptoP256VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_p384_generate_keypair")
  func rmCryptoP384GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p384_generate_keypair_from_secret_key")
  func rmCryptoP384GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p384_sign_der_prehash")
  func rmCryptoP384SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
  ) -> Int32
  @_silgen_name("rm_crypto_p384_verify_der_prehash")
  func rmCryptoP384VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_p521_generate_keypair")
  func rmCryptoP521GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p521_generate_keypair_from_secret_key")
  func rmCryptoP521GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_p521_sign_der_prehash")
  func rmCryptoP521SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
  ) -> Int32
  @_silgen_name("rm_crypto_p521_verify_der_prehash")
  func rmCryptoP521VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_bip340_schnorr_derive_public_key")
  func rmCryptoBip340SchnorrDerivePublicKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_bip340_schnorr_sign")
  func rmCryptoBip340SchnorrSignLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
  ) -> Int32
  @_silgen_name("rm_crypto_bip340_schnorr_verify")
  func rmCryptoBip340SchnorrVerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
  ) -> Int32

  @_silgen_name("rm_crypto_aes128_kw_wrap_key")
  func rmCryptoAes128KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes128_kw_unwrap_key")
  func rmCryptoAes128KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes192_kw_wrap_key")
  func rmCryptoAes192KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes192_kw_unwrap_key")
  func rmCryptoAes192KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes256_kw_wrap_key")
  func rmCryptoAes256KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
  @_silgen_name("rm_crypto_aes256_kw_unwrap_key")
  func rmCryptoAes256KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
  ) -> Int32
#endif
