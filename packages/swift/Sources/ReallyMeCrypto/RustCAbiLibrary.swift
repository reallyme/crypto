// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#if canImport(Darwin)
import Darwin
#endif
import Foundation

#if REALLYME_CRYPTO_LINKED_FFI
private typealias LinkedAeadFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
) -> Int32
private typealias LinkedArgon2idFunction = @convention(c) (
    UInt32,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedGenerateKeyPairFunction = @convention(c) (
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedSignFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedVerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int
) -> Int32
private typealias LinkedEcdsaSignFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt>?
) -> Int32
private typealias LinkedBip340SignFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedBip340SchnorrDerivePublicKeyFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedAesKwFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
) -> Int32
private typealias LinkedHpkeSealFunction = @convention(c) (
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
private typealias LinkedHpkeOpenFunction = @convention(c) (
    UInt32,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
) -> Int32
private typealias LinkedRsaPkcs1v15VerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UInt32,
    UInt32,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int
) -> Int32
private typealias LinkedRsaPssVerifyFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UInt32,
    UInt32,
    UInt32,
    Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int
) -> Int32
private typealias LinkedSlhDsaDeriveKeyPairFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedKemEncapsulateDerandFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedKemEncapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32

@_silgen_name("rm_crypto_aes192_gcm_encrypt")
private func rmCryptoAes192GcmEncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes192_gcm_decrypt")
private func rmCryptoAes192GcmDecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes256_gcm_siv_encrypt")
private func rmCryptoAes256GcmSivEncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes256_gcm_siv_decrypt")
private func rmCryptoAes256GcmSivDecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_xchacha20_poly1305_encrypt")
private func rmCryptoXChaCha20Poly1305EncryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_xchacha20_poly1305_decrypt")
private func rmCryptoXChaCha20Poly1305DecryptLinked(
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int>?
) -> Int32

@_silgen_name("rm_crypto_argon2id_derive_key")
private func rmCryptoArgon2idDeriveKeyLinked(
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_ed25519_generate_keypair")
private func rmCryptoEd25519GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_ed25519_generate_keypair_from_seed")
private func rmCryptoEd25519GenerateKeypairFromSeedLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_ed25519_sign")
private func rmCryptoEd25519SignLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_ed25519_verify")
private func rmCryptoEd25519VerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_p256_generate_keypair")
private func rmCryptoP256GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p256_generate_keypair_from_secret_key")
private func rmCryptoP256GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p256_sign_der_prehash")
private func rmCryptoP256SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
) -> Int32
@_silgen_name("rm_crypto_p256_verify_der_prehash")
private func rmCryptoP256VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_p384_generate_keypair")
private func rmCryptoP384GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p384_generate_keypair_from_secret_key")
private func rmCryptoP384GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p384_sign_der_prehash")
private func rmCryptoP384SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
) -> Int32
@_silgen_name("rm_crypto_p384_verify_der_prehash")
private func rmCryptoP384VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_p521_generate_keypair")
private func rmCryptoP521GenerateKeypairLinked(
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p521_generate_keypair_from_secret_key")
private func rmCryptoP521GenerateKeypairFromSecretKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_p521_sign_der_prehash")
private func rmCryptoP521SignDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt>?
) -> Int32
@_silgen_name("rm_crypto_p521_verify_der_prehash")
private func rmCryptoP521VerifyDerPrehashLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_bip340_schnorr_derive_public_key")
private func rmCryptoBip340SchnorrDerivePublicKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_bip340_schnorr_sign")
private func rmCryptoBip340SchnorrSignLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_bip340_schnorr_verify")
private func rmCryptoBip340SchnorrVerifyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_aes256_kw_wrap_key")
private func rmCryptoAes256KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes256_kw_unwrap_key")
private func rmCryptoAes256KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32

@_silgen_name("rm_crypto_hpke_seal_base")
private func rmCryptoHpkeSealBaseLinked(
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
private func rmCryptoHpkeOpenBaseLinked(
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
private func rmCryptoRsaVerifyPkcs1v15Linked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UInt32,
    _: UInt32,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_rsa_verify_pss")
private func rmCryptoRsaVerifyPssLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UInt32,
    _: UInt32,
    _: UInt32,
    _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int
) -> Int32

@_silgen_name("rm_crypto_ml_dsa_44_generate_keypair")
private func rmCryptoMlDsa44GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_44_generate_keypair_from_seed")
private func rmCryptoMlDsa44GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_44_sign")
private func rmCryptoMlDsa44SignLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_44_verify")
private func rmCryptoMlDsa44VerifyLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_65_generate_keypair")
private func rmCryptoMlDsa65GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_65_generate_keypair_from_seed")
private func rmCryptoMlDsa65GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_65_sign")
private func rmCryptoMlDsa65SignLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_65_verify")
private func rmCryptoMlDsa65VerifyLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_87_generate_keypair")
private func rmCryptoMlDsa87GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_87_generate_keypair_from_seed")
private func rmCryptoMlDsa87GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_87_sign")
private func rmCryptoMlDsa87SignLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_dsa_87_verify")
private func rmCryptoMlDsa87VerifyLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int) -> Int32

@_silgen_name("rm_crypto_slh_dsa_sha2_128s_generate_keypair")
private func rmCryptoSlhDsaSha2128sGenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_slh_dsa_sha2_128s_derive_keypair")
private func rmCryptoSlhDsaSha2128sDeriveKeypairLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int
) -> Int32
@_silgen_name("rm_crypto_slh_dsa_sha2_128s_sign")
private func rmCryptoSlhDsaSha2128sSignLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_slh_dsa_sha2_128s_verify")
private func rmCryptoSlhDsaSha2128sVerifyLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int) -> Int32

@_silgen_name("rm_crypto_ml_kem_512_generate_keypair")
private func rmCryptoMlKem512GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_512_generate_keypair_from_seed")
private func rmCryptoMlKem512GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_512_encapsulate")
private func rmCryptoMlKem512EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_512_encapsulate_derand")
private func rmCryptoMlKem512EncapsulateDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_512_decapsulate")
private func rmCryptoMlKem512DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_generate_keypair")
private func rmCryptoMlKem768GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_generate_keypair_from_seed")
private func rmCryptoMlKem768GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_encapsulate")
private func rmCryptoMlKem768EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_encapsulate_derand")
private func rmCryptoMlKem768EncapsulateDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_decapsulate")
private func rmCryptoMlKem768DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_generate_keypair")
private func rmCryptoMlKem1024GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_generate_keypair_from_seed")
private func rmCryptoMlKem1024GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_encapsulate")
private func rmCryptoMlKem1024EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_encapsulate_derand")
private func rmCryptoMlKem1024EncapsulateDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_decapsulate")
private func rmCryptoMlKem1024DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32

@_silgen_name("rm_crypto_x_wing_768_generate_keypair")
private func rmCryptoXWing768GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_generate_keypair_derand")
private func rmCryptoXWing768GenerateKeypairDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_encapsulate")
private func rmCryptoXWing768EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_encapsulate_derand")
private func rmCryptoXWing768EncapsulateDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_decapsulate")
private func rmCryptoXWing768DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_1024_generate_keypair")
private func rmCryptoXWing1024GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_1024_generate_keypair_derand")
private func rmCryptoXWing1024GenerateKeypairDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_1024_encapsulate")
private func rmCryptoXWing1024EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_1024_encapsulate_derand")
private func rmCryptoXWing1024EncapsulateDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_1024_decapsulate")
private func rmCryptoXWing1024DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
#endif

/// Runtime handle for the ReallyMe Rust C ABI provider.
///
/// Release SwiftPM packages link the bundled `ReallyMeCryptoFFI` binary target
/// and resolve symbols directly. The path-based initializer is retained for
/// local Rust development and tests against freshly built dynamic libraries.
public final class ReallyMeRustCAbiLibrary: @unchecked Sendable {
    private let handle: UnsafeMutableRawPointer?
    private let usesLinkedSymbols: Bool

    public static var isBundledProviderAvailable: Bool {
        #if REALLYME_CRYPTO_LINKED_FFI
        return true
        #else
        return false
        #endif
    }

    public static func bundledProvider() throws -> ReallyMeRustCAbiLibrary {
        #if REALLYME_CRYPTO_LINKED_FFI
        return ReallyMeRustCAbiLibrary(linkedSymbols: ())
        #else
        throw ReallyMeCryptoError.providerFailure
        #endif
    }

    #if REALLYME_CRYPTO_LINKED_FFI
    private init(linkedSymbols _: Void) {
        handle = nil
        usesLinkedSymbols = true
    }
    #endif

    public init(path: String) throws {
        #if canImport(Darwin)
        guard FileManager.default.fileExists(atPath: path) else {
            throw ReallyMeCryptoError.dynamicLibraryNotFound
        }
        guard let loadedHandle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            throw ReallyMeCryptoError.dynamicLibraryLoadFailed
        }
        handle = loadedHandle
        usesLinkedSymbols = false
        #else
        _ = path
        throw ReallyMeCryptoError.unsupportedPlatform
        #endif
    }

    deinit {
        #if canImport(Darwin)
        if let handle {
            dlclose(handle)
        }
        #endif
    }

    public func loadFunction<Function>(_ symbol: StaticString, as type: Function.Type) throws -> Function {
        #if REALLYME_CRYPTO_LINKED_FFI
        if usesLinkedSymbols {
            return try loadLinkedFunction(symbol, as: type)
        }
        #endif
        #if canImport(Darwin)
        guard let handle else {
            throw ReallyMeCryptoError.providerFailure
        }
        guard let rawSymbol = dlsym(handle, symbol.description) else {
            throw ReallyMeCryptoError.symbolNotFound
        }
        return unsafeBitCast(rawSymbol, to: Function.self)
        #else
        _ = symbol
        _ = type
        throw ReallyMeCryptoError.unsupportedPlatform
        #endif
    }

    #if REALLYME_CRYPTO_LINKED_FFI
    private func linked<Concrete, Function>(_ function: Concrete, as _: Function.Type) -> Function {
        unsafeBitCast(function, to: Function.self)
    }

    private func loadLinkedFunction<Function>(_ symbol: StaticString, as type: Function.Type) throws -> Function {
        switch symbol.description {
        case "rm_crypto_aes192_gcm_encrypt": return linked(rmCryptoAes192GcmEncryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_aes192_gcm_decrypt": return linked(rmCryptoAes192GcmDecryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_aes256_gcm_siv_encrypt": return linked(rmCryptoAes256GcmSivEncryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_aes256_gcm_siv_decrypt": return linked(rmCryptoAes256GcmSivDecryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_xchacha20_poly1305_encrypt": return linked(rmCryptoXChaCha20Poly1305EncryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_xchacha20_poly1305_decrypt": return linked(rmCryptoXChaCha20Poly1305DecryptLinked as LinkedAeadFunction, as: type)
        case "rm_crypto_argon2id_derive_key": return linked(rmCryptoArgon2idDeriveKeyLinked as LinkedArgon2idFunction, as: type)
        case "rm_crypto_ed25519_generate_keypair": return linked(rmCryptoEd25519GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ed25519_generate_keypair_from_seed": return linked(rmCryptoEd25519GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ed25519_sign": return linked(rmCryptoEd25519SignLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ed25519_verify": return linked(rmCryptoEd25519VerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_p256_generate_keypair": return linked(rmCryptoP256GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_p256_generate_keypair_from_secret_key": return linked(rmCryptoP256GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_p256_sign_der_prehash": return linked(rmCryptoP256SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case "rm_crypto_p256_verify_der_prehash": return linked(rmCryptoP256VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_p384_generate_keypair": return linked(rmCryptoP384GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_p384_generate_keypair_from_secret_key": return linked(rmCryptoP384GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_p384_sign_der_prehash": return linked(rmCryptoP384SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case "rm_crypto_p384_verify_der_prehash": return linked(rmCryptoP384VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_p521_generate_keypair": return linked(rmCryptoP521GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_p521_generate_keypair_from_secret_key": return linked(rmCryptoP521GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_p521_sign_der_prehash": return linked(rmCryptoP521SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case "rm_crypto_p521_verify_der_prehash": return linked(rmCryptoP521VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_bip340_schnorr_derive_public_key": return linked(rmCryptoBip340SchnorrDerivePublicKeyLinked as LinkedBip340SchnorrDerivePublicKeyFunction, as: type)
        case "rm_crypto_bip340_schnorr_sign": return linked(rmCryptoBip340SchnorrSignLinked as LinkedBip340SignFunction, as: type)
        case "rm_crypto_bip340_schnorr_verify": return linked(rmCryptoBip340SchnorrVerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_aes256_kw_wrap_key": return linked(rmCryptoAes256KwWrapKeyLinked as LinkedAesKwFunction, as: type)
        case "rm_crypto_aes256_kw_unwrap_key": return linked(rmCryptoAes256KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
        case "rm_crypto_hpke_seal_base": return linked(rmCryptoHpkeSealBaseLinked as LinkedHpkeSealFunction, as: type)
        case "rm_crypto_hpke_open_base": return linked(rmCryptoHpkeOpenBaseLinked as LinkedHpkeOpenFunction, as: type)
        case "rm_crypto_rsa_verify_pkcs1v15": return linked(rmCryptoRsaVerifyPkcs1v15Linked as LinkedRsaPkcs1v15VerifyFunction, as: type)
        case "rm_crypto_rsa_verify_pss": return linked(rmCryptoRsaVerifyPssLinked as LinkedRsaPssVerifyFunction, as: type)
        case "rm_crypto_ml_dsa_44_generate_keypair": return linked(rmCryptoMlDsa44GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_44_generate_keypair_from_seed": return linked(rmCryptoMlDsa44GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_44_sign": return linked(rmCryptoMlDsa44SignLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ml_dsa_44_verify": return linked(rmCryptoMlDsa44VerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_ml_dsa_65_generate_keypair": return linked(rmCryptoMlDsa65GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_65_generate_keypair_from_seed": return linked(rmCryptoMlDsa65GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_65_sign": return linked(rmCryptoMlDsa65SignLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ml_dsa_65_verify": return linked(rmCryptoMlDsa65VerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_ml_dsa_87_generate_keypair": return linked(rmCryptoMlDsa87GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_87_generate_keypair_from_seed": return linked(rmCryptoMlDsa87GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_dsa_87_sign": return linked(rmCryptoMlDsa87SignLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ml_dsa_87_verify": return linked(rmCryptoMlDsa87VerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_slh_dsa_sha2_128s_generate_keypair": return linked(rmCryptoSlhDsaSha2128sGenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_slh_dsa_sha2_128s_derive_keypair": return linked(rmCryptoSlhDsaSha2128sDeriveKeypairLinked as LinkedSlhDsaDeriveKeyPairFunction, as: type)
        case "rm_crypto_slh_dsa_sha2_128s_sign": return linked(rmCryptoSlhDsaSha2128sSignLinked as LinkedSignFunction, as: type)
        case "rm_crypto_slh_dsa_sha2_128s_verify": return linked(rmCryptoSlhDsaSha2128sVerifyLinked as LinkedVerifyFunction, as: type)
        case "rm_crypto_ml_kem_512_generate_keypair": return linked(rmCryptoMlKem512GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_512_generate_keypair_from_seed": return linked(rmCryptoMlKem512GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_512_encapsulate": return linked(rmCryptoMlKem512EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case "rm_crypto_ml_kem_512_encapsulate_derand": return linked(rmCryptoMlKem512EncapsulateDerandLinked as LinkedKemEncapsulateDerandFunction, as: type)
        case "rm_crypto_ml_kem_512_decapsulate": return linked(rmCryptoMlKem512DecapsulateLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ml_kem_768_generate_keypair": return linked(rmCryptoMlKem768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_768_generate_keypair_from_seed": return linked(rmCryptoMlKem768GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_768_encapsulate": return linked(rmCryptoMlKem768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case "rm_crypto_ml_kem_768_encapsulate_derand": return linked(rmCryptoMlKem768EncapsulateDerandLinked as LinkedKemEncapsulateDerandFunction, as: type)
        case "rm_crypto_ml_kem_768_decapsulate": return linked(rmCryptoMlKem768DecapsulateLinked as LinkedSignFunction, as: type)
        case "rm_crypto_ml_kem_1024_generate_keypair": return linked(rmCryptoMlKem1024GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_1024_generate_keypair_from_seed": return linked(rmCryptoMlKem1024GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case "rm_crypto_ml_kem_1024_encapsulate": return linked(rmCryptoMlKem1024EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case "rm_crypto_ml_kem_1024_encapsulate_derand": return linked(rmCryptoMlKem1024EncapsulateDerandLinked as LinkedKemEncapsulateDerandFunction, as: type)
        case "rm_crypto_ml_kem_1024_decapsulate": return linked(rmCryptoMlKem1024DecapsulateLinked as LinkedSignFunction, as: type)
        case "rm_crypto_x_wing_768_generate_keypair": return linked(rmCryptoXWing768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_x_wing_768_generate_keypair_derand": return linked(rmCryptoXWing768GenerateKeypairDerandLinked as LinkedBip340SchnorrDerivePublicKeyFunction, as: type)
        case "rm_crypto_x_wing_768_encapsulate": return linked(rmCryptoXWing768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case "rm_crypto_x_wing_768_encapsulate_derand": return linked(rmCryptoXWing768EncapsulateDerandLinked as LinkedKemEncapsulateDerandFunction, as: type)
        case "rm_crypto_x_wing_768_decapsulate": return linked(rmCryptoXWing768DecapsulateLinked as LinkedSignFunction, as: type)
        case "rm_crypto_x_wing_1024_generate_keypair": return linked(rmCryptoXWing1024GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case "rm_crypto_x_wing_1024_generate_keypair_derand": return linked(rmCryptoXWing1024GenerateKeypairDerandLinked as LinkedBip340SchnorrDerivePublicKeyFunction, as: type)
        case "rm_crypto_x_wing_1024_encapsulate": return linked(rmCryptoXWing1024EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case "rm_crypto_x_wing_1024_encapsulate_derand": return linked(rmCryptoXWing1024EncapsulateDerandLinked as LinkedKemEncapsulateDerandFunction, as: type)
        case "rm_crypto_x_wing_1024_decapsulate": return linked(rmCryptoXWing1024DecapsulateLinked as LinkedSignFunction, as: type)
        default:
            throw ReallyMeCryptoError.symbolNotFound
        }
    }
    #endif
}
