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
private typealias LinkedKmac256Function = @convention(c) (
    UnsafePointer<UInt8>?, Int,
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
private typealias LinkedXWingDeriveKeyPairFunction = @convention(c) (
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
private typealias LinkedKemEncapsulateFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int
) -> Int32
private typealias LinkedOperationResponseFunction = @convention(c) (
    UnsafePointer<UInt8>?, Int,
    UnsafeMutablePointer<UInt8>?, Int,
    UnsafeMutablePointer<Int>?
) -> Int32

private enum LinkedRustCAbiSymbol: String, CaseIterable {
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

@_silgen_name("rm_crypto_kmac256_derive")
private func rmCryptoKmac256DeriveLinked(
    _: UnsafePointer<UInt8>?, _: Int,
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

@_silgen_name("rm_crypto_aes128_kw_wrap_key")
private func rmCryptoAes128KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes128_kw_unwrap_key")
private func rmCryptoAes128KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes192_kw_wrap_key")
private func rmCryptoAes192KwWrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32
@_silgen_name("rm_crypto_aes192_kw_unwrap_key")
private func rmCryptoAes192KwUnwrapKeyLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
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
@_silgen_name("rm_crypto_ml_kem_512_decapsulate")
private func rmCryptoMlKem512DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_generate_keypair")
private func rmCryptoMlKem768GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_generate_keypair_from_seed")
private func rmCryptoMlKem768GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_encapsulate")
private func rmCryptoMlKem768EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_768_decapsulate")
private func rmCryptoMlKem768DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_generate_keypair")
private func rmCryptoMlKem1024GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_generate_keypair_from_seed")
private func rmCryptoMlKem1024GenerateKeypairFromSeedLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_encapsulate")
private func rmCryptoMlKem1024EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_ml_kem_1024_decapsulate")
private func rmCryptoMlKem1024DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32

@_silgen_name("rm_crypto_x_wing_768_generate_keypair")
private func rmCryptoXWing768GenerateKeypairLinked(_: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_generate_keypair_derand")
private func rmCryptoXWing768GenerateKeypairDerandLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_encapsulate")
private func rmCryptoXWing768EncapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32
@_silgen_name("rm_crypto_x_wing_768_decapsulate")
private func rmCryptoXWing768DecapsulateLinked(_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt8>?, _: Int) -> Int32

@_silgen_name("rm_crypto_process_operation_response")
private func rmCryptoProcessOperationResponseLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32

@_silgen_name("rm_crypto_process_operation_response_json")
private func rmCryptoProcessOperationResponseJsonLinked(
    _: UnsafePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<UInt8>?, _: Int,
    _: UnsafeMutablePointer<Int>?
) -> Int32
#endif

/// Runtime handle for the ReallyMe Rust C ABI provider.
///
/// Release SwiftPM packages link the bundled `ReallyMeCryptoFFI` binary target
/// and resolve symbols directly. The path-based initializer is retained for
/// local Rust development and tests against freshly built dynamic libraries;
/// it accepts only absolute paths so resolution never depends on a mutable
/// process working directory.
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
        guard (path as NSString).isAbsolutePath else {
            throw ReallyMeCryptoError.invalidInput
        }
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

    func loadFunction<Function>(_ symbol: StaticString, as type: Function.Type) throws -> Function {
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
    private func linked<Concrete, Function>(
        _ function: Concrete,
        as requestedType: Function.Type
    ) throws -> Function {
        // A symbol name and a generic caller-selected function type are not a
        // sufficient ABI contract. Reject mismatched metatypes before the one
        // unavoidable cast so an internal adapter cannot invoke undefined
        // behavior by pairing a valid symbol with the wrong signature.
        guard ObjectIdentifier(requestedType) == ObjectIdentifier(Concrete.self) else {
            throw ReallyMeCryptoError.providerFailure
        }
        return unsafeBitCast(function, to: Function.self)
    }

    private func loadLinkedFunction<Function>(_ symbol: StaticString, as type: Function.Type) throws -> Function {
        guard let linkedSymbol = LinkedRustCAbiSymbol(symbol) else {
            throw ReallyMeCryptoError.symbolNotFound
        }
        switch linkedSymbol {
        case .processOperationResponse: return try linked(rmCryptoProcessOperationResponseLinked as LinkedOperationResponseFunction, as: type)
        case .processOperationResponseJson: return try linked(rmCryptoProcessOperationResponseJsonLinked as LinkedOperationResponseFunction, as: type)
        case .aes192GcmEncrypt: return try linked(rmCryptoAes192GcmEncryptLinked as LinkedAeadFunction, as: type)
        case .aes192GcmDecrypt: return try linked(rmCryptoAes192GcmDecryptLinked as LinkedAeadFunction, as: type)
        case .aes256GcmSivEncrypt: return try linked(rmCryptoAes256GcmSivEncryptLinked as LinkedAeadFunction, as: type)
        case .aes256GcmSivDecrypt: return try linked(rmCryptoAes256GcmSivDecryptLinked as LinkedAeadFunction, as: type)
        case .xchacha20Poly1305Encrypt: return try linked(rmCryptoXChaCha20Poly1305EncryptLinked as LinkedAeadFunction, as: type)
        case .xchacha20Poly1305Decrypt: return try linked(rmCryptoXChaCha20Poly1305DecryptLinked as LinkedAeadFunction, as: type)
        case .argon2idDeriveKey: return try linked(rmCryptoArgon2idDeriveKeyLinked as LinkedArgon2idFunction, as: type)
        case .kmac256Derive: return try linked(rmCryptoKmac256DeriveLinked as LinkedKmac256Function, as: type)
        case .ed25519GenerateKeypair: return try linked(rmCryptoEd25519GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .ed25519GenerateKeypairFromSeed: return try linked(rmCryptoEd25519GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .ed25519Sign: return try linked(rmCryptoEd25519SignLinked as LinkedSignFunction, as: type)
        case .ed25519Verify: return try linked(rmCryptoEd25519VerifyLinked as LinkedVerifyFunction, as: type)
        case .p256GenerateKeypair: return try linked(rmCryptoP256GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .p256GenerateKeypairFromSecretKey: return try linked(rmCryptoP256GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case .p256SignDerPrehash: return try linked(rmCryptoP256SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case .p256VerifyDerPrehash: return try linked(rmCryptoP256VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case .p384GenerateKeypair: return try linked(rmCryptoP384GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .p384GenerateKeypairFromSecretKey: return try linked(rmCryptoP384GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case .p384SignDerPrehash: return try linked(rmCryptoP384SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case .p384VerifyDerPrehash: return try linked(rmCryptoP384VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case .p521GenerateKeypair: return try linked(rmCryptoP521GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .p521GenerateKeypairFromSecretKey: return try linked(rmCryptoP521GenerateKeypairFromSecretKeyLinked as LinkedDeriveKeyPairFunction, as: type)
        case .p521SignDerPrehash: return try linked(rmCryptoP521SignDerPrehashLinked as LinkedEcdsaSignFunction, as: type)
        case .p521VerifyDerPrehash: return try linked(rmCryptoP521VerifyDerPrehashLinked as LinkedVerifyFunction, as: type)
        case .bip340SchnorrDerivePublicKey: return try linked(rmCryptoBip340SchnorrDerivePublicKeyLinked as LinkedBip340SchnorrDerivePublicKeyFunction, as: type)
        case .bip340SchnorrSign: return try linked(rmCryptoBip340SchnorrSignLinked as LinkedBip340SignFunction, as: type)
        case .bip340SchnorrVerify: return try linked(rmCryptoBip340SchnorrVerifyLinked as LinkedVerifyFunction, as: type)
        case .aes128KwWrapKey: return try linked(rmCryptoAes128KwWrapKeyLinked as LinkedAesKwFunction, as: type)
        case .aes128KwUnwrapKey: return try linked(rmCryptoAes128KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
        case .aes192KwWrapKey: return try linked(rmCryptoAes192KwWrapKeyLinked as LinkedAesKwFunction, as: type)
        case .aes192KwUnwrapKey: return try linked(rmCryptoAes192KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
        case .aes256KwWrapKey: return try linked(rmCryptoAes256KwWrapKeyLinked as LinkedAesKwFunction, as: type)
        case .aes256KwUnwrapKey: return try linked(rmCryptoAes256KwUnwrapKeyLinked as LinkedAesKwFunction, as: type)
        case .hpkeSealBase: return try linked(rmCryptoHpkeSealBaseLinked as LinkedHpkeSealFunction, as: type)
        case .hpkeOpenBase: return try linked(rmCryptoHpkeOpenBaseLinked as LinkedHpkeOpenFunction, as: type)
        case .rsaVerifyPkcs1v15: return try linked(rmCryptoRsaVerifyPkcs1v15Linked as LinkedRsaPkcs1v15VerifyFunction, as: type)
        case .rsaVerifyPss: return try linked(rmCryptoRsaVerifyPssLinked as LinkedRsaPssVerifyFunction, as: type)
        case .mlDsa44GenerateKeypair: return try linked(rmCryptoMlDsa44GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlDsa44GenerateKeypairFromSeed: return try linked(rmCryptoMlDsa44GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlDsa44Sign: return try linked(rmCryptoMlDsa44SignLinked as LinkedSignFunction, as: type)
        case .mlDsa44Verify: return try linked(rmCryptoMlDsa44VerifyLinked as LinkedVerifyFunction, as: type)
        case .mlDsa65GenerateKeypair: return try linked(rmCryptoMlDsa65GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlDsa65GenerateKeypairFromSeed: return try linked(rmCryptoMlDsa65GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlDsa65Sign: return try linked(rmCryptoMlDsa65SignLinked as LinkedSignFunction, as: type)
        case .mlDsa65Verify: return try linked(rmCryptoMlDsa65VerifyLinked as LinkedVerifyFunction, as: type)
        case .mlDsa87GenerateKeypair: return try linked(rmCryptoMlDsa87GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlDsa87GenerateKeypairFromSeed: return try linked(rmCryptoMlDsa87GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlDsa87Sign: return try linked(rmCryptoMlDsa87SignLinked as LinkedSignFunction, as: type)
        case .mlDsa87Verify: return try linked(rmCryptoMlDsa87VerifyLinked as LinkedVerifyFunction, as: type)
        case .slhDsaSha2128sGenerateKeypair: return try linked(rmCryptoSlhDsaSha2128sGenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .slhDsaSha2128sDeriveKeypair: return try linked(rmCryptoSlhDsaSha2128sDeriveKeypairLinked as LinkedSlhDsaDeriveKeyPairFunction, as: type)
        case .slhDsaSha2128sSign: return try linked(rmCryptoSlhDsaSha2128sSignLinked as LinkedSignFunction, as: type)
        case .slhDsaSha2128sVerify: return try linked(rmCryptoSlhDsaSha2128sVerifyLinked as LinkedVerifyFunction, as: type)
        case .mlKem512GenerateKeypair: return try linked(rmCryptoMlKem512GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlKem512GenerateKeypairFromSeed: return try linked(rmCryptoMlKem512GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlKem512Encapsulate: return try linked(rmCryptoMlKem512EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case .mlKem512Decapsulate: return try linked(rmCryptoMlKem512DecapsulateLinked as LinkedSignFunction, as: type)
        case .mlKem768GenerateKeypair: return try linked(rmCryptoMlKem768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlKem768GenerateKeypairFromSeed: return try linked(rmCryptoMlKem768GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlKem768Encapsulate: return try linked(rmCryptoMlKem768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case .mlKem768Decapsulate: return try linked(rmCryptoMlKem768DecapsulateLinked as LinkedSignFunction, as: type)
        case .mlKem1024GenerateKeypair: return try linked(rmCryptoMlKem1024GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .mlKem1024GenerateKeypairFromSeed: return try linked(rmCryptoMlKem1024GenerateKeypairFromSeedLinked as LinkedDeriveKeyPairFunction, as: type)
        case .mlKem1024Encapsulate: return try linked(rmCryptoMlKem1024EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case .mlKem1024Decapsulate: return try linked(rmCryptoMlKem1024DecapsulateLinked as LinkedSignFunction, as: type)
        case .xWing768GenerateKeypair: return try linked(rmCryptoXWing768GenerateKeypairLinked as LinkedGenerateKeyPairFunction, as: type)
        case .xWing768GenerateKeypairDerand: return try linked(rmCryptoXWing768GenerateKeypairDerandLinked as LinkedXWingDeriveKeyPairFunction, as: type)
        case .xWing768Encapsulate: return try linked(rmCryptoXWing768EncapsulateLinked as LinkedKemEncapsulateFunction, as: type)
        case .xWing768Decapsulate: return try linked(rmCryptoXWing768DecapsulateLinked as LinkedSignFunction, as: type)
        }
    }
    #endif
}
