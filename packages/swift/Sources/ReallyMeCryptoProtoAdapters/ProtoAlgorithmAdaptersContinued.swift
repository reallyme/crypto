// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

extension ReallyMeCryptoProtoAdapters {
  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeKdfAlgorithm {
    switch value {
    case .hkdfSha256:
      .hkdfSha256
    case .hkdfSha384:
      .hkdfSha384
    case .argon2ID:
      .argon2id
    case .kmac256:
      .kmac256
    case .pbkdf2HmacSha256:
      .pbkdf2HmacSha256
    case .pbkdf2HmacSha512:
      .pbkdf2HmacSha512
    case .jwaConcatKdfSha256:
      .jwaConcatKdfSha256
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeKdfAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoKdfAlgorithm {
    switch value {
    case .hkdfSha256:
      .hkdfSha256
    case .hkdfSha384:
      .hkdfSha384
    case .argon2id:
      .argon2ID
    case .kmac256:
      .kmac256
    case .pbkdf2HmacSha256:
      .pbkdf2HmacSha256
    case .pbkdf2HmacSha512:
      .pbkdf2HmacSha512
    case .jwaConcatKdfSha256:
      .jwaConcatKdfSha256
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyWrapAlgorithm {
    switch value {
    case .aes128Kw:
      .aes128Kw
    case .aes192Kw:
      .aes192Kw
    case .aes256Kw:
      .aes256Kw
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeKeyWrapAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoKeyWrapAlgorithm {
    switch value {
    case .aes128Kw:
      .aes128Kw
    case .aes192Kw:
      .aes192Kw
    case .aes256Kw:
      .aes256Kw
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoHpkeSuiteIdentifier
  ) throws(ReallyMeCryptoError) -> ReallyMeHpkeSuite {
    if value.kem == .dhkemP256HkdfSha256,
      value.kdf == .hkdfSha256,
      value.aead == .aes256Gcm
    {
      return .dhkemP256HkdfSha256HkdfSha256Aes256Gcm
    }
    if value.kem == .dhkemX25519HkdfSha256,
      value.kdf == .hkdfSha256,
      value.aead == .chacha20Poly1305
    {
      return .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305
    }
    throw ReallyMeCryptoError.unsupportedAlgorithm
  }

  public static func toProto(
    _ value: ReallyMeHpkeSuite
  ) -> ReallyMeCryptoProto.ReallyMeProtoHpkeSuiteIdentifier {
    var result = ReallyMeCryptoProto.ReallyMeProtoHpkeSuiteIdentifier()
    result.kdf = .hkdfSha256
    switch value {
    case .dhkemP256HkdfSha256HkdfSha256Aes256Gcm:
      result.kem = .dhkemP256HkdfSha256
      result.aead = .aes256Gcm
    case .dhkemX25519HkdfSha256HkdfSha256ChaCha20Poly1305:
      result.kem = .dhkemX25519HkdfSha256
      result.aead = .chacha20Poly1305
    }
    return result
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeMulticodecKeyAlgorithm {
    switch value {
    case .ed25519Pub:
      .ed25519PublicKey
    case .x25519Pub:
      .x25519PublicKey
    case .secp256K1Pub:
      .secp256k1PublicKey
    case .p256Pub:
      .p256PublicKey
    case .p384Pub:
      .p384PublicKey
    case .p521Pub:
      .p521PublicKey
    case .ed448Pub:
      .ed448PublicKey
    case .rsaPub:
      .rsaPublicKey
    case .mlKem512Pub:
      .mlKem512PublicKey
    case .mlKem768Pub:
      .mlKem768PublicKey
    case .mlKem1024Pub:
      .mlKem1024PublicKey
    case .mlDsa44Pub:
      .mlDsa44PublicKey
    case .mlDsa65Pub:
      .mlDsa65PublicKey
    case .mlDsa87Pub:
      .mlDsa87PublicKey
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeMulticodecKeyAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoMulticodecKeyAlgorithm {
    switch value {
    case .ed25519PublicKey:
      .ed25519Pub
    case .x25519PublicKey:
      .x25519Pub
    case .secp256k1PublicKey:
      .secp256K1Pub
    case .p256PublicKey:
      .p256Pub
    case .p384PublicKey:
      .p384Pub
    case .p521PublicKey:
      .p521Pub
    case .ed448PublicKey:
      .ed448Pub
    case .rsaPublicKey:
      .rsaPub
    case .mlKem512PublicKey:
      .mlKem512Pub
    case .mlKem768PublicKey:
      .mlKem768Pub
    case .mlKem1024PublicKey:
      .mlKem1024Pub
    case .mlDsa44PublicKey:
      .mlDsa44Pub
    case .mlDsa65PublicKey:
      .mlDsa65Pub
    case .mlDsa87PublicKey:
      .mlDsa87Pub
    }
  }

}
