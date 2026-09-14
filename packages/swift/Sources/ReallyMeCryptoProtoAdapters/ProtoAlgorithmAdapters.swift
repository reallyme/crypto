// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeCrypto
import ReallyMeCryptoProto
import SwiftProtobuf

extension ReallyMeCryptoProtoAdapters {
  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeSignatureAlgorithm {
    switch value {
    case .ed25519:
      .ed25519
    case .ecdsaP256Sha256:
      .ecdsaP256Sha256
    case .ecdsaP384Sha384:
      .ecdsaP384Sha384
    case .ecdsaP521Sha512:
      .ecdsaP521Sha512
    case .ecdsaSecp256K1Sha256:
      .ecdsaSecp256k1Sha256
    case .bip340SchnorrSecp256K1Sha256:
      .bip340SchnorrSecp256k1Sha256
    case .rsaPkcs1V15Sha1:
      .rsaPkcs1v15Sha1
    case .rsaPkcs1V15Sha256:
      .rsaPkcs1v15Sha256
    case .rsaPkcs1V15Sha384:
      .rsaPkcs1v15Sha384
    case .rsaPkcs1V15Sha512:
      .rsaPkcs1v15Sha512
    case .rsaPssSha1Mgf1Sha1:
      .rsaPssSha1Mgf1Sha1
    case .rsaPssSha256Mgf1Sha256:
      .rsaPssSha256Mgf1Sha256
    case .rsaPssSha384Mgf1Sha384:
      .rsaPssSha384Mgf1Sha384
    case .rsaPssSha512Mgf1Sha512:
      .rsaPssSha512Mgf1Sha512
    case .mlDsa44:
      .mlDsa44
    case .mlDsa65:
      .mlDsa65
    case .mlDsa87:
      .mlDsa87
    case .slhDsaSha2128S:
      .slhDsaSha2_128s
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeSignatureAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoSignatureAlgorithm {
    switch value {
    case .ed25519:
      .ed25519
    case .ecdsaP256Sha256:
      .ecdsaP256Sha256
    case .ecdsaP384Sha384:
      .ecdsaP384Sha384
    case .ecdsaP521Sha512:
      .ecdsaP521Sha512
    case .ecdsaSecp256k1Sha256:
      .ecdsaSecp256K1Sha256
    case .bip340SchnorrSecp256k1Sha256:
      .bip340SchnorrSecp256K1Sha256
    case .rsaPkcs1v15Sha1:
      .rsaPkcs1V15Sha1
    case .rsaPkcs1v15Sha256:
      .rsaPkcs1V15Sha256
    case .rsaPkcs1v15Sha384:
      .rsaPkcs1V15Sha384
    case .rsaPkcs1v15Sha512:
      .rsaPkcs1V15Sha512
    case .rsaPssSha1Mgf1Sha1:
      .rsaPssSha1Mgf1Sha1
    case .rsaPssSha256Mgf1Sha256:
      .rsaPssSha256Mgf1Sha256
    case .rsaPssSha384Mgf1Sha384:
      .rsaPssSha384Mgf1Sha384
    case .rsaPssSha512Mgf1Sha512:
      .rsaPssSha512Mgf1Sha512
    case .mlDsa44:
      .mlDsa44
    case .mlDsa65:
      .mlDsa65
    case .mlDsa87:
      .mlDsa87
    case .slhDsaSha2_128s:
      .slhDsaSha2128S
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeHashAlgorithm {
    switch value {
    case .sha2256:
      .sha2_256
    case .sha2384:
      .sha2_384
    case .sha2512:
      .sha2_512
    case .sha3224:
      .sha3_224
    case .sha3256:
      .sha3_256
    case .sha3384:
      .sha3_384
    case .sha3512:
      .sha3_512
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeHashAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoHashAlgorithm {
    switch value {
    case .sha2_256:
      .sha2256
    case .sha2_384:
      .sha2384
    case .sha2_512:
      .sha2512
    case .sha3_224:
      .sha3224
    case .sha3_256:
      .sha3256
    case .sha3_384:
      .sha3384
    case .sha3_512:
      .sha3512
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeAeadAlgorithm {
    switch value {
    case .aes128Gcm:
      .aes128Gcm
    case .aes192Gcm:
      .aes192Gcm
    case .aes256Gcm:
      .aes256Gcm
    case .aes256GcmSiv:
      .aes256GcmSiv
    case .chacha20Poly1305:
      .chacha20Poly1305
    case .xchacha20Poly1305:
      .xchacha20Poly1305
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeAeadAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoAeadAlgorithm {
    switch value {
    case .aes128Gcm:
      .aes128Gcm
    case .aes192Gcm:
      .aes192Gcm
    case .aes256Gcm:
      .aes256Gcm
    case .aes256GcmSiv:
      .aes256GcmSiv
    case .chacha20Poly1305:
      .chacha20Poly1305
    case .xchacha20Poly1305:
      .xchacha20Poly1305
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeKemAlgorithm {
    switch value {
    case .mlKem512:
      .mlKem512
    case .mlKem768:
      .mlKem768
    case .mlKem1024:
      .mlKem1024
    case .xWing768:
      .xWing768
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeKemAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoKemAlgorithm {
    switch value {
    case .mlKem512:
      .mlKem512
    case .mlKem768:
      .mlKem768
    case .mlKem1024:
      .mlKem1024
    case .xWing768:
      .xWing768
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeKeyAgreementAlgorithm {
    switch value {
    case .x25519:
      .x25519
    case .p256Ecdh:
      .p256Ecdh
    case .p384Ecdh:
      .p384Ecdh
    case .p521Ecdh:
      .p521Ecdh
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeKeyAgreementAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoKeyAgreementAlgorithm {
    switch value {
    case .x25519:
      .x25519
    case .p256Ecdh:
      .p256Ecdh
    case .p384Ecdh:
      .p384Ecdh
    case .p521Ecdh:
      .p521Ecdh
    }
  }

  public static func fromProto(
    _ value: ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm
  ) throws(ReallyMeCryptoError) -> ReallyMeMacAlgorithm {
    switch value {
    case .hmacSha256:
      .hmacSha256
    case .hmacSha384:
      .hmacSha384
    case .hmacSha512:
      .hmacSha512
    default:
      throw ReallyMeCryptoError.unsupportedAlgorithm
    }
  }

  public static func toProto(
    _ value: ReallyMeMacAlgorithm
  ) -> ReallyMeCryptoProto.ReallyMeProtoMacAlgorithm {
    switch value {
    case .hmacSha256:
      .hmacSha256
    case .hmacSha384:
      .hmacSha384
    case .hmacSha512:
      .hmacSha512
    }
  }

}
