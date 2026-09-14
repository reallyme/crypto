// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Secp256k1ABI
import Security
import SwiftProviderProbes
import XCTest

struct Manifest: Decodable {
  let vectors: [String]
  let runtimeLanes: [RuntimeLane]

  enum CodingKeys: String, CodingKey {
    case vectors
    case runtimeLanes = "runtime_lanes"
  }
}

struct RuntimeLane: Decodable {
  let name: String
  let status: String
  let algorithms: [String]
  let notes: [String]
}

struct P256Vector: Decodable {
  let secretKey: String
  let publicKeyCompressed: String
  let publicKeyUncompressed: String
  let peerSecretKey: String
  let peerPublicKeyCompressed: String
  let peerPublicKeyUncompressed: String
  let sharedSecret: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKeyCompressed = "public_key_compressed"
    case publicKeyUncompressed = "public_key_uncompressed"
    case peerSecretKey = "peer_secret_key"
    case peerPublicKeyCompressed = "peer_public_key_compressed"
    case peerPublicKeyUncompressed = "peer_public_key_uncompressed"
    case sharedSecret = "shared_secret"
  }
}

struct Sec1EcdsaVector: Decodable {
  let secretKey: String
  let publicKeyCompressed: String
  let publicKeyUncompressed: String
  let message: String
  let signatureDer: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKeyCompressed = "public_key_compressed"
    case publicKeyUncompressed = "public_key_uncompressed"
    case message
    case signatureDer = "signature_der"
  }
}

struct Ed25519Vector: Decodable {
  let secretKey: String
  let publicKey: String
  let message: String
  let signature: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case message
    case signature
  }
}

struct X25519Vector: Decodable {
  let secretKey: String
  let publicKey: String
  let peerSecretKey: String
  let peerPublicKey: String
  let sharedSecret: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case peerSecretKey = "peer_secret_key"
    case peerPublicKey = "peer_public_key"
    case sharedSecret = "shared_secret"
  }
}

struct Secp256k1Vector: Decodable {
  let secretKey: String
  let publicKeyCompressed: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKeyCompressed = "public_key_compressed"
  }
}

struct Bip340SchnorrVector: Decodable {
  let secretKey: String
  let publicKeyXonly: String
  let publicKeyFormat: String
  let message: String
  let auxRand: String
  let signature: String

  enum CodingKeys: String, CodingKey {
    case secretKey = "secret_key"
    case publicKeyXonly = "public_key_xonly"
    case publicKeyFormat = "public_key_format"
    case message
    case auxRand = "aux_rand"
    case signature
  }
}

struct RsaVector: Decodable {
  let keyFormat: String
  let publicKeyDer: String
  let message: String
  let pkcs1v15Sha1Signature: String
  let pkcs1v15Sha256Signature: String
  let pssSha256Mgf1Sha256SaltLen: Int
  let pssSha256Mgf1Sha256Signature: String

  enum CodingKeys: String, CodingKey {
    case keyFormat = "key_format"
    case publicKeyDer = "public_key_der"
    case message
    case pkcs1v15Sha1Signature = "pkcs1v15_sha1_signature"
    case pkcs1v15Sha256Signature = "pkcs1v15_sha256_signature"
    case pssSha256Mgf1Sha256SaltLen = "pss_sha256_mgf1_sha256_salt_len"
    case pssSha256Mgf1Sha256Signature = "pss_sha256_mgf1_sha256_signature"
  }
}

struct MlDsaVector: Decodable {
  let secretKeyFormat: String
  let secretKey: String
  let publicKey: String
  let publicKeyLength: Int
  let message: String
  let signature: String

  enum CodingKeys: String, CodingKey {
    case secretKeyFormat = "secret_key_format"
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case publicKeyLength = "public_key_length"
    case message
    case signature
  }
}

struct SlhDsaVector: Decodable {
  let secretKeyFormat: String
  let keygenSkSeed: String
  let keygenSkPrf: String
  let keygenPkSeed: String
  let secretKey: String
  let publicKey: String
  let publicKeyLength: Int
  let secretKeyLength: Int
  let message: String
  let signature: String
  let signatureLength: Int

  enum CodingKeys: String, CodingKey {
    case secretKeyFormat = "secret_key_format"
    case keygenSkSeed = "keygen_sk_seed"
    case keygenSkPrf = "keygen_sk_prf"
    case keygenPkSeed = "keygen_pk_seed"
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case publicKeyLength = "public_key_length"
    case secretKeyLength = "secret_key_length"
    case message
    case signature
    case signatureLength = "signature_length"
  }
}

struct MlKemVector: Decodable {
  let secretKeyFormat: String
  let secretKey: String
  let publicKey: String
  let publicKeyLength: Int
  let ciphertext: String
  let sharedSecret: String
  let tamperedCiphertext: String
  let tamperedSharedSecret: String

  enum CodingKeys: String, CodingKey {
    case secretKeyFormat = "secret_key_format"
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case publicKeyLength = "public_key_length"
    case ciphertext
    case sharedSecret = "shared_secret"
    case tamperedCiphertext = "tampered_ciphertext"
    case tamperedSharedSecret = "tampered_shared_secret"
  }
}

struct XWingVectors: Decodable {
  let xWing768: XWingVector

  enum CodingKeys: String, CodingKey {
    case xWing768 = "x_wing_768"
  }
}

struct XWingVector: Decodable {
  let secretKeyFormat: String
  let secretKey: String
  let publicKey: String
  let publicKeyLength: Int
  let encapsSeed: String
  let ciphertext: String
  let ciphertextLength: Int
  let sharedSecret: String

  enum CodingKeys: String, CodingKey {
    case secretKeyFormat = "secret_key_format"
    case secretKey = "secret_key"
    case publicKey = "public_key"
    case publicKeyLength = "public_key_length"
    case encapsSeed = "encaps_seed"
    case ciphertext
    case ciphertextLength = "ciphertext_length"
    case sharedSecret = "shared_secret"
  }
}

struct HpkeVectors: Decodable {
  let p256Sha256Aes256Gcm: HpkeVector
  let x25519Sha256ChaCha20Poly1305: HpkeVector

  enum CodingKeys: String, CodingKey {
    case p256Sha256Aes256Gcm = "p256_sha256_aes256gcm"
    case x25519Sha256ChaCha20Poly1305 = "x25519_sha256_chacha20poly1305"
  }
}

struct HpkeVector: Decodable {
  let alg: String
  let mode: String
  let kemId: Int
  let kdfId: Int
  let aeadId: Int
  let recipientSecretKey: String
  let recipientPublicKey: String
  let encapsSeed: String
  let info: String
  let aad: String
  let plaintext: String
  let encapsulatedKey: String
  let ciphertext: String
  let tamperedCiphertext: String

  enum CodingKeys: String, CodingKey {
    case alg
    case mode
    case kemId = "kem_id"
    case kdfId = "kdf_id"
    case aeadId = "aead_id"
    case recipientSecretKey = "recipient_secret_key"
    case recipientPublicKey = "recipient_public_key"
    case encapsSeed = "encaps_seed"
    case info
    case aad
    case plaintext
    case encapsulatedKey = "encapsulated_key"
    case ciphertext
    case tamperedCiphertext = "tampered_ciphertext"
  }
}

struct Aes256GcmVector: Decodable {
  let key: String
  let nonce: String
  let aad: String
  let plaintext: String
  let ciphertextWithTag: String

  enum CodingKeys: String, CodingKey {
    case key
    case nonce
    case aad
    case plaintext
    case ciphertextWithTag = "ciphertext_with_tag"
  }
}

struct AesKwVector: Decodable {
  let alg: String
  let kek: String
  let keyData: String
  let wrappedKey: String

  enum CodingKeys: String, CodingKey {
    case alg
    case kek
    case keyData = "key_data"
    case wrappedKey = "wrapped_key"
  }
}

struct Kmac256Vector: Decodable {
  let alg: String
  let key: String
  let context: String
  let customization: String
  let outputLength: Int
  let derivedKey: String

  enum CodingKeys: String, CodingKey {
    case alg
    case key
    case context
    case customization
    case outputLength = "output_length"
    case derivedKey = "derived_key"
  }
}

struct ChaCha20Poly1305Vectors: Decodable {
  let chacha20Poly1305: ChaCha20Poly1305Vector
  let xChaCha20Poly1305: ChaCha20Poly1305Vector

  enum CodingKeys: String, CodingKey {
    case chacha20Poly1305 = "chacha20_poly1305"
    case xChaCha20Poly1305 = "xchacha20_poly1305"
  }
}

struct ChaCha20Poly1305Vector: Decodable {
  let key: String
  let nonce: String
  let aad: String
  let plaintext: String
  let ciphertextWithTag: String

  enum CodingKeys: String, CodingKey {
    case key
    case nonce
    case aad
    case plaintext
    case ciphertextWithTag = "ciphertext_with_tag"
  }
}

struct HashVector: Decodable {
  let message: String
  let sha2_256: String
  let sha2_384: String
  let sha2_512: String
  let sha3_224: String
  let sha3_256: String
  let sha3_384: String
  let sha3_512: String
}

struct HmacVectors: Decodable {
  let hmacSha256: HmacVector
  let hmacSha384: HmacVector
  let hmacSha512: HmacVector

  enum CodingKeys: String, CodingKey {
    case hmacSha256 = "hmac_sha256"
    case hmacSha384 = "hmac_sha384"
    case hmacSha512 = "hmac_sha512"
  }
}

struct HkdfVector: Decodable {
  let alg: String
  let hash: String
  let ikm: String
  let salt: String
  let info: String
  let outputLen: Int
  let okm: String

  enum CodingKeys: String, CodingKey {
    case alg
    case hash
    case ikm
    case salt
    case info
    case outputLen = "output_len"
    case okm
  }
}

struct HmacVector: Decodable {
  let key: String
  let message: String
  let tag: String
}

struct Pbkdf2Vectors: Decodable {
  let pbkdf2HmacSha256: Pbkdf2Vector
  let pbkdf2HmacSha512: Pbkdf2Vector

  enum CodingKeys: String, CodingKey {
    case pbkdf2HmacSha256 = "pbkdf2_hmac_sha256"
    case pbkdf2HmacSha512 = "pbkdf2_hmac_sha512"
  }
}

struct Pbkdf2Vector: Decodable {
  let alg: String
  let password: String
  let salt: String
  let iterations: Int
  let outputLen: Int
  let derivedKey: String

  enum CodingKeys: String, CodingKey {
    case alg
    case password
    case salt
    case iterations
    case outputLen = "output_len"
    case derivedKey = "derived_key"
  }
}

struct JwkVectors: Decodable {
  let vectors: [JwkVector]
}

struct JwkVector: Decodable {
  let alg: String
  let publicKey: String
  let publicKeyLength: Int
  let jwkJcs: String
  let multikey: String?
  let multikeyStatus: String

  enum CodingKeys: String, CodingKey {
    case alg
    case publicKey = "public_key"
    case publicKeyLength = "public_key_length"
    case jwkJcs = "jwk_jcs"
    case multikey
    case multikeyStatus = "multikey_status"
  }
}

struct SwiftJwkSpec {
  let alg: String
  let crv: String
  let kty: String
  let keyUse: String
  let publicKeyLength: Int
}

struct ParsedJwk {
  let alg: String
  let publicKey: Data
}
