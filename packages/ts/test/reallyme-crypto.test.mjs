// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  aes128GcmOpen,
  aes128GcmSeal,
  aes192GcmOpen,
  aes192GcmSeal,
  aes256GcmOpen,
  aes256GcmSeal,
  aes256GcmSivOpen,
  aes256GcmSivSeal,
  aes256KwUnwrapKey,
  aes256KwWrapKey,
  argon2idDeriveKey,
  base64urlDecode,
  base64urlEncode,
  chacha20Poly1305Open,
  chacha20Poly1305Seal,
  dagCborComputeCid,
  dagCborVerifyCid,
  hpkeOpenBase,
  hpkeSealBase,
  hpkeSealBaseDerand,
  initSync,
  multibaseBase58btcEncode,
  multibaseBase64urlEncode,
  multibaseDecode,
  multicodecLookupPrefix,
  multicodecPrefixForName,
  multikeyEncode,
  multikeyParse,
  mlKem1024Decapsulate,
  mlKem1024DeriveKeypair,
  mlKem1024Encapsulate,
  mlKem1024EncapsulateDerand,
  mlKem1024GenerateKeypair,
  mlDsa44DeriveKeypair,
  mlDsa44GenerateKeypair,
  mlDsa44Sign,
  mlDsa44Verify,
  mlDsa65DeriveKeypair,
  mlDsa65GenerateKeypair,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa87DeriveKeypair,
  mlDsa87GenerateKeypair,
  mlDsa87Sign,
  mlDsa87Verify,
  mlKem512Decapsulate,
  mlKem512DeriveKeypair,
  mlKem512Encapsulate,
  mlKem512EncapsulateDerand,
  mlKem512GenerateKeypair,
  mlKem768Decapsulate,
  mlKem768DeriveKeypair,
  mlKem768Encapsulate,
  mlKem768EncapsulateDerand,
  mlKem768GenerateKeypair,
  rsaVerifyPkcs1v15,
  rsaVerifyPss,
  slhDsaSha2128sDeriveKeypair,
  slhDsaSha2128sGenerateKeypair,
  slhDsaSha2128sSign,
  slhDsaSha2128sVerify,
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
  xWing1024Decapsulate,
  xWing1024DeriveKeypair,
  xWing1024Encapsulate,
  xWing1024EncapsulateDerand,
  xWing1024GenerateKeypair,
  xWing768Decapsulate,
  xWing768DeriveKeypair,
  xWing768Encapsulate,
  xWing768EncapsulateDerand,
  xWing768GenerateKeypair,
} from "../dist/wasm/reallyme_crypto_wasm.js";
import { sealHpkeBaseDeterministicallyForTest } from "../dist/hpke.js";
import { deriveSlhDsaSha2128sKeypairForTest } from "../dist/slhDsa.js";
import { encapsulateXWingDeterministicallyForTest } from "../dist/xWing.js";

import {
  compiledProviders,
  BIP340_SCHNORR_SIGNATURE_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  installReallyMeWasmProvider,
  REALLYME_AEAD_ALGORITHMS,
  REALLYME_HASH_ALGORITHMS,
  REALLYME_HPKE_SUITES,
  REALLYME_KDF_ALGORITHMS,
  REALLYME_KEM_ALGORITHMS,
  REALLYME_KEY_AGREEMENT_ALGORITHMS,
  REALLYME_KEY_WRAP_ALGORITHMS,
  REALLYME_MAC_ALGORITHMS,
  REALLYME_SIGNATURE_ALGORITHMS,
  ReallyMeCrypto,
  ReallyMeCryptoError,
  ReallyMeCodecs,
  ReallyMeDigest,
  ReallyMeEd25519,
  ReallyMeArgon2id,
  ReallyMeBip340Schnorr,
  ReallyMeP256Ecdsa,
  ReallyMeP256Ecdh,
  ReallyMeP384Ecdh,
  ReallyMeP384Ecdsa,
  ReallyMeP521Ecdh,
  ReallyMeP521Ecdsa,
  ReallyMeHpke,
  ReallyMeJwk,
  ReallyMeJwaConcatKdf,
  ReallyMeMlDsa,
  ReallyMeMlKem,
  ReallyMeRsa,
  ReallyMeSecp256k1,
  ReallyMeSlhDsa,
  ReallyMeX25519,
  ReallyMeXWing,
  HPKE_P256_PUBLIC_KEY_LENGTH,
  HPKE_X25519_PUBLIC_KEY_LENGTH,
  ML_DSA_44_PUBLIC_KEY_LENGTH,
  ML_DSA_44_SIGNATURE_LENGTH,
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  ML_DSA_87_PUBLIC_KEY_LENGTH,
  ML_DSA_87_SIGNATURE_LENGTH,
  ML_DSA_SECRET_KEY_LENGTH,
  ML_KEM_1024_CIPHERTEXT_LENGTH,
  ML_KEM_1024_PUBLIC_KEY_LENGTH,
  ML_KEM_512_CIPHERTEXT_LENGTH,
  ML_KEM_512_PUBLIC_KEY_LENGTH,
  ML_KEM_768_CIPHERTEXT_LENGTH,
  ML_KEM_768_PUBLIC_KEY_LENGTH,
  ML_KEM_ENCAPSULATION_RANDOMNESS_LENGTH,
  ML_KEM_SECRET_KEY_LENGTH,
  ML_KEM_SHARED_SECRET_LENGTH,
  P256_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P384_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P521_ECDSA_DER_SIGNATURE_MAX_LENGTH,
  P256_ECDH_SHARED_SECRET_LENGTH,
  P384_ECDH_SHARED_SECRET_LENGTH,
  P521_ECDH_SHARED_SECRET_LENGTH,
  SECP256K1_SIGNATURE_LENGTH,
  SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH,
  SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH,
  SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH,
  SLH_DSA_SHA2_128S_SIGNATURE_LENGTH,
  X_WING_1024_CIPHERTEXT_LENGTH,
  X_WING_1024_PUBLIC_KEY_LENGTH,
  X_WING_768_CIPHERTEXT_LENGTH,
  X_WING_768_PUBLIC_KEY_LENGTH,
  X_WING_SECRET_KEY_LENGTH,
  X_WING_SHARED_SECRET_LENGTH,
  X25519_SHARED_SECRET_LENGTH,
} from "../dist/index.js";
import {
  AeadAlgorithm,
  CodecErrorReason,
  CryptoErrorReason,
  HashAlgorithm,
  KdfAlgorithm,
  KeyAgreementAlgorithm,
  MulticodecKeyAlgorithm,
  SignatureAlgorithm,
  aeadAlgorithmFromProto,
  aeadAlgorithmToProto,
  hashAlgorithmFromProto,
  hashAlgorithmToProto,
  kdfAlgorithmFromProto,
  kdfAlgorithmToProto,
  keyAgreementAlgorithmFromProto,
  keyAgreementAlgorithmToProto,
  multicodecKeyAlgorithmFromProto,
  signatureAlgorithmFromProto,
  signatureAlgorithmToProto,
} from "../dist/proto.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const bytes = (hexString) => Uint8Array.from(Buffer.from(hexString, "hex"));
const base64UrlBytes = (base64url) =>
  Uint8Array.from(Buffer.from(base64url, "base64url"));
const assertUnsupportedAlgorithm = (operation) => {
  assert.throws(
    operation,
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
};
const assertReallyMeError = (operation, code) => {
  assert.throws(
    operation,
    (error) => error instanceof ReallyMeCryptoError && error.code === code,
  );
};
const wasmBytes = readFileSync(
  new URL("../dist/wasm/reallyme_crypto_wasm_bg.wasm", import.meta.url),
);
initSync({ module: wasmBytes });
installReallyMeWasmProvider({
  aes128GcmOpen,
  aes128GcmSeal,
  aes192GcmOpen,
  aes192GcmSeal,
  aes256GcmOpen,
  aes256GcmSeal,
  aes256GcmSivOpen,
  aes256GcmSivSeal,
  aes256KwUnwrapKey,
  aes256KwWrapKey,
  argon2idDeriveKey,
  base64urlDecode,
  base64urlEncode,
  chacha20Poly1305Open,
  chacha20Poly1305Seal,
  dagCborComputeCid,
  dagCborVerifyCid,
  hpkeOpenBase,
  hpkeSealBase,
  hpkeSealBaseDerand,
  mlDsa44DeriveKeypair,
  mlDsa44GenerateKeypair,
  mlDsa44Sign,
  mlDsa44Verify,
  mlDsa65DeriveKeypair,
  mlDsa65GenerateKeypair,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa87DeriveKeypair,
  mlDsa87GenerateKeypair,
  mlDsa87Sign,
  mlDsa87Verify,
  mlKem1024Decapsulate,
  mlKem1024DeriveKeypair,
  mlKem1024Encapsulate,
  mlKem1024EncapsulateDerand,
  mlKem1024GenerateKeypair,
  mlKem512Decapsulate,
  mlKem512DeriveKeypair,
  mlKem512Encapsulate,
  mlKem512EncapsulateDerand,
  mlKem512GenerateKeypair,
  mlKem768Decapsulate,
  mlKem768DeriveKeypair,
  mlKem768Encapsulate,
  mlKem768EncapsulateDerand,
  mlKem768GenerateKeypair,
  multibaseBase58btcEncode,
  multibaseBase64urlEncode,
  multibaseDecode,
  multicodecLookupPrefix,
  multicodecPrefixForName,
  multikeyEncode,
  multikeyParse,
  rsaVerifyPkcs1v15,
  rsaVerifyPss,
  slhDsaSha2128sDeriveKeypair,
  slhDsaSha2128sGenerateKeypair,
  slhDsaSha2128sSign,
  slhDsaSha2128sVerify,
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
  xWing1024Decapsulate,
  xWing1024DeriveKeypair,
  xWing1024Encapsulate,
  xWing1024EncapsulateDerand,
  xWing1024GenerateKeypair,
  xWing768Decapsulate,
  xWing768DeriveKeypair,
  xWing768Encapsulate,
  xWing768EncapsulateDerand,
  xWing768GenerateKeypair,
});

test("proto adapters round-trip supported algorithms and reject reserved values", () => {
  assert.equal(signatureAlgorithmFromProto(SignatureAlgorithm.ED25519), "Ed25519");
  assert.equal(
    signatureAlgorithmToProto("BIP340-Schnorr-secp256k1-SHA256"),
    SignatureAlgorithm.BIP340_SCHNORR_SECP256K1_SHA256,
  );
  assert.equal(hashAlgorithmFromProto(HashAlgorithm.SHA2_256), "SHA2-256");
  assert.equal(hashAlgorithmToProto("SHA3-512"), HashAlgorithm.SHA3_512);
  assert.equal(aeadAlgorithmFromProto(AeadAlgorithm.AES_128_GCM), "AES-128-GCM");
  assert.equal(aeadAlgorithmToProto("AES-128-GCM"), AeadAlgorithm.AES_128_GCM);
  assert.equal(aeadAlgorithmFromProto(AeadAlgorithm.AES_192_GCM), "AES-192-GCM");
  assert.equal(aeadAlgorithmToProto("AES-192-GCM"), AeadAlgorithm.AES_192_GCM);
  assert.equal(
    keyAgreementAlgorithmFromProto(KeyAgreementAlgorithm.P384_ECDH),
    "P-384-ECDH",
  );
  assert.equal(
    keyAgreementAlgorithmToProto("P-521-ECDH"),
    KeyAgreementAlgorithm.P521_ECDH,
  );
  assert.equal(
    kdfAlgorithmFromProto(KdfAlgorithm.JWA_CONCAT_KDF_SHA256),
    "JWA-CONCAT-KDF-SHA256",
  );
  assert.equal(
    kdfAlgorithmToProto("JWA-CONCAT-KDF-SHA256"),
    KdfAlgorithm.JWA_CONCAT_KDF_SHA256,
  );
  assert.equal(
    multicodecKeyAlgorithmFromProto(MulticodecKeyAlgorithm.ML_KEM_768_PUB),
    "mlkem-768-pub",
  );
  assert.equal(CryptoErrorReason.PRIMITIVE_VERIFICATION_FAILED, 121);
  assert.equal(CodecErrorReason.PEM_INVALID_BOUNDARY, 200);
  assertUnsupportedAlgorithm(() => hashAlgorithmFromProto(HashAlgorithm.UNSPECIFIED));
  assertUnsupportedAlgorithm(() =>
    multicodecKeyAlgorithmFromProto(MulticodecKeyAlgorithm.ED25519_PRIV),
  );
  assertUnsupportedAlgorithm(() => signatureAlgorithmFromProto(65_535));
});

const vectorString = (object, name) => {
  const value = object[name];
  assert.equal(typeof value, "string");
  return value;
};

const vectorNumber = (object, name) => {
  const value = object[name];
  assert.equal(typeof value, "number");
  return value;
};

const xWingVectors = JSON.parse(
  readFileSync(new URL("../../../vectors/x_wing.json", import.meta.url), "utf8"),
);
const aes128GcmVector = JSON.parse(
  readFileSync(new URL("../../../vectors/aes128gcm.json", import.meta.url), "utf8"),
);
const aes192GcmVector = JSON.parse(
  readFileSync(new URL("../../../vectors/aes192gcm.json", import.meta.url), "utf8"),
);
const aes256GcmVector = JSON.parse(
  readFileSync(new URL("../../../vectors/aes256gcm.json", import.meta.url), "utf8"),
);
const aes256GcmSivVector = JSON.parse(
  readFileSync(new URL("../../../vectors/aes256gcmsiv.json", import.meta.url), "utf8"),
);
const argon2idVector = JSON.parse(
  readFileSync(new URL("../../../vectors/argon2id.json", import.meta.url), "utf8"),
);
const aes256KwVector = JSON.parse(
  readFileSync(new URL("../../../vectors/aes256kw.json", import.meta.url), "utf8"),
);
const chachaVectors = JSON.parse(
  readFileSync(new URL("../../../vectors/chacha20poly1305.json", import.meta.url), "utf8"),
);
const concatKdfVector = JSON.parse(
  readFileSync(new URL("../../../vectors/concat_kdf.json", import.meta.url), "utf8"),
);
const hpkeVectors = JSON.parse(
  readFileSync(new URL("../../../vectors/hpke.json", import.meta.url), "utf8"),
);
const mlKemVectors = {
  "ML-KEM-512": JSON.parse(
    readFileSync(new URL("../../../vectors/mlkem512.json", import.meta.url), "utf8"),
  ),
  "ML-KEM-768": JSON.parse(
    readFileSync(new URL("../../../vectors/mlkem768.json", import.meta.url), "utf8"),
  ),
  "ML-KEM-1024": JSON.parse(
    readFileSync(new URL("../../../vectors/mlkem1024.json", import.meta.url), "utf8"),
  ),
};
const mlDsaVectors = {
  "ML-DSA-44": JSON.parse(
    readFileSync(new URL("../../../vectors/ml_dsa_44.json", import.meta.url), "utf8"),
  ),
  "ML-DSA-65": JSON.parse(
    readFileSync(new URL("../../../vectors/ml_dsa_65.json", import.meta.url), "utf8"),
  ),
  "ML-DSA-87": JSON.parse(
    readFileSync(new URL("../../../vectors/ml_dsa_87.json", import.meta.url), "utf8"),
  ),
};
const slhDsaVector = JSON.parse(
  readFileSync(new URL("../../../vectors/slh_dsa_sha2_128s.json", import.meta.url), "utf8"),
);
const codecsVector = JSON.parse(
  readFileSync(new URL("../../../vectors/codecs.json", import.meta.url), "utf8"),
);
const jwkVector = JSON.parse(
  readFileSync(new URL("../../../vectors/jwk.json", import.meta.url), "utf8"),
);
const p256Vector = JSON.parse(
  readFileSync(new URL("../../../vectors/p256.json", import.meta.url), "utf8"),
);
const p384Vector = JSON.parse(
  readFileSync(new URL("../../../vectors/p384.json", import.meta.url), "utf8"),
);
const p521Vector = JSON.parse(
  readFileSync(new URL("../../../vectors/p521.json", import.meta.url), "utf8"),
);
const bip340SchnorrVector = JSON.parse(
  readFileSync(new URL("../../../vectors/bip340_schnorr.json", import.meta.url), "utf8"),
);
const rsaVector = JSON.parse(
  readFileSync(new URL("../../../vectors/rsa.json", import.meta.url), "utf8"),
);

const xWingCase = (name) => {
  const value = xWingVectors[name];
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value;
};

const chachaCase = (name) => {
  const value = chachaVectors[name];
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value;
};

const hpkeCase = (name) => {
  const value = hpkeVectors[name];
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value;
};

const mlKemCase = (algorithm) => {
  const value = mlKemVectors[algorithm];
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value;
};

const mlDsaCase = (algorithm) => {
  const value = mlDsaVectors[algorithm];
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  return value;
};

// Keypair from vectors/secp256k1.json — the same KAT every lane proves.
const vectorSecretKey = bytes(
  "4e390c72a5d15f209963812e37af04bce156489a2f730d8451c63b09f528617d",
);
const vectorPublicKey = bytes(
  "02e1517f97e1877f63fee722a687ddaefc3ec7cce1d27360aeec02091f04e18dd4",
);
const bip340SchnorrSecretKey = base64UrlBytes(
  vectorString(bip340SchnorrVector, "secret_key"),
);
const bip340SchnorrPublicKey = base64UrlBytes(
  vectorString(bip340SchnorrVector, "public_key_xonly"),
);
const bip340SchnorrMessage = base64UrlBytes(
  vectorString(bip340SchnorrVector, "message"),
);
const bip340SchnorrAuxRand = base64UrlBytes(
  vectorString(bip340SchnorrVector, "aux_rand"),
);
const bip340SchnorrSignature = base64UrlBytes(
  vectorString(bip340SchnorrVector, "signature"),
);

// Keypair from vectors/ed25519.json — the same KAT every lane proves.
const ed25519SecretKey = bytes(
  "9b712355c46a089f4182701852cdef4322116da07e394abcd85f132692a1be77",
);
const ed25519PublicKey = bytes(
  "6ddffbec369caae216a5fb99080a6ce013799d8bea00d39804d7a90d73502d82",
);
const ed25519Message = bytes(
  "5265616c6c794d65207369676e617475726520636f6e666f726d616e636520766563746f72",
);
const ed25519Signature = bytes(
  "69d360b839583ce3632021e8ca6b382533f68e8c53f4996cd84dfda548273659" +
    "3646588752e7d8d22a84cdccdc4cb84e6b8c781e672745aca5ace2443cccde03",
);

// Key agreement case from vectors/x25519.json — the same KAT every lane proves.
const x25519SecretKey = bytes(
  "13b40e434329c8395922a66d6fb8c50d3b35263f8e5c06cac624a86527d3b304",
);
const x25519PublicKey = bytes(
  "cbbec1ce67440087d03bfd8536ea3f7fa922cf529abc66578b62f3bf5ab26141",
);
const x25519PeerSecretKey = bytes(
  "73806939b0f9e8d2ae4c3d70a4b725933687d2858ca5d08960a9e25450ef50ae",
);
const x25519PeerPublicKey = bytes(
  "4444a8bf80ad7e56fc28dbc826d9f44fc49bd945f3ba2626138f791d7a55180b",
);
const x25519SharedSecret = bytes(
  "e00c4d62a8beeeedc0d7d0aca78e4c94395a063539a8204ce8fc11120e8dbc18",
);

const p256EcdhSecretKey = base64UrlBytes(vectorString(p256Vector, "secret_key"));
const p256EcdhPublicKey = base64UrlBytes(
  vectorString(p256Vector, "public_key_compressed"),
);
const p256EcdhPeerSecretKey = base64UrlBytes(
  vectorString(p256Vector, "peer_secret_key"),
);
const p256EcdhPeerPublicKey = base64UrlBytes(
  vectorString(p256Vector, "peer_public_key_compressed"),
);
const p256EcdhSharedSecret = base64UrlBytes(
  vectorString(p256Vector, "shared_secret"),
);
const p384EcdhSecretKey = base64UrlBytes(vectorString(p384Vector, "secret_key"));
const p384EcdhPublicKey = base64UrlBytes(
  vectorString(p384Vector, "public_key_compressed"),
);
const p384EcdhPeerSecretKey = base64UrlBytes(
  vectorString(p384Vector, "peer_secret_key"),
);
const p384EcdhPeerPublicKey = base64UrlBytes(
  vectorString(p384Vector, "peer_public_key_compressed"),
);
const p384EcdhSharedSecret = base64UrlBytes(
  vectorString(p384Vector, "shared_secret"),
);
const p521EcdhSecretKey = base64UrlBytes(vectorString(p521Vector, "secret_key"));
const p521EcdhPublicKey = base64UrlBytes(
  vectorString(p521Vector, "public_key_compressed"),
);
const p521EcdhPeerSecretKey = base64UrlBytes(
  vectorString(p521Vector, "peer_secret_key"),
);
const p521EcdhPeerPublicKey = base64UrlBytes(
  vectorString(p521Vector, "peer_public_key_compressed"),
);
const p521EcdhSharedSecret = base64UrlBytes(
  vectorString(p521Vector, "shared_secret"),
);
const p256EcdsaMessage = base64UrlBytes(
  vectorString(p256Vector, "ecdsa_message"),
);
const p256EcdsaSignature = base64UrlBytes(
  vectorString(p256Vector, "ecdsa_signature_der"),
);

test("provider catalog is explicit", () => {
  assert.deepEqual(
    [...compiledProviders],
    ["@noble/curves", "@noble/hashes", "ReallyMe Rust WASM"],
  );
});

test("WASM codecs match shared vectors", () => {
  const raw = base64UrlBytes(vectorString(codecsVector, "raw"));
  const base64url = vectorString(codecsVector, "base64url");
  const multibaseBase64url = vectorString(codecsVector, "multibase_base64url");
  const multibaseBase58btc = vectorString(codecsVector, "multibase_base58btc");
  const dagCborBytes = base64UrlBytes(vectorString(codecsVector, "dag_cbor"));
  const dagCborCid = vectorString(codecsVector, "dag_cbor_cid");

  assert.equal(ReallyMeCodecs.base64urlEncode(raw), base64url);
  assert.deepEqual(ReallyMeCodecs.base64urlDecode(base64url), raw);
  assert.equal(ReallyMeCodecs.multibaseBase64urlEncode(raw), multibaseBase64url);
  assert.equal(ReallyMeCodecs.multibaseBase58btcEncode(raw), multibaseBase58btc);
  assert.deepEqual(ReallyMeCodecs.multibaseDecode(multibaseBase64url), raw);
  assert.deepEqual(ReallyMeCodecs.multibaseDecode(multibaseBase58btc), raw);
  assert.equal(ReallyMeCodecs.dagCborComputeCid(dagCborBytes), dagCborCid);

  const cidVerification = ReallyMeCodecs.dagCborVerifyCid(dagCborCid, dagCborBytes);
  assert.equal(cidVerification.valid, true);
  assert.equal(cidVerification.expectedCid, dagCborCid);
  assert.equal(cidVerification.actualCid, dagCborCid);

  const tampered = new Uint8Array(dagCborBytes);
  tampered[tampered.length - 1] ^= 1;
  assert.equal(ReallyMeCodecs.dagCborVerifyCid(dagCborCid, tampered).valid, false);
});

test("WASM multicodec table matches shared prefix vectors", () => {
  const entries = codecsVector.multicodec_prefixes;
  assert.equal(Array.isArray(entries), true);

  for (const entry of entries) {
    const name = vectorString(entry, "name");
    const alg = vectorString(entry, "alg");
    const prefix = base64UrlBytes(vectorString(entry, "prefix"));
    const metadata = ReallyMeCodecs.multicodecPrefixForName(name);
    const lookup = ReallyMeCodecs.multicodecLookupPrefix(prefix);

    assert.equal(metadata.name, name);
    assert.equal(metadata.alg, alg);
    assert.deepEqual(metadata.prefix, prefix);
    assert.equal(lookup.name, name);
    assert.equal(lookup.alg, alg);
    assert.deepEqual(lookup.prefix, prefix);
  }
});

test("WASM multikey round-trips the shared public key vector", () => {
  const codecName = vectorString(codecsVector, "multicodec_name");
  const algorithmName = vectorString(codecsVector, "multicodec_alg");
  const multikey = vectorString(codecsVector, "multikey");
  const parsed = ReallyMeCodecs.multikeyParse(multikey);

  assert.equal(parsed.codecName, codecName);
  assert.equal(parsed.algorithmName, algorithmName);
  assert.equal(parsed.expectedPublicKeyLength, 32);
  assert.equal(parsed.publicKey.length, 32);
  assert.equal(ReallyMeCodecs.multikeyEncode(codecName, parsed.publicKey), multikey);
});

test("JWK vectors match the TypeScript package facade", () => {
  assert.ok(Array.isArray(jwkVector.vectors));
  for (const vector of jwkVector.vectors) {
    const alg = vectorString(vector, "alg");
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const expectedJcs = vectorString(vector, "jwk_jcs");

    assert.equal(publicKey.length, vectorNumber(vector, "public_key_length"));
    const jwk = ReallyMeJwk.toJwk(alg, publicKey);
    assert.equal(ReallyMeJwk.toJcs(jwk), expectedJcs);

    const parsed = ReallyMeJwk.fromJwk(JSON.parse(expectedJcs));
    assert.equal(parsed.algorithm, alg);
    assert.deepEqual(parsed.publicKey, publicKey);
    assert.equal(ReallyMeJwk.toJcs(parsed.jwk), expectedJcs);
  }
});

test("WASM codecs reject malformed inputs deterministically", () => {
  assert.throws(
    () => ReallyMeCodecs.base64urlDecode("AA="),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCodecs.multibaseDecode("xnot-supported"),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCodecs.multicodecPrefixForName("not-a-codec"),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
  assert.throws(
    () => ReallyMeCodecs.multicodecLookupPrefix(new Uint8Array([0xff, 0xff])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
  assert.throws(
    () => ReallyMeCodecs.multikeyEncode("ed25519-pub", new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCodecs.multikeyParse("z"),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("sha256 known answer", () => {
  assert.equal(
    hex(ReallyMeDigest.sha256(new TextEncoder().encode("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("generic facade hashes supported SHA-2", () => {
  const input = new TextEncoder().encode("abc");

  assert.deepEqual(ReallyMeCrypto.hash("SHA2-256", input), ReallyMeDigest.sha256(input));
  assert.deepEqual(ReallyMeCrypto.hash("SHA2-384", input), ReallyMeDigest.sha384(input));
  assert.deepEqual(ReallyMeCrypto.hash("SHA2-512", input), ReallyMeDigest.sha512(input));
});

test("generic facade hashes supported SHA-3 known answers", () => {
  const input = new TextEncoder().encode("abc");

  assert.equal(
    hex(ReallyMeCrypto.hash("SHA3-224", input)),
    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
  );
  assert.equal(
    hex(ReallyMeCrypto.hash("SHA3-256", input)),
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
  );
  assert.equal(
    hex(ReallyMeCrypto.hash("SHA3-384", input)),
    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2" +
      "98d88cea927ac7f539f1edf228376d25",
  );
  assert.equal(
    hex(ReallyMeCrypto.hash("SHA3-512", input)),
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
  );
});

// HMAC key/message/tags are vectors/hmac.json (RFC 4231 test case 1) —
// the same KAT the conformance lanes prove.
test("generic facade HMAC known answers", () => {
  const key = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const message = bytes("4869205468657265");
  const sha256Tag = ReallyMeCrypto.authenticate("HMAC-SHA-256", key, message);
  const sha512Tag = ReallyMeCrypto.authenticate("HMAC-SHA-512", key, message);

  assert.equal(
    hex(sha256Tag),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  );
  assert.equal(
    hex(sha512Tag),
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd" +
      "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  );
  assert.equal(
    ReallyMeCrypto.verifyMac("HMAC-SHA-256", sha256Tag, key, message),
    true,
  );
  assert.equal(
    ReallyMeCrypto.verifyMac("HMAC-SHA-512", sha512Tag, key, message),
    true,
  );
});

test("generic facade HMAC rejects invalid input and tampering", () => {
  const key = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const message = bytes("4869205468657265");
  const tag = ReallyMeCrypto.authenticate("HMAC-SHA-256", key, message);
  tag[0] ^= 0x01;

  assert.equal(ReallyMeCrypto.verifyMac("HMAC-SHA-256", tag, key, message), false);
  assert.throws(
    () => ReallyMeCrypto.authenticate("HMAC-SHA-256", new Uint8Array(), message),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.verifyMac("HMAC-SHA-256", new Uint8Array(1), key, message),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("generic facade PBKDF2 known answers", () => {
  const password = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("salt");

  assert.equal(
    hex(ReallyMeCrypto.deriveKey("PBKDF2-HMAC-SHA-256", password, salt, 4096, 32)),
    "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
  );
  assert.equal(
    hex(ReallyMeCrypto.deriveKey("PBKDF2-HMAC-SHA-512", password, salt, 4096, 64)),
    "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5" +
      "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
  );
});

test("generic facade PBKDF2 rejects invalid inputs and unsupported KDF", () => {
  const password = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("salt");

  assert.throws(
    () => ReallyMeCrypto.deriveKey("PBKDF2-HMAC-SHA-256", new Uint8Array(), salt, 4096, 32),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKey("PBKDF2-HMAC-SHA-256", password, new Uint8Array(), 4096, 32),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKey("PBKDF2-HMAC-SHA-256", password, salt, 0, 32),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKey("HKDF-SHA256", password, salt, 1, 32),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
});

test("generic facade HKDF known answer", () => {
  const inputKeyMaterial = bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  const salt = bytes("000102030405060708090a0b0c");
  const info = bytes("f0f1f2f3f4f5f6f7f8f9");

  assert.equal(
    hex(ReallyMeCrypto.deriveHkdf("HKDF-SHA256", inputKeyMaterial, salt, info, 42)),
    "3cb25f25faacd57a90434f64d0362f2a" +
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
      "34007208d5b887185865",
  );
});

test("generic facade HKDF rejects invalid inputs and unsupported KDF", () => {
  const salt = bytes("000102030405060708090a0b0c");
  const info = bytes("f0f1f2f3f4f5f6f7f8f9");

  assert.throws(
    () => ReallyMeCrypto.deriveHkdf("HKDF-SHA256", new Uint8Array(), salt, info, 42),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveHkdf("HKDF-SHA256", new Uint8Array([0x0b]), salt, info, 0),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.deriveHkdf(
        "PBKDF2-HMAC-SHA-256",
        new Uint8Array([0x0b]),
        salt,
        info,
        42,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
});

test("generic facade JWA Concat KDF matches shared vector", () => {
  const sharedSecret = base64UrlBytes(vectorString(concatKdfVector, "shared_secret"));
  const algorithmId = base64UrlBytes(vectorString(concatKdfVector, "algorithm_id"));
  const partyUInfo = base64UrlBytes(vectorString(concatKdfVector, "party_u_info"));
  const partyVInfo = base64UrlBytes(vectorString(concatKdfVector, "party_v_info"));
  const expected = base64UrlBytes(vectorString(concatKdfVector, "derived_key"));
  const outputLength = vectorNumber(concatKdfVector, "output_len");

  assert.deepEqual(
    ReallyMeJwaConcatKdf.deriveSha256(
      sharedSecret,
      algorithmId,
      partyUInfo,
      partyVInfo,
      outputLength,
    ),
    expected,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveJwaConcatKdfSha256(
      "JWA-CONCAT-KDF-SHA256",
      sharedSecret,
      algorithmId,
      partyUInfo,
      partyVInfo,
      outputLength,
    ),
    expected,
  );
});

test("generic facade JWA Concat KDF rejects invalid inputs and unsupported KDF", () => {
  const sharedSecret = base64UrlBytes(vectorString(concatKdfVector, "shared_secret"));
  const algorithmId = base64UrlBytes(vectorString(concatKdfVector, "algorithm_id"));
  const partyUInfo = base64UrlBytes(vectorString(concatKdfVector, "party_u_info"));
  const partyVInfo = base64UrlBytes(vectorString(concatKdfVector, "party_v_info"));

  assert.throws(
    () =>
      ReallyMeCrypto.deriveJwaConcatKdfSha256(
        "JWA-CONCAT-KDF-SHA256",
        new Uint8Array(),
        algorithmId,
        partyUInfo,
        partyVInfo,
        16,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.deriveJwaConcatKdfSha256(
        "JWA-CONCAT-KDF-SHA256",
        sharedSecret,
        new Uint8Array(),
        partyUInfo,
        partyVInfo,
        16,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.deriveJwaConcatKdfSha256(
        "JWA-CONCAT-KDF-SHA256",
        sharedSecret,
        algorithmId,
        partyUInfo,
        partyVInfo,
        0,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.deriveJwaConcatKdfSha256(
        "HKDF-SHA256",
        sharedSecret,
        algorithmId,
        partyUInfo,
        partyVInfo,
        16,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
});

test("argon2id known answer derives through WASM", () => {
  const secret = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("somesaltvalue1234");
  const expected = bytes(
    "53334265f014b5a46f2b3fce4de2c965669b6cd3a4879366385dfc301c234757",
  );

  assert.deepEqual(ReallyMeArgon2id.deriveKey(1, secret, salt), expected);
  assert.deepEqual(ReallyMeCrypto.deriveKey("Argon2id", secret, salt, 1, 32), expected);
});

test("argon2id shared vector derives through WASM", () => {
  const secret = base64UrlBytes(vectorString(argon2idVector, "secret"));
  const salt = base64UrlBytes(vectorString(argon2idVector, "salt"));
  const expected = base64UrlBytes(vectorString(argon2idVector, "derived_key"));

  assert.deepEqual(ReallyMeArgon2id.deriveKey(1, secret, salt), expected);
  assert.deepEqual(ReallyMeCrypto.deriveKey("Argon2id", secret, salt, 1, 32), expected);
});

test("aes-256-gcm-siv shared vector seals and opens through WASM", () => {
  const key = base64UrlBytes(vectorString(aes256GcmSivVector, "key"));
  const nonce = base64UrlBytes(vectorString(aes256GcmSivVector, "nonce"));
  const aad = base64UrlBytes(vectorString(aes256GcmSivVector, "aad"));
  const plaintext = base64UrlBytes(vectorString(aes256GcmSivVector, "plaintext"));
  const ciphertextWithTag = base64UrlBytes(
    vectorString(aes256GcmSivVector, "ciphertext_with_tag"),
  );

  // GCM-SIV is deterministic, so sealing must reproduce the committed bytes.
  assert.deepEqual(
    ReallyMeCrypto.seal("AES-256-GCM-SIV", key, nonce, aad, plaintext),
    ciphertextWithTag,
  );
  assert.deepEqual(
    ReallyMeCrypto.open("AES-256-GCM-SIV", key, nonce, aad, ciphertextWithTag),
    plaintext,
  );

  const tampered = Uint8Array.from(ciphertextWithTag);
  tampered[tampered.length - 1] ^= 0x01;
  assert.throws(
    () => ReallyMeCrypto.open("AES-256-GCM-SIV", key, nonce, aad, tampered),
    (error) => error instanceof ReallyMeCryptoError && error.code === "provider-failure",
  );
});

test("argon2id rejects invalid inputs through typed errors", () => {
  const secret = new TextEncoder().encode("password");
  const salt = new TextEncoder().encode("somesaltvalue1234");

  assert.throws(
    () => ReallyMeArgon2id.deriveKey(99, secret, salt),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeArgon2id.deriveKey(1, new Uint8Array(), salt),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeArgon2id.deriveKey(1, secret, new Uint8Array(15)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("aead vectors seal and open through WASM", () => {
  const cases = [
    {
      algorithm: "AES-128-GCM",
      vector: aes128GcmVector,
    },
    {
      algorithm: "AES-192-GCM",
      vector: aes192GcmVector,
    },
    {
      algorithm: "AES-256-GCM",
      vector: aes256GcmVector,
    },
    {
      algorithm: "ChaCha20-Poly1305",
      vector: chachaCase("chacha20_poly1305"),
    },
    {
      algorithm: "XChaCha20-Poly1305",
      vector: chachaCase("xchacha20_poly1305"),
    },
  ];

  for (const testCase of cases) {
    const key = base64UrlBytes(vectorString(testCase.vector, "key"));
    const nonce = base64UrlBytes(vectorString(testCase.vector, "nonce"));
    const aad = base64UrlBytes(vectorString(testCase.vector, "aad"));
    const plaintext = base64UrlBytes(vectorString(testCase.vector, "plaintext"));
    const ciphertextWithTag = base64UrlBytes(
      vectorString(testCase.vector, "ciphertext_with_tag"),
    );

    assert.deepEqual(
      ReallyMeCrypto.seal(testCase.algorithm, key, nonce, aad, plaintext),
      ciphertextWithTag,
    );
    assert.deepEqual(
      ReallyMeCrypto.open(testCase.algorithm, key, nonce, aad, ciphertextWithTag),
      plaintext,
    );

    // A one-bit flip of the authentication tag must be rejected.
    const tamperedTag = Uint8Array.from(ciphertextWithTag);
    tamperedTag[tamperedTag.length - 1] ^= 0x01;
    assert.throws(
      () => ReallyMeCrypto.open(testCase.algorithm, key, nonce, aad, tamperedTag),
      (error) =>
        error instanceof ReallyMeCryptoError && error.code === "provider-failure",
      `${testCase.algorithm} tag tamper`,
    );

    // A one-bit flip of the AAD must also break authentication.
    if (aad.length > 0) {
      const tamperedAad = Uint8Array.from(aad);
      tamperedAad[0] ^= 0x01;
      assert.throws(
        () =>
          ReallyMeCrypto.open(testCase.algorithm, key, nonce, tamperedAad, ciphertextWithTag),
        (error) =>
          error instanceof ReallyMeCryptoError && error.code === "provider-failure",
        `${testCase.algorithm} aad tamper`,
      );
    }
  }
});

test("aead rejects malformed and tampered inputs through typed errors", () => {
  const key = base64UrlBytes(vectorString(aes256GcmVector, "key"));
  const nonce = base64UrlBytes(vectorString(aes256GcmVector, "nonce"));
  const aad = base64UrlBytes(vectorString(aes256GcmVector, "aad"));
  const plaintext = base64UrlBytes(vectorString(aes256GcmVector, "plaintext"));
  const ciphertextWithTag = ReallyMeCrypto.seal(
    "AES-256-GCM-SIV",
    key,
    nonce,
    aad,
    plaintext,
  );
  const tampered = Uint8Array.from(ciphertextWithTag);
  tampered[0] ^= 0x01;

  assert.deepEqual(
    ReallyMeCrypto.open("AES-256-GCM-SIV", key, nonce, aad, ciphertextWithTag),
    plaintext,
  );
  assert.throws(
    () => ReallyMeCrypto.seal("AES-256-GCM", new Uint8Array(31), nonce, aad, plaintext),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.seal(
        "AES-128-GCM",
        new Uint8Array(32),
        nonce,
        aad,
        plaintext,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.seal("AES-192-GCM", new Uint8Array(23), nonce, aad, plaintext),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.seal("XChaCha20-Poly1305", key, nonce, aad, plaintext),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.open("AES-256-GCM", key, nonce, aad, new Uint8Array(15)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.open("AES-256-GCM-SIV", key, nonce, aad, tampered),
    (error) => error instanceof ReallyMeCryptoError && error.code === "provider-failure",
  );
});

test("aes-kw vector wraps and unwraps through WASM", () => {
  const kek = base64UrlBytes(vectorString(aes256KwVector, "kek"));
  const keyData = base64UrlBytes(vectorString(aes256KwVector, "key_data"));
  const wrappedKey = base64UrlBytes(vectorString(aes256KwVector, "wrapped_key"));

  assert.deepEqual(ReallyMeCrypto.wrapKey("AES-256-KW", kek, keyData), wrappedKey);
  assert.deepEqual(ReallyMeCrypto.unwrapKey("AES-256-KW", kek, wrappedKey), keyData);
});

test("aes-kw rejects malformed and tampered inputs through typed errors", () => {
  const kek = base64UrlBytes(vectorString(aes256KwVector, "kek"));
  const keyData = base64UrlBytes(vectorString(aes256KwVector, "key_data"));
  const wrappedKey = ReallyMeCrypto.wrapKey("AES-256-KW", kek, keyData);
  const tampered = Uint8Array.from(wrappedKey);
  tampered[0] ^= 0x01;

  assert.throws(
    () => ReallyMeCrypto.wrapKey("AES-256-KW", new Uint8Array(31), keyData),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.wrapKey("AES-256-KW", kek, new Uint8Array(15)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.unwrapKey("AES-256-KW", kek, new Uint8Array(23)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.unwrapKey("AES-256-KW", kek, tampered),
    (error) => error instanceof ReallyMeCryptoError && error.code === "provider-failure",
  );
});

test("hpke vectors seal and open through WASM", () => {
  const cases = [
    {
      suite: "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
      caseName: "p256_sha256_aes256gcm",
      publicKeyLength: HPKE_P256_PUBLIC_KEY_LENGTH,
    },
    {
      suite: "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
      caseName: "x25519_sha256_chacha20poly1305",
      publicKeyLength: HPKE_X25519_PUBLIC_KEY_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = hpkeCase(testCase.caseName);
    const recipientSecretKey = base64UrlBytes(vectorString(vector, "recipient_secret_key"));
    const recipientPublicKey = base64UrlBytes(vectorString(vector, "recipient_public_key"));
    const encapsulationSeed = base64UrlBytes(vectorString(vector, "encaps_seed"));
    const info = base64UrlBytes(vectorString(vector, "info"));
    const aad = base64UrlBytes(vectorString(vector, "aad"));
    const plaintext = base64UrlBytes(vectorString(vector, "plaintext"));
    const encapsulatedKey = base64UrlBytes(vectorString(vector, "encapsulated_key"));
    const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));

    assert.equal(recipientPublicKey.length, testCase.publicKeyLength);

    const deterministic = sealHpkeBaseDeterministicallyForTest(
      testCase.suite,
      recipientPublicKey,
      encapsulationSeed,
      info,
      aad,
      plaintext,
    );
    assert.deepEqual(deterministic.encapsulatedKey, encapsulatedKey);
    assert.deepEqual(deterministic.ciphertext, ciphertext);
    assert.deepEqual(
      ReallyMeCrypto.openHpke(
        testCase.suite,
        recipientSecretKey,
        encapsulatedKey,
        info,
        aad,
        ciphertext,
      ),
      plaintext,
    );

    const randomized = ReallyMeCrypto.sealHpke(
      testCase.suite,
      recipientPublicKey,
      info,
      aad,
      plaintext,
    );
    assert.equal(randomized.encapsulatedKey.length, testCase.publicKeyLength);
    assert.equal(randomized.ciphertext.length, ciphertext.length);
    assert.deepEqual(
      ReallyMeCrypto.openHpke(
        testCase.suite,
        recipientSecretKey,
        randomized.encapsulatedKey,
        info,
        aad,
        randomized.ciphertext,
      ),
      plaintext,
    );
  }
});

test("hpke rejects malformed and tampered inputs through typed errors", () => {
  const vector = hpkeCase("p256_sha256_aes256gcm");
  const recipientSecretKey = base64UrlBytes(vectorString(vector, "recipient_secret_key"));
  const recipientPublicKey = base64UrlBytes(vectorString(vector, "recipient_public_key"));
  const info = base64UrlBytes(vectorString(vector, "info"));
  const aad = base64UrlBytes(vectorString(vector, "aad"));
  const plaintext = base64UrlBytes(vectorString(vector, "plaintext"));
  const encapsulatedKey = base64UrlBytes(vectorString(vector, "encapsulated_key"));
  const tamperedCiphertext = base64UrlBytes(vectorString(vector, "tampered_ciphertext"));

  assert.throws(
    () =>
      ReallyMeCrypto.sealHpke(
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        new Uint8Array(64),
        info,
        aad,
        plaintext,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.openHpke(
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        new Uint8Array(31),
        encapsulatedKey,
        info,
        aad,
        tamperedCiphertext,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      sealHpkeBaseDeterministicallyForTest(
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        recipientPublicKey,
        new Uint8Array(31),
        info,
        aad,
        plaintext,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeHpke.openBase(
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        recipientSecretKey,
        encapsulatedKey,
        info,
        aad,
        tamperedCiphertext,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "provider-failure",
  );
});

test("x-wing vectors derive, encapsulate, and decapsulate through WASM", () => {
  const cases = [
    {
      algorithm: "X-Wing-768",
      caseName: "x_wing_768",
      publicKeyLength: X_WING_768_PUBLIC_KEY_LENGTH,
      ciphertextLength: X_WING_768_CIPHERTEXT_LENGTH,
    },
    {
      algorithm: "X-Wing-1024",
      caseName: "x_wing_1024",
      publicKeyLength: X_WING_1024_PUBLIC_KEY_LENGTH,
      ciphertextLength: X_WING_1024_CIPHERTEXT_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = xWingCase(testCase.caseName);
    const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const encapsulationSeed = base64UrlBytes(vectorString(vector, "encaps_seed"));
    const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));
    const sharedSecret = base64UrlBytes(vectorString(vector, "shared_secret"));

    assert.equal(vectorNumber(vector, "public_key_length"), testCase.publicKeyLength);
    assert.equal(vectorNumber(vector, "ciphertext_length"), testCase.ciphertextLength);

    const keyPair = ReallyMeXWing.deriveKeyPair(testCase.algorithm, secretKey);
    assert.equal(keyPair.secretKey.length, X_WING_SECRET_KEY_LENGTH);
    assert.deepEqual(keyPair.secretKey, secretKey);
    assert.deepEqual(keyPair.publicKey, publicKey);

    const encapsulation = ReallyMeCrypto.encapsulate(testCase.algorithm, publicKey);
    assert.equal(encapsulation.ciphertext.length, testCase.ciphertextLength);
    assert.equal(encapsulation.sharedSecret.length, X_WING_SHARED_SECRET_LENGTH);
    assert.deepEqual(
      ReallyMeCrypto.decapsulate(testCase.algorithm, encapsulation.ciphertext, secretKey),
      encapsulation.sharedSecret,
    );

    const deterministic = encapsulateXWingDeterministicallyForTest(
      testCase.algorithm,
      publicKey,
      encapsulationSeed,
    );
    assert.deepEqual(deterministic.ciphertext, ciphertext);
    assert.deepEqual(deterministic.sharedSecret, sharedSecret);
    assert.deepEqual(
      ReallyMeCrypto.decapsulate(testCase.algorithm, ciphertext, secretKey),
      sharedSecret,
    );
  }
});

test("x-wing rejects malformed inputs through typed errors", () => {
  const vector = xWingCase("x_wing_768");
  const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
  const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
  const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));

  assert.throws(
    () => ReallyMeXWing.deriveKeyPair("X-Wing-768", new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.encapsulate("X-Wing-768", new Uint8Array(1_215)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.decapsulate("X-Wing-768", new Uint8Array(1_119), secretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.decapsulate("X-Wing-768", ciphertext, new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      encapsulateXWingDeterministicallyForTest(
        "X-Wing-768",
        publicKey,
        new Uint8Array(63),
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("ml-kem vectors decapsulate and roundtrip through WASM", () => {
  const cases = [
    {
      algorithm: "ML-KEM-512",
      publicKeyLength: ML_KEM_512_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_512_CIPHERTEXT_LENGTH,
    },
    {
      algorithm: "ML-KEM-768",
      publicKeyLength: ML_KEM_768_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_768_CIPHERTEXT_LENGTH,
    },
    {
      algorithm: "ML-KEM-1024",
      publicKeyLength: ML_KEM_1024_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_1024_CIPHERTEXT_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = mlKemCase(testCase.algorithm);
    const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));
    const sharedSecret = base64UrlBytes(vectorString(vector, "shared_secret"));
    const tamperedCiphertext = base64UrlBytes(
      vectorString(vector, "tampered_ciphertext"),
    );
    const tamperedSharedSecret = base64UrlBytes(
      vectorString(vector, "tampered_shared_secret"),
    );

    assert.equal(vectorNumber(vector, "public_key_length"), testCase.publicKeyLength);
    assert.equal(publicKey.length, testCase.publicKeyLength);
    assert.equal(secretKey.length, ML_KEM_SECRET_KEY_LENGTH);
    assert.equal(ciphertext.length, testCase.ciphertextLength);

    assert.deepEqual(
      ReallyMeCrypto.decapsulate(testCase.algorithm, ciphertext, secretKey),
      sharedSecret,
    );
    assert.deepEqual(
      ReallyMeCrypto.decapsulate(testCase.algorithm, tamperedCiphertext, secretKey),
      tamperedSharedSecret,
    );

    const generated = ReallyMeCrypto.generateKemKeyPair(testCase.algorithm);
    assert.equal(generated.publicKey.length, testCase.publicKeyLength);
    assert.equal(generated.secretKey.length, ML_KEM_SECRET_KEY_LENGTH);

    const encapsulation = ReallyMeCrypto.encapsulate(testCase.algorithm, generated.publicKey);
    assert.equal(encapsulation.ciphertext.length, testCase.ciphertextLength);
    assert.equal(encapsulation.sharedSecret.length, ML_KEM_SHARED_SECRET_LENGTH);
    assert.deepEqual(
      ReallyMeCrypto.decapsulate(
        testCase.algorithm,
        encapsulation.ciphertext,
        generated.secretKey,
      ),
      encapsulation.sharedSecret,
    );
  }
});

test("ml-kem rejects malformed inputs through typed errors", () => {
  const vector = mlKemCase("ML-KEM-768");
  const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
  const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
  const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));

  assert.throws(
    () => ReallyMeMlKem.encapsulate("ML-KEM-768", new Uint8Array(1_183)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.decapsulate("ML-KEM-768", new Uint8Array(1_087), secretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.decapsulate("ML-KEM-768", ciphertext, new Uint8Array(63)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.deepEqual(
    ReallyMeCrypto.decapsulate("ML-KEM-768", ciphertext, secretKey),
    ReallyMeMlKem.decapsulate("ML-KEM-768", ciphertext, secretKey),
  );
  assert.equal(publicKey.length, ML_KEM_768_PUBLIC_KEY_LENGTH);
});

test("ml-kem derives vector keypairs and deterministic encapsulations through WASM", () => {
  const cases = [
    {
      algorithm: "ML-KEM-512",
      publicKeyLength: ML_KEM_512_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_512_CIPHERTEXT_LENGTH,
    },
    {
      algorithm: "ML-KEM-768",
      publicKeyLength: ML_KEM_768_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_768_CIPHERTEXT_LENGTH,
    },
    {
      algorithm: "ML-KEM-1024",
      publicKeyLength: ML_KEM_1024_PUBLIC_KEY_LENGTH,
      ciphertextLength: ML_KEM_1024_CIPHERTEXT_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = mlKemCase(testCase.algorithm);
    const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const randomness = base64UrlBytes(vectorString(vector, "encaps_randomness"));
    const ciphertext = base64UrlBytes(vectorString(vector, "ciphertext"));
    const sharedSecret = base64UrlBytes(vectorString(vector, "shared_secret"));
    const first = ReallyMeMlKem.deriveKeyPair(testCase.algorithm, secretKey);
    const second = ReallyMeMlKem.deriveKeyPair(testCase.algorithm, secretKey);

    assert.deepEqual(first, second);
    assert.equal(first.publicKey.length, testCase.publicKeyLength);
    assert.deepEqual(first.publicKey, publicKey);
    assert.deepEqual(first.secretKey, secretKey);
    assert.equal(randomness.length, ML_KEM_ENCAPSULATION_RANDOMNESS_LENGTH);

    const firstEncapsulation = ReallyMeMlKem.encapsulateDeterministicallyForTest(
      testCase.algorithm,
      first.publicKey,
      randomness,
    );
    const secondEncapsulation = ReallyMeMlKem.encapsulateDeterministicallyForTest(
      testCase.algorithm,
      first.publicKey,
      randomness,
    );
    assert.deepEqual(firstEncapsulation, secondEncapsulation);
    assert.deepEqual(firstEncapsulation.ciphertext, ciphertext);
    assert.deepEqual(firstEncapsulation.sharedSecret, sharedSecret);
    assert.equal(firstEncapsulation.ciphertext.length, testCase.ciphertextLength);
    assert.deepEqual(
      ReallyMeMlKem.decapsulate(
        testCase.algorithm,
        firstEncapsulation.ciphertext,
        first.secretKey,
      ),
      firstEncapsulation.sharedSecret,
    );
  }

  assert.throws(
    () => ReallyMeMlKem.deriveKeyPair("ML-KEM-768", new Uint8Array(63)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeMlKem.encapsulateDeterministicallyForTest(
      "ML-KEM-768",
      new Uint8Array(ML_KEM_768_PUBLIC_KEY_LENGTH),
      new Uint8Array(31),
    ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("ml-dsa vectors sign and verify through WASM", () => {
  const cases = [
    {
      algorithm: "ML-DSA-44",
      publicKeyLength: ML_DSA_44_PUBLIC_KEY_LENGTH,
      signatureLength: ML_DSA_44_SIGNATURE_LENGTH,
    },
    {
      algorithm: "ML-DSA-65",
      publicKeyLength: ML_DSA_65_PUBLIC_KEY_LENGTH,
      signatureLength: ML_DSA_65_SIGNATURE_LENGTH,
    },
    {
      algorithm: "ML-DSA-87",
      publicKeyLength: ML_DSA_87_PUBLIC_KEY_LENGTH,
      signatureLength: ML_DSA_87_SIGNATURE_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = mlDsaCase(testCase.algorithm);
    const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const message = base64UrlBytes(vectorString(vector, "message"));
    const signature = base64UrlBytes(vectorString(vector, "signature"));

    assert.equal(vectorNumber(vector, "public_key_length"), testCase.publicKeyLength);
    assert.equal(publicKey.length, testCase.publicKeyLength);
    assert.equal(secretKey.length, ML_DSA_SECRET_KEY_LENGTH);
    assert.equal(signature.length, testCase.signatureLength);

    assert.deepEqual(
      ReallyMeCrypto.sign(testCase.algorithm, message, secretKey),
      signature,
    );
    ReallyMeCrypto.verify(testCase.algorithm, signature, message, publicKey);

    const generated = ReallyMeCrypto.generateKeyPair(testCase.algorithm);
    assert.equal(generated.publicKey.length, testCase.publicKeyLength);
    assert.equal(generated.secretKey.length, ML_DSA_SECRET_KEY_LENGTH);
    const generatedSignature = ReallyMeCrypto.sign(
      testCase.algorithm,
      message,
      generated.secretKey,
    );
    assert.equal(generatedSignature.length, testCase.signatureLength);
    ReallyMeCrypto.verify(
      testCase.algorithm,
      generatedSignature,
      message,
      generated.publicKey,
    );
  }
});

test("ml-dsa derives vector keypairs from supplied seeds through WASM", () => {
  const cases = [
    {
      algorithm: "ML-DSA-44",
      publicKeyLength: ML_DSA_44_PUBLIC_KEY_LENGTH,
    },
    {
      algorithm: "ML-DSA-65",
      publicKeyLength: ML_DSA_65_PUBLIC_KEY_LENGTH,
    },
    {
      algorithm: "ML-DSA-87",
      publicKeyLength: ML_DSA_87_PUBLIC_KEY_LENGTH,
    },
  ];

  for (const testCase of cases) {
    const vector = mlDsaCase(testCase.algorithm);
    const seed = base64UrlBytes(vectorString(vector, "secret_key"));
    const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
    const first = ReallyMeMlDsa.deriveKeyPair(testCase.algorithm, seed);
    const second = ReallyMeMlDsa.deriveKeyPair(testCase.algorithm, seed);
    const facade = ReallyMeCrypto.deriveKeyPair(testCase.algorithm, seed);

    assert.deepEqual(first, second);
    assert.equal(first.publicKey.length, testCase.publicKeyLength);
    assert.deepEqual(first.publicKey, publicKey);
    assert.deepEqual(first.secretKey, seed);
    assert.deepEqual(facade.publicKey, publicKey);
    assert.deepEqual(facade.secretKey, seed);
  }

  assert.throws(
    () => ReallyMeMlDsa.deriveKeyPair("ML-DSA-65", new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("ml-dsa rejects tampered and malformed inputs through typed errors", () => {
  const vector = mlDsaCase("ML-DSA-65");
  const secretKey = base64UrlBytes(vectorString(vector, "secret_key"));
  const publicKey = base64UrlBytes(vectorString(vector, "public_key"));
  const message = base64UrlBytes(vectorString(vector, "message"));
  const signature = base64UrlBytes(vectorString(vector, "signature"));
  const tamperedSignature = Uint8Array.from(signature);
  tamperedSignature[0] ^= 0x01;

  assertReallyMeError(
    () => ReallyMeMlDsa.verify("ML-DSA-65", tamperedSignature, message, publicKey),
    "invalid-signature",
  );
  assert.throws(
    () => ReallyMeCrypto.sign("ML-DSA-65", message, new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.verify("ML-DSA-65", signature, message, new Uint8Array(1_951)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.verify("ML-DSA-65", new Uint8Array(3_308), message, publicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.deepEqual(
    ReallyMeMlDsa.sign("ML-DSA-65", message, secretKey),
    signature,
  );
});

test("slh-dsa vector derives, signs, and verifies through WASM", () => {
  const skSeed = base64UrlBytes(vectorString(slhDsaVector, "keygen_sk_seed"));
  const skPrf = base64UrlBytes(vectorString(slhDsaVector, "keygen_sk_prf"));
  const pkSeed = base64UrlBytes(vectorString(slhDsaVector, "keygen_pk_seed"));
  const secretKey = base64UrlBytes(vectorString(slhDsaVector, "secret_key"));
  const publicKey = base64UrlBytes(vectorString(slhDsaVector, "public_key"));
  const message = base64UrlBytes(vectorString(slhDsaVector, "message"));
  const signature = base64UrlBytes(vectorString(slhDsaVector, "signature"));

  assert.equal(skSeed.length, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  assert.equal(skPrf.length, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  assert.equal(pkSeed.length, SLH_DSA_SHA2_128S_KEYGEN_SEED_LENGTH);
  assert.equal(vectorNumber(slhDsaVector, "public_key_length"), publicKey.length);
  assert.equal(vectorNumber(slhDsaVector, "secret_key_length"), secretKey.length);
  assert.equal(vectorNumber(slhDsaVector, "signature_length"), signature.length);

  const derived = deriveSlhDsaSha2128sKeypairForTest(skSeed, skPrf, pkSeed);
  assert.deepEqual(derived.publicKey, publicKey);
  assert.deepEqual(derived.secretKey, secretKey);
  assert.equal(publicKey.length, SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH);
  assert.equal(secretKey.length, SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH);
  assert.equal(signature.length, SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);

  assert.deepEqual(
    ReallyMeCrypto.sign("SLH-DSA-SHA2-128s", message, secretKey),
    signature,
  );
  ReallyMeCrypto.verify("SLH-DSA-SHA2-128s", signature, message, publicKey);

  const generated = ReallyMeCrypto.generateKeyPair("SLH-DSA-SHA2-128s");
  assert.equal(generated.publicKey.length, SLH_DSA_SHA2_128S_PUBLIC_KEY_LENGTH);
  assert.equal(generated.secretKey.length, SLH_DSA_SHA2_128S_SECRET_KEY_LENGTH);
  const generatedSignature = ReallyMeCrypto.sign(
    "SLH-DSA-SHA2-128s",
    message,
    generated.secretKey,
  );
  assert.equal(generatedSignature.length, SLH_DSA_SHA2_128S_SIGNATURE_LENGTH);
  ReallyMeCrypto.verify(
    "SLH-DSA-SHA2-128s",
    generatedSignature,
    message,
    generated.publicKey,
  );
});

test("slh-dsa rejects tampered and malformed inputs through typed errors", () => {
  const publicKey = base64UrlBytes(vectorString(slhDsaVector, "public_key"));
  const secretKey = base64UrlBytes(vectorString(slhDsaVector, "secret_key"));
  const message = base64UrlBytes(vectorString(slhDsaVector, "message"));
  const signature = base64UrlBytes(vectorString(slhDsaVector, "signature"));
  const tamperedSignature = Uint8Array.from(signature);
  tamperedSignature[0] ^= 0x01;

  assertReallyMeError(
    () =>
      ReallyMeSlhDsa.verify(
        "SLH-DSA-SHA2-128s",
        tamperedSignature,
        message,
        publicKey,
      ),
    "invalid-signature",
  );
  assert.throws(
    () => ReallyMeCrypto.sign("SLH-DSA-SHA2-128s", message, new Uint8Array(63)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.verify(
        "SLH-DSA-SHA2-128s",
        signature,
        message,
        new Uint8Array(31),
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeCrypto.verify(
        "SLH-DSA-SHA2-128s",
        new Uint8Array(7_855),
        message,
        publicKey,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      deriveSlhDsaSha2128sKeypairForTest(
        new Uint8Array(15),
        new Uint8Array(16),
        new Uint8Array(16),
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.deepEqual(
    ReallyMeSlhDsa.sign("SLH-DSA-SHA2-128s", message, secretKey),
    signature,
  );
  // SLH-DSA derivation needs three FIPS seed components, so the facade's
  // single-secret deriveKeyPair deliberately reports it as unsupported.
  assertUnsupportedAlgorithm(() =>
    ReallyMeCrypto.deriveKeyPair("SLH-DSA-SHA2-128s", secretKey),
  );
});

test("generic facade returns typed unsupported algorithm", () => {
  assertUnsupportedAlgorithm(() => ReallyMeCrypto.generateKeyPair("RSA-PKCS1v15-SHA1"));
});

test("generic facade supported algorithm sets are explicit", () => {
  assert.deepEqual(
    [...REALLYME_HASH_ALGORITHMS],
    [
      "SHA2-256",
      "SHA2-384",
      "SHA2-512",
      "SHA3-224",
      "SHA3-256",
      "SHA3-384",
      "SHA3-512",
    ],
  );
  assert.deepEqual([...REALLYME_MAC_ALGORITHMS], ["HMAC-SHA-256", "HMAC-SHA-512"]);
  assert.deepEqual(
    [...REALLYME_KEY_AGREEMENT_ALGORITHMS],
    ["X25519", "P-256-ECDH", "P-384-ECDH", "P-521-ECDH"],
  );
});

test("generic facade unsupported signatures are exhaustive", () => {
  const empty = new Uint8Array();
  const generateSupported = new Set([
    "Ed25519",
    "ECDSA-P256-SHA256",
    "ECDSA-P384-SHA384",
    "ECDSA-P521-SHA512",
    "ECDSA-secp256k1-SHA256",
    "BIP340-Schnorr-secp256k1-SHA256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
  ]);
  const signSupported = new Set([
    "Ed25519",
    "ECDSA-P256-SHA256",
    "ECDSA-P384-SHA384",
    "ECDSA-P521-SHA512",
    "ECDSA-secp256k1-SHA256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
  ]);
  const verifySupported = new Set([
    "Ed25519",
    "ECDSA-P256-SHA256",
    "ECDSA-P384-SHA384",
    "ECDSA-P521-SHA512",
    "ECDSA-secp256k1-SHA256",
    "BIP340-Schnorr-secp256k1-SHA256",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
  ]);

  for (const algorithm of REALLYME_SIGNATURE_ALGORITHMS) {
    if (!generateSupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.generateKeyPair(algorithm));
    }
    if (!signSupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.sign(algorithm, empty, empty));
    }
    if (!verifySupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.verify(algorithm, empty, empty, empty));
    }
  }
});

test("generic facade unsupported reserved families are exhaustive", () => {
  const empty = new Uint8Array();
  const supportedKem = new Set([
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "X-Wing-768",
    "X-Wing-1024",
  ]);
  assert.deepEqual(
    [...REALLYME_AEAD_ALGORITHMS],
    [
      "AES-128-GCM",
      "AES-192-GCM",
      "AES-256-GCM",
      "AES-256-GCM-SIV",
      "ChaCha20-Poly1305",
      "XChaCha20-Poly1305",
    ],
  );

  for (const algorithm of REALLYME_KEM_ALGORITHMS) {
    if (!supportedKem.has(algorithm)) {
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.generateKemKeyPair(algorithm));
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.encapsulate(algorithm, empty));
      assertUnsupportedAlgorithm(() => ReallyMeCrypto.decapsulate(algorithm, empty, empty));
    }
  }

  assert.deepEqual([...REALLYME_KEY_WRAP_ALGORITHMS], ["AES-256-KW"]);

  assert.deepEqual(
    [...REALLYME_HPKE_SUITES],
    [
      "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
      "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
    ],
  );
});

test("generic facade unsupported KDF routes are exhaustive", () => {
  const empty = new Uint8Array();
  const deriveKeySupported = new Set([
    "Argon2id",
    "PBKDF2-HMAC-SHA-256",
    "PBKDF2-HMAC-SHA-512",
  ]);
  const deriveHkdfSupported = new Set(["HKDF-SHA256"]);
  const deriveJwaConcatKdfSupported = new Set(["JWA-CONCAT-KDF-SHA256"]);

  for (const algorithm of REALLYME_KDF_ALGORITHMS) {
    if (!deriveKeySupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() =>
        ReallyMeCrypto.deriveKey(algorithm, empty, empty, 1, 1),
      );
    }

    if (!deriveHkdfSupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() =>
        ReallyMeCrypto.deriveHkdf(algorithm, empty, empty, empty, 1),
      );
    }

    if (!deriveJwaConcatKdfSupported.has(algorithm)) {
      assertUnsupportedAlgorithm(() =>
        ReallyMeCrypto.deriveJwaConcatKdfSha256(algorithm, empty, empty, empty, empty, 1),
      );
    }
  }
});

test("ed25519 derive public key known answer", () => {
  assert.deepEqual(
    ReallyMeEd25519.derivePublicKey(ed25519SecretKey),
    ed25519PublicKey,
  );

  const keyPair = ReallyMeCrypto.deriveKeyPair("Ed25519", ed25519SecretKey);
  assert.deepEqual(keyPair.publicKey, ed25519PublicKey);
  assert.deepEqual(keyPair.secretKey, ed25519SecretKey);
});

test("ed25519 sign is deterministic, cross-lane KAT, and verifies", () => {
  const first = ReallyMeEd25519.sign(ed25519Message, ed25519SecretKey);
  const second = ReallyMeEd25519.sign(ed25519Message, ed25519SecretKey);

  assert.deepEqual(first, second, "Ed25519 signatures must be deterministic");
  assert.equal(first.length, ED25519_SIGNATURE_LENGTH);
  assert.deepEqual(first, ed25519Signature);
  ReallyMeEd25519.verify(first, ed25519Message, ed25519PublicKey);
});

test("generic facade ed25519 known answer", () => {
  const signature = ReallyMeCrypto.sign(
    "Ed25519",
    ed25519Message,
    ed25519SecretKey,
  );

  assert.deepEqual(signature, ed25519Signature);
  ReallyMeCrypto.verify(
    "Ed25519",
    signature,
    ed25519Message,
    ed25519PublicKey,
  );
});

test("ed25519 rejects tampered signature and message", () => {
  const extended = new Uint8Array([...ed25519Message, 0x00]);
  assertReallyMeError(
    () => ReallyMeEd25519.verify(ed25519Signature, extended, ed25519PublicKey),
    "invalid-signature",
  );

  const flipped = Uint8Array.from(ed25519Signature);
  flipped[10] ^= 0xff;
  assertReallyMeError(
    () => ReallyMeEd25519.verify(flipped, ed25519Message, ed25519PublicKey),
    "invalid-signature",
  );
});

test("ed25519 rejects malformed inputs", () => {
  assert.throws(
    () => ReallyMeEd25519.sign(ed25519Message, new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeEd25519.derivePublicKey(new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyPair("Ed25519", new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeEd25519.verify(new Uint8Array(63), ed25519Message, ed25519PublicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeEd25519.verify(ed25519Signature, ed25519Message, new Uint8Array(31)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("ed25519 generate keypair round trip", () => {
  const { publicKey, secretKey } = ReallyMeCrypto.generateKeyPair("Ed25519");
  assert.equal(secretKey.length, 32);
  assert.equal(publicKey.length, 32);

  const signature = ReallyMeCrypto.sign("Ed25519", ed25519Message, secretKey);
  ReallyMeCrypto.verify("Ed25519", signature, ed25519Message, publicKey);
});

test("x25519 derive public key known answer", () => {
  assert.deepEqual(
    ReallyMeX25519.derivePublicKey(x25519SecretKey),
    x25519PublicKey,
  );
  assert.deepEqual(
    ReallyMeX25519.derivePublicKey(x25519PeerSecretKey),
    x25519PeerPublicKey,
  );

  const keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
    "X25519",
    x25519SecretKey,
  );
  assert.deepEqual(keyPair.publicKey, x25519PublicKey);
  assert.deepEqual(keyPair.secretKey, x25519SecretKey);
});

test("x25519 derive shared secret known answer", () => {
  assert.deepEqual(
    ReallyMeX25519.deriveSharedSecret(x25519PeerPublicKey, x25519SecretKey),
    x25519SharedSecret,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveSharedSecret(
      "X25519",
      x25519PublicKey,
      x25519PeerSecretKey,
    ),
    x25519SharedSecret,
  );
});

test("x25519 rejects malformed inputs", () => {
  assert.throws(
    () => ReallyMeX25519.derivePublicKey(new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyAgreementKeyPair("X25519", new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeX25519.deriveSharedSecret(new Uint8Array(31), x25519SecretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeX25519.deriveSharedSecret(new Uint8Array(32), x25519SecretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("x25519 generate keypair round trip", () => {
  const alice = ReallyMeX25519.generateKeyPair();
  const bob = ReallyMeX25519.generateKeyPair();
  const aliceSecret = ReallyMeCrypto.deriveSharedSecret(
    "X25519",
    bob.publicKey,
    alice.secretKey,
  );
  const bobSecret = ReallyMeCrypto.deriveSharedSecret(
    "X25519",
    alice.publicKey,
    bob.secretKey,
  );

  assert.equal(aliceSecret.length, X25519_SHARED_SECRET_LENGTH);
  assert.deepEqual(aliceSecret, bobSecret);
});

test("p256 ecdh known answer", () => {
  assert.deepEqual(
    ReallyMeP256Ecdh.derivePublicKey(p256EcdhSecretKey),
    p256EcdhPublicKey,
  );
  assert.deepEqual(
    ReallyMeP256Ecdh.deriveSharedSecret(
      p256EcdhPeerPublicKey,
      p256EcdhSecretKey,
    ),
    p256EcdhSharedSecret,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveSharedSecret(
      "P-256-ECDH",
      p256EcdhPublicKey,
      p256EcdhPeerSecretKey,
    ),
    p256EcdhSharedSecret,
  );

  const keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
    "P-256-ECDH",
    p256EcdhSecretKey,
  );
  assert.deepEqual(keyPair.publicKey, p256EcdhPublicKey);
  assert.deepEqual(keyPair.secretKey, p256EcdhSecretKey);
});

test("p256 ecdh rejects malformed inputs", () => {
  assert.throws(
    () => ReallyMeP256Ecdh.derivePublicKey(new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyAgreementKeyPair("P-256-ECDH", new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeP256Ecdh.deriveSharedSecret(new Uint8Array(33), p256EcdhSecretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("p256 ecdh generate keypair round trip", () => {
  const alice = ReallyMeP256Ecdh.generateKeyPair();
  const bob = ReallyMeP256Ecdh.generateKeyPair();
  const aliceSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-256-ECDH",
    bob.publicKey,
    alice.secretKey,
  );
  const bobSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-256-ECDH",
    alice.publicKey,
    bob.secretKey,
  );

  assert.equal(aliceSecret.length, P256_ECDH_SHARED_SECRET_LENGTH);
  assert.deepEqual(aliceSecret, bobSecret);
});

test("p384 ecdh known answer", () => {
  assert.deepEqual(
    ReallyMeP384Ecdh.derivePublicKey(p384EcdhSecretKey),
    p384EcdhPublicKey,
  );
  assert.deepEqual(
    ReallyMeP384Ecdh.deriveSharedSecret(
      p384EcdhPeerPublicKey,
      p384EcdhSecretKey,
    ),
    p384EcdhSharedSecret,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveSharedSecret(
      "P-384-ECDH",
      p384EcdhPublicKey,
      p384EcdhPeerSecretKey,
    ),
    p384EcdhSharedSecret,
  );

  const keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
    "P-384-ECDH",
    p384EcdhSecretKey,
  );
  assert.deepEqual(keyPair.publicKey, p384EcdhPublicKey);
  assert.deepEqual(keyPair.secretKey, p384EcdhSecretKey);
});

test("p384 ecdh rejects malformed inputs", () => {
  assert.throws(
    () => ReallyMeP384Ecdh.derivePublicKey(new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyAgreementKeyPair("P-384-ECDH", new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeP384Ecdh.deriveSharedSecret(new Uint8Array(49), p384EcdhSecretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("p384 ecdh generate keypair round trip", () => {
  const alice = ReallyMeP384Ecdh.generateKeyPair();
  const bob = ReallyMeP384Ecdh.generateKeyPair();
  const aliceSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-384-ECDH",
    bob.publicKey,
    alice.secretKey,
  );
  const bobSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-384-ECDH",
    alice.publicKey,
    bob.secretKey,
  );

  assert.equal(aliceSecret.length, P384_ECDH_SHARED_SECRET_LENGTH);
  assert.deepEqual(aliceSecret, bobSecret);
});

test("p521 ecdh known answer", () => {
  assert.deepEqual(
    ReallyMeP521Ecdh.derivePublicKey(p521EcdhSecretKey),
    p521EcdhPublicKey,
  );
  assert.deepEqual(
    ReallyMeP521Ecdh.deriveSharedSecret(
      p521EcdhPeerPublicKey,
      p521EcdhSecretKey,
    ),
    p521EcdhSharedSecret,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveSharedSecret(
      "P-521-ECDH",
      p521EcdhPublicKey,
      p521EcdhPeerSecretKey,
    ),
    p521EcdhSharedSecret,
  );

  const keyPair = ReallyMeCrypto.deriveKeyAgreementKeyPair(
    "P-521-ECDH",
    p521EcdhSecretKey,
  );
  assert.deepEqual(keyPair.publicKey, p521EcdhPublicKey);
  assert.deepEqual(keyPair.secretKey, p521EcdhSecretKey);
});

test("p521 ecdh rejects malformed inputs", () => {
  assert.throws(
    () => ReallyMeP521Ecdh.derivePublicKey(new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyAgreementKeyPair("P-521-ECDH", new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeP521Ecdh.deriveSharedSecret(new Uint8Array(67), p521EcdhSecretKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("p521 ecdh generate keypair round trip", () => {
  const alice = ReallyMeP521Ecdh.generateKeyPair();
  const bob = ReallyMeP521Ecdh.generateKeyPair();
  const aliceSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-521-ECDH",
    bob.publicKey,
    alice.secretKey,
  );
  const bobSecret = ReallyMeCrypto.deriveSharedSecret(
    "P-521-ECDH",
    alice.publicKey,
    bob.secretKey,
  );

  assert.equal(aliceSecret.length, P521_ECDH_SHARED_SECRET_LENGTH);
  assert.deepEqual(aliceSecret, bobSecret);
});

test("p256 ecdsa known answer and facade parity", () => {
  assert.deepEqual(
    ReallyMeP256Ecdsa.derivePublicKey(p256EcdhSecretKey),
    p256EcdhPublicKey,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveKeyPair("ECDSA-P256-SHA256", p256EcdhSecretKey).publicKey,
    p256EcdhPublicKey,
  );

  const signature = ReallyMeP256Ecdsa.sign(p256EcdsaMessage, p256EcdhSecretKey);
  assert.deepEqual(signature, p256EcdsaSignature);
  ReallyMeP256Ecdsa.verify(signature, p256EcdsaMessage, p256EcdhPublicKey);

  assert.deepEqual(
    ReallyMeCrypto.sign("ECDSA-P256-SHA256", p256EcdsaMessage, p256EcdhSecretKey),
    p256EcdsaSignature,
  );
  ReallyMeCrypto.verify(
    "ECDSA-P256-SHA256",
    p256EcdsaSignature,
    p256EcdsaMessage,
    p256EcdhPublicKey,
  );
});

test("p256 ecdsa rejects tampering and malformed inputs", () => {
  const tamperedMessage = new Uint8Array([...p256EcdsaMessage, 0x00]);
  assertReallyMeError(
    () =>
      ReallyMeP256Ecdsa.verify(
        p256EcdsaSignature,
        tamperedMessage,
        p256EcdhPublicKey,
      ),
    "invalid-signature",
  );

  const tamperedSignature = Uint8Array.from(p256EcdsaSignature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  assertReallyMeError(
    () =>
      ReallyMeP256Ecdsa.verify(
        tamperedSignature,
        p256EcdsaMessage,
        p256EcdhPublicKey,
      ),
    "invalid-signature",
  );

  assert.throws(
    () => ReallyMeP256Ecdsa.sign(p256EcdsaMessage, new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeP256Ecdsa.verify(new Uint8Array(7), p256EcdsaMessage, p256EcdhPublicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  const invalidKey = Uint8Array.from(p256EcdhPublicKey);
  invalidKey[0] = 0x07;
  assert.throws(
    () =>
      ReallyMeP256Ecdsa.verify(
        p256EcdsaSignature,
        p256EcdsaMessage,
        invalidKey,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("p256 ecdsa generate keypair round trip", () => {
  const { publicKey, secretKey } = ReallyMeP256Ecdsa.generateKeyPair();
  const message = new TextEncoder().encode("fresh p256 keypair");
  const signature = ReallyMeP256Ecdsa.sign(message, secretKey);

  assert.equal(publicKey.length, 33);
  assert.equal(secretKey.length, 32);
  assert.ok(signature.length <= P256_ECDSA_DER_SIGNATURE_MAX_LENGTH);
  ReallyMeP256Ecdsa.verify(signature, message, publicKey);
});

const assertNistEcdsaProvider = (testCase) => {
  const secretKey = base64UrlBytes(vectorString(testCase.vector, "secret_key"));
  const publicKey = base64UrlBytes(
    vectorString(testCase.vector, "public_key_compressed"),
  );
  const message = base64UrlBytes(vectorString(testCase.vector, "message"));
  const signature = base64UrlBytes(vectorString(testCase.vector, "signature_der"));

  assert.deepEqual(testCase.provider.derivePublicKey(secretKey), publicKey);
  assert.deepEqual(testCase.provider.deriveKeyPair(secretKey).publicKey, publicKey);
  assert.deepEqual(
    ReallyMeCrypto.deriveKeyPair(testCase.algorithm, secretKey).publicKey,
    publicKey,
  );
  assert.deepEqual(testCase.provider.sign(message, secretKey), signature);
  testCase.provider.verify(signature, message, publicKey);
  assert.deepEqual(
    ReallyMeCrypto.sign(testCase.algorithm, message, secretKey),
    signature,
  );
  ReallyMeCrypto.verify(testCase.algorithm, signature, message, publicKey);

  const tamperedSignature = Uint8Array.from(signature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  assertReallyMeError(
    () => testCase.provider.verify(tamperedSignature, message, publicKey),
    "invalid-signature",
  );

  assert.throws(
    () => testCase.provider.sign(message, new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => testCase.provider.verify(new Uint8Array(7), message, publicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  const invalidKey = Uint8Array.from(publicKey);
  invalidKey[0] = 0x07;
  assert.throws(
    () => testCase.provider.verify(signature, message, invalidKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  const generated = testCase.provider.generateKeyPair();
  const generatedSignature = testCase.provider.sign(message, generated.secretKey);
  assert.equal(generated.publicKey.length, testCase.publicKeyLength);
  assert.equal(generated.secretKey.length, testCase.secretKeyLength);
  assert.ok(generatedSignature.length <= testCase.maxDerLength);
  testCase.provider.verify(generatedSignature, message, generated.publicKey);
};

test("p384 ecdsa known answer and facade parity", () => {
  assertNistEcdsaProvider({
    algorithm: "ECDSA-P384-SHA384",
    maxDerLength: P384_ECDSA_DER_SIGNATURE_MAX_LENGTH,
    provider: ReallyMeP384Ecdsa,
    publicKeyLength: 49,
    secretKeyLength: 48,
    vector: p384Vector,
  });
});

test("p521 ecdsa known answer and facade parity", () => {
  assertNistEcdsaProvider({
    algorithm: "ECDSA-P521-SHA512",
    maxDerLength: P521_ECDSA_DER_SIGNATURE_MAX_LENGTH,
    provider: ReallyMeP521Ecdsa,
    publicKeyLength: 67,
    secretKeyLength: 66,
    vector: p521Vector,
  });
});

test("rsa verify known answers through WASM", () => {
  const publicKeyDer = base64UrlBytes(vectorString(rsaVector, "public_key_der"));
  const message = base64UrlBytes(vectorString(rsaVector, "message"));
  const cases = [
    ["RSA-PKCS1v15-SHA1", "pkcs1v15_sha1_signature"],
    ["RSA-PKCS1v15-SHA256", "pkcs1v15_sha256_signature"],
    ["RSA-PKCS1v15-SHA384", "pkcs1v15_sha384_signature"],
    ["RSA-PKCS1v15-SHA512", "pkcs1v15_sha512_signature"],
    ["RSA-PSS-SHA1-MGF1-SHA1", "pss_sha1_mgf1_sha1_signature"],
    ["RSA-PSS-SHA256-MGF1-SHA256", "pss_sha256_mgf1_sha256_signature"],
    ["RSA-PSS-SHA384-MGF1-SHA384", "pss_sha384_mgf1_sha384_signature"],
    ["RSA-PSS-SHA512-MGF1-SHA512", "pss_sha512_mgf1_sha512_signature"],
  ];

  for (const [algorithm, signatureField] of cases) {
    const signature = base64UrlBytes(vectorString(rsaVector, signatureField));
    ReallyMeRsa.verify(algorithm, signature, message, publicKeyDer, "PKCS1");
  }
});

test("rsa verify rejects tampering and malformed inputs through typed errors", () => {
  const publicKeyDer = base64UrlBytes(vectorString(rsaVector, "public_key_der"));
  const message = base64UrlBytes(vectorString(rsaVector, "message"));
  const signature = base64UrlBytes(
    vectorString(rsaVector, "pkcs1v15_sha256_signature"),
  );

  const tamperedSignature = Uint8Array.from(signature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  assertReallyMeError(
    () =>
      ReallyMeRsa.verify(
        "RSA-PKCS1v15-SHA256",
        tamperedSignature,
        message,
        publicKeyDer,
        "PKCS1",
      ),
    "invalid-signature",
  );

  assert.throws(
    () =>
      ReallyMeRsa.verify(
        "RSA-PKCS1v15-SHA256",
        new Uint8Array(),
        message,
        publicKeyDer,
        "PKCS1",
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeRsa.verify(
        "RSA-PKCS1v15-SHA256",
        signature,
        message,
        new Uint8Array(),
        "PKCS1",
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeRsa.verify(
        "ECDSA-P256-SHA256",
        signature,
        message,
        publicKeyDer,
        "PKCS1",
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "unsupported-algorithm",
  );
});

test("secp256k1 derive public key known answer", () => {
  assert.deepEqual(
    ReallyMeSecp256k1.derivePublicKey(vectorSecretKey),
    vectorPublicKey,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveKeyPair("ECDSA-secp256k1-SHA256", vectorSecretKey).publicKey,
    vectorPublicKey,
  );
});

test("secp256k1 sign is deterministic, cross-lane KAT, and verifies", () => {
  const message = new TextEncoder().encode("reallyme secp256k1 contract");

  const first = ReallyMeSecp256k1.sign(message, vectorSecretKey);
  const second = ReallyMeSecp256k1.sign(message, vectorSecretKey);
  assert.deepEqual(first, second, "RFC 6979 signatures must be deterministic");
  assert.equal(first.length, SECP256K1_SIGNATURE_LENGTH);

  // Cross-lane KAT: the same bytes libsecp256k1 (Swift lane) and
  // BouncyCastle (Kotlin lane) produce for this message and key.
  assert.equal(
    hex(first),
    "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d" +
      "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee",
  );

  ReallyMeSecp256k1.verify(first, message, vectorPublicKey);
});

test("generic facade secp256k1 known answer", () => {
  const message = new TextEncoder().encode("reallyme secp256k1 contract");
  const signature = ReallyMeCrypto.sign(
    "ECDSA-secp256k1-SHA256",
    message,
    vectorSecretKey,
  );

  assert.equal(
    hex(signature),
    "b94d52260da1d40bbc404432860437ac166781f2da4340086508a26db5e7d14d" +
      "371dfc9f3c1908fa0980a28182a75bc8d3b80cf53a58d0c8e179f966bb79b3ee",
  );
  ReallyMeCrypto.verify(
    "ECDSA-secp256k1-SHA256",
    signature,
    message,
    vectorPublicKey,
  );
});

test("secp256k1 rejects tampered signature and message", () => {
  const message = new TextEncoder().encode("tamper check");
  const signature = ReallyMeSecp256k1.sign(message, vectorSecretKey);

  const extended = new Uint8Array([...message, 0x00]);
  assertReallyMeError(
    () => ReallyMeSecp256k1.verify(signature, extended, vectorPublicKey),
    "invalid-signature",
  );

  const flipped = Uint8Array.from(signature);
  flipped[10] ^= 0xff;
  assertReallyMeError(
    () => ReallyMeSecp256k1.verify(flipped, message, vectorPublicKey),
    "invalid-signature",
  );
});

test("secp256k1 rejects high-S malleated twin", () => {
  const curveOrder = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  );
  const message = new TextEncoder().encode("malleability check");
  const signature = ReallyMeSecp256k1.sign(message, vectorSecretKey);
  ReallyMeSecp256k1.verify(signature, message, vectorPublicKey);

  // (r, n - s) verifies under raw ECDSA but must be rejected (BIP 0062).
  const s = BigInt("0x" + hex(signature.slice(32)));
  const highS = (curveOrder - s).toString(16).padStart(64, "0");
  const malleated = new Uint8Array([...signature.slice(0, 32), ...bytes(highS)]);
  assertReallyMeError(
    () => ReallyMeSecp256k1.verify(malleated, message, vectorPublicKey),
    "invalid-signature",
  );
});

test("secp256k1 rejects malformed inputs", () => {
  const message = new TextEncoder().encode("shape check");

  assert.throws(
    () => ReallyMeSecp256k1.sign(message, new Uint8Array([1, 2])),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeSecp256k1.derivePublicKey(new Uint8Array(32)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () => ReallyMeCrypto.deriveKeyPair("ECDSA-secp256k1-SHA256", new Uint8Array(32)),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  assert.throws(
    () => ReallyMeSecp256k1.verify(new Uint8Array(63), message, vectorPublicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );

  const invalidKey = Uint8Array.from(vectorPublicKey);
  invalidKey[0] = 0x07; // not a valid SEC1 compressed prefix
  assert.throws(
    () =>
      ReallyMeSecp256k1.verify(
        new Uint8Array(SECP256K1_SIGNATURE_LENGTH),
        message,
        invalidKey,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("secp256k1 generate keypair round trip", () => {
  const { publicKey, secretKey } = ReallyMeSecp256k1.generateKeyPair();
  assert.equal(secretKey.length, 32);
  assert.equal(publicKey.length, 33);

  const message = new TextEncoder().encode("fresh keypair");
  const signature = ReallyMeSecp256k1.sign(message, secretKey);
  ReallyMeSecp256k1.verify(signature, message, publicKey);
});

test("bip340 schnorr known answer and facade sign/verify", () => {
  assert.deepEqual(
    ReallyMeBip340Schnorr.derivePublicKey(bip340SchnorrSecretKey),
    bip340SchnorrPublicKey,
  );
  assert.deepEqual(
    ReallyMeCrypto.deriveKeyPair(
      "BIP340-Schnorr-secp256k1-SHA256",
      bip340SchnorrSecretKey,
    ).publicKey,
    bip340SchnorrPublicKey,
  );
  assert.deepEqual(
    ReallyMeBip340Schnorr.sign(
      bip340SchnorrMessage,
      bip340SchnorrSecretKey,
      bip340SchnorrAuxRand,
    ),
    bip340SchnorrSignature,
  );
  assert.deepEqual(
    ReallyMeCrypto.signBip340Schnorr(
      bip340SchnorrMessage,
      bip340SchnorrSecretKey,
      bip340SchnorrAuxRand,
    ),
    bip340SchnorrSignature,
  );
  ReallyMeBip340Schnorr.verify(
    bip340SchnorrSignature,
    bip340SchnorrMessage,
    bip340SchnorrPublicKey,
  );
  ReallyMeCrypto.verify(
    "BIP340-Schnorr-secp256k1-SHA256",
    bip340SchnorrSignature,
    bip340SchnorrMessage,
    bip340SchnorrPublicKey,
  );

  const generated = ReallyMeCrypto.generateKeyPair(
    "BIP340-Schnorr-secp256k1-SHA256",
  );
  assert.equal(generated.publicKey.length, 32);
  assert.equal(generated.secretKey.length, 32);
});

test("bip340 schnorr rejects malformed inputs and generic sign", () => {
  assertUnsupportedAlgorithm(() =>
    ReallyMeCrypto.sign(
      "BIP340-Schnorr-secp256k1-SHA256",
      bip340SchnorrMessage,
      bip340SchnorrSecretKey,
    ),
  );

  const tamperedSignature = Uint8Array.from(bip340SchnorrSignature);
  tamperedSignature[tamperedSignature.length - 1] ^= 0x01;
  assertReallyMeError(
    () =>
      ReallyMeBip340Schnorr.verify(
        tamperedSignature,
        bip340SchnorrMessage,
        bip340SchnorrPublicKey,
      ),
    "invalid-signature",
  );

  assert.throws(
    () =>
      ReallyMeBip340Schnorr.sign(
        new Uint8Array(31),
        bip340SchnorrSecretKey,
        bip340SchnorrAuxRand,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeBip340Schnorr.sign(
        bip340SchnorrMessage,
        bip340SchnorrSecretKey,
        new Uint8Array(31),
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
  assert.throws(
    () =>
      ReallyMeBip340Schnorr.verify(
        new Uint8Array(BIP340_SCHNORR_SIGNATURE_LENGTH - 1),
        bip340SchnorrMessage,
        bip340SchnorrPublicKey,
      ),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
  );
});

test("facade fails closed for out-of-enum identifiers from JS callers", () => {
  // TypeScript unions can't stop a plain-JS caller passing an unknown string.
  // Every value-returning facade dispatcher must throw, never return undefined.
  const input = new TextEncoder().encode("x");
  const bad = "NOPE-not-an-algorithm";
  const cases = [
    () => ReallyMeCrypto.hash(bad, input),
    () => ReallyMeCrypto.authenticate(bad, input, input),
    () => ReallyMeCrypto.verifyMac(bad, input, input, input),
    () => ReallyMeCrypto.deriveKey(bad, input, input, 4096, 32),
    () => ReallyMeCrypto.deriveHkdf(bad, input, input, input, 32),
    () => ReallyMeCrypto.deriveSharedSecret(bad, input, input),
    () => ReallyMeCrypto.generateKemKeyPair(bad),
    () => ReallyMeCrypto.encapsulate(bad, input),
    () => ReallyMeCrypto.decapsulate(bad, input, input),
    () => ReallyMeCrypto.seal(bad, input, input, input, input),
    () => ReallyMeCrypto.open(bad, input, input, input, input),
    () => ReallyMeCrypto.wrapKey(bad, input, input),
    () => ReallyMeCrypto.unwrapKey(bad, input, input),
    () => ReallyMeCrypto.sign(bad, input, input),
    () => ReallyMeCrypto.verify(bad, input, input, input),
    () => ReallyMeCrypto.generateKeyPair(bad),
    () => ReallyMeCrypto.sealHpke(bad, input, input, input, input),
    () => ReallyMeCrypto.openHpke(bad, input, input, input, input, input),
  ];
  for (const fn of cases) {
    assert.throws(
      fn,
      (e) => e instanceof ReallyMeCryptoError && e.code === "unsupported-algorithm",
    );
  }
});
