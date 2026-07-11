// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { sha3_224, sha3_256, sha3_384, sha3_512, shake256 } from "@noble/hashes/sha3.js";
import {
  constants as cryptoConstants,
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPublicKey,
  pbkdf2Sync,
  verify as cryptoVerify,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ReallyMeJwk } from "../../../../packages/ts/dist/jwk.js";

const ErrorCode = Object.freeze({
  InvalidJson: "InvalidJson",
  InvalidVectorShape: "InvalidVectorShape",
  InvalidBase64Url: "InvalidBase64Url",
  InvalidOracleMetadata: "InvalidOracleMetadata",
  UnexpectedLength: "UnexpectedLength",
  PublicKeyMismatch: "PublicKeyMismatch",
  DecryptionMismatch: "DecryptionMismatch",
  DigestMismatch: "DigestMismatch",
  MacMismatch: "MacMismatch",
  SharedSecretMismatch: "SharedSecretMismatch",
  SignatureMismatch: "SignatureMismatch",
  KemSharedSecretMismatch: "KemSharedSecretMismatch",
  XWingMismatch: "XWingMismatch",
  HpkeMismatch: "HpkeMismatch",
  IntegrityAccepted: "IntegrityAccepted",
  KdfMismatch: "KdfMismatch",
  SignatureRejected: "SignatureRejected",
  SignatureAccepted: "SignatureAccepted",
  JwkMismatch: "JwkMismatch",
});

class VectorVerificationError extends Error {
  constructor(code, vectorName) {
    super(`${code}: ${vectorName}`);
    this.name = "VectorVerificationError";
    this.code = code;
    this.vectorName = vectorName;
  }
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(scriptDir, "..");
const repoRoot = resolve(packageDir, "..", "..", "..");
const vectorsDir = resolve(repoRoot, "vectors");
const kemRandomness = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
]);
const xWingLabel = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
const aesKwDefaultIv = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

function concatBytes(parts, vectorName) {
  let totalLength = 0;
  for (const part of parts) {
    totalLength += part.length;
  }
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  if (offset !== totalLength) {
    throw new VectorVerificationError(ErrorCode.UnexpectedLength, vectorName);
  }
  return out;
}

function equalBytes(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left[index] ^ right[index];
  }
  return diff === 0;
}

function parseJson(bytes, vectorName) {
  try {
    return JSON.parse(bytes);
  } catch {
    throw new VectorVerificationError(ErrorCode.InvalidJson, vectorName);
  }
}

function fieldString(value, fieldName, vectorName) {
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.hasOwn(value, fieldName) ||
    typeof value[fieldName] !== "string"
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return value[fieldName];
}

function fieldObject(value, fieldName, vectorName) {
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.hasOwn(value, fieldName) ||
    typeof value[fieldName] !== "object" ||
    value[fieldName] === null ||
    Array.isArray(value[fieldName])
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return value[fieldName];
}

function fieldArray(value, fieldName, vectorName) {
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.hasOwn(value, fieldName) ||
    !Array.isArray(value[fieldName])
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return value[fieldName];
}

function fieldNumber(value, fieldName, vectorName) {
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.hasOwn(value, fieldName) ||
    typeof value[fieldName] !== "number" ||
    !Number.isSafeInteger(value[fieldName]) ||
    value[fieldName] < 0
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return value[fieldName];
}

function fieldNullableString(value, fieldName, vectorName) {
  if (
    typeof value !== "object" ||
    value === null ||
    !Object.hasOwn(value, fieldName) ||
    (typeof value[fieldName] !== "string" && value[fieldName] !== null)
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return value[fieldName];
}

function decodeBase64Url(value, vectorName) {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new VectorVerificationError(ErrorCode.InvalidBase64Url, vectorName);
  }
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function requireLength(bytes, expectedLength, vectorName) {
  if (bytes.length !== expectedLength) {
    throw new VectorVerificationError(ErrorCode.UnexpectedLength, vectorName);
  }
}

function readDerLength(bytes, offset, vectorName) {
  if (offset >= bytes.length) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  const first = bytes[offset];
  const nextOffset = offset + 1;
  if ((first & 0x80) === 0) {
    return { length: first, offset: nextOffset };
  }
  const lengthBytes = first & 0x7f;
  if (lengthBytes === 0 || lengthBytes > 2 || nextOffset + lengthBytes > bytes.length) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  let length = 0;
  for (let index = 0; index < lengthBytes; index += 1) {
    length = length * 256 + bytes[nextOffset + index];
  }
  return { length, offset: nextOffset + lengthBytes };
}

function readDerInteger(bytes, offset, width, vectorName) {
  if (offset >= bytes.length || bytes[offset] !== 0x02) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  const lengthInfo = readDerLength(bytes, offset + 1, vectorName);
  const start = lengthInfo.offset;
  const end = start + lengthInfo.length;
  if (end > bytes.length || lengthInfo.length === 0 || lengthInfo.length > width + 1) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  let value = bytes.subarray(start, end);
  if (value.length === width + 1) {
    if (value[0] !== 0x00) {
      throw new VectorVerificationError(ErrorCode.UnexpectedLength, vectorName);
    }
    value = value.subarray(1);
  }
  if (value.length > width) {
    throw new VectorVerificationError(ErrorCode.UnexpectedLength, vectorName);
  }
  const out = new Uint8Array(width);
  out.set(value, width - value.length);
  return { value: out, offset: end };
}

function derToFixedWidthSignature(signatureDer, width, vectorName) {
  if (signatureDer.length < 8 || signatureDer[0] !== 0x30) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  const sequenceLength = readDerLength(signatureDer, 1, vectorName);
  const sequenceEnd = sequenceLength.offset + sequenceLength.length;
  if (sequenceEnd !== signatureDer.length) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  const r = readDerInteger(signatureDer, sequenceLength.offset, width, vectorName);
  const s = readDerInteger(signatureDer, r.offset, width, vectorName);
  if (s.offset !== sequenceEnd) {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
  }
  return concatBytes([r.value, s.value], vectorName);
}

async function loadVector(name) {
  const bytes = await readFile(resolve(vectorsDir, name), { encoding: "utf8" });
  return parseJson(bytes, name);
}

async function verifyOracleMetadata() {
  const manifest = await loadVector("manifest.json");
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    manifest.post_quantum_oracle?.package !== "@noble/post-quantum" ||
    manifest.post_quantum_oracle.version !== "0.6.1"
  ) {
    throw new VectorVerificationError(ErrorCode.InvalidOracleMetadata, "manifest.json");
  }
}

async function verifyP256() {
  const name = "p256.json";
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKeyCompressed = decodeBase64Url(fieldString(vector, "public_key_compressed", name), name);
  const publicKeyUncompressed = decodeBase64Url(fieldString(vector, "public_key_uncompressed", name), name);
  const peerSecretKey = decodeBase64Url(fieldString(vector, "peer_secret_key", name), name);
  const peerPublicKeyCompressed = decodeBase64Url(fieldString(vector, "peer_public_key_compressed", name), name);
  const peerPublicKeyUncompressed = decodeBase64Url(fieldString(vector, "peer_public_key_uncompressed", name), name);
  const sharedSecret = decodeBase64Url(fieldString(vector, "shared_secret", name), name);

  try {
    requireLength(secretKey, 32, name);
    requireLength(peerSecretKey, 32, name);
    requireLength(sharedSecret, 32, name);
    if (!equalBytes(p256.getPublicKey(secretKey, true), publicKeyCompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(p256.getPublicKey(secretKey, false), publicKeyUncompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(p256.getPublicKey(peerSecretKey, true), peerPublicKeyCompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(p256.getPublicKey(peerSecretKey, false), peerPublicKeyUncompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    const derived = p256.getSharedSecret(secretKey, peerPublicKeyCompressed, false).slice(1, 33);
    const peerDerived = p256.getSharedSecret(peerSecretKey, publicKeyCompressed, false).slice(1, 33);
    if (!equalBytes(derived, sharedSecret) || !equalBytes(peerDerived, sharedSecret)) {
      throw new VectorVerificationError(ErrorCode.SharedSecretMismatch, name);
    }
  } finally {
    secretKey.fill(0);
    peerSecretKey.fill(0);
    sharedSecret.fill(0);
  }
}

async function verifySec1Ecdsa(name, curve, secretKeyLength, compressedLength, uncompressedLength) {
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKeyCompressed = decodeBase64Url(fieldString(vector, "public_key_compressed", name), name);
  const publicKeyUncompressed = decodeBase64Url(fieldString(vector, "public_key_uncompressed", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const signature = decodeBase64Url(fieldString(vector, "signature_der", name), name);
  const fixedWidthSignature = derToFixedWidthSignature(signature, secretKeyLength, name);

  try {
    requireLength(secretKey, secretKeyLength, name);
    requireLength(publicKeyCompressed, compressedLength, name);
    requireLength(publicKeyUncompressed, uncompressedLength, name);
    if (!equalBytes(curve.getPublicKey(secretKey, true), publicKeyCompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(curve.getPublicKey(secretKey, false), publicKeyUncompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!curve.verify(fixedWidthSignature, message, publicKeyCompressed, { lowS: false })) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }
  } finally {
    secretKey.fill(0);
    fixedWidthSignature.fill(0);
  }
}

async function verifyP384() {
  await verifySec1Ecdsa("p384.json", p384, 48, 49, 97);
}

async function verifyP521() {
  await verifySec1Ecdsa("p521.json", p521, 66, 67, 133);
}

async function verifyEd25519() {
  const name = "ed25519.json";
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const signature = decodeBase64Url(fieldString(vector, "signature", name), name);

  try {
    requireLength(secretKey, 32, name);
    if (!equalBytes(ed25519.getPublicKey(secretKey), publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    const generatedSignature = ed25519.sign(message, secretKey);
    if (!equalBytes(generatedSignature, signature)) {
      throw new VectorVerificationError(ErrorCode.SignatureMismatch, name);
    }
    if (!ed25519.verify(signature, message, publicKey)) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }
  } finally {
    secretKey.fill(0);
  }
}

async function verifySecp256k1() {
  const name = "secp256k1.json";
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKeyCompressed = decodeBase64Url(fieldString(vector, "public_key_compressed", name), name);

  try {
    requireLength(secretKey, 32, name);
    if (!equalBytes(secp256k1.getPublicKey(secretKey, true), publicKeyCompressed)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
  } finally {
    secretKey.fill(0);
  }
}

async function verifyBip340Schnorr() {
  const name = "bip340_schnorr.json";
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key_xonly", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const auxRand = decodeBase64Url(fieldString(vector, "aux_rand", name), name);
  const signature = decodeBase64Url(fieldString(vector, "signature", name), name);

  try {
    if (fieldString(vector, "public_key_format", name) !== "x-only") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(secretKey, 32, name);
    requireLength(publicKey, 32, name);
    requireLength(message, 32, name);
    requireLength(auxRand, 32, name);
    requireLength(signature, 64, name);

    if (!equalBytes(schnorr.getPublicKey(secretKey), publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }

    const generatedSignature = schnorr.sign(message, secretKey, auxRand);
    if (!equalBytes(generatedSignature, signature)) {
      throw new VectorVerificationError(ErrorCode.SignatureMismatch, name);
    }

    if (!schnorr.verify(signature, message, publicKey)) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }

    const tampered = signature.slice();
    tampered[0] ^= 0x01;
    if (schnorr.verify(tampered, message, publicKey)) {
      throw new VectorVerificationError(ErrorCode.SignatureAccepted, name);
    }
  } finally {
    secretKey.fill(0);
    auxRand.fill(0);
  }
}

async function verifyRsa() {
  const name = "rsa.json";
  const vector = await loadVector(name);
  const publicKeyDer = decodeBase64Url(fieldString(vector, "public_key_der", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const pkcs1Sha1 = decodeBase64Url(fieldString(vector, "pkcs1v15_sha1_signature", name), name);
  const pkcs1Sha256 = decodeBase64Url(fieldString(vector, "pkcs1v15_sha256_signature", name), name);
  const pssSha256 = decodeBase64Url(
    fieldString(vector, "pss_sha256_mgf1_sha256_signature", name),
    name,
  );
  const saltLength = fieldNumber(vector, "pss_sha256_mgf1_sha256_salt_len", name);

  try {
    requireLength(pkcs1Sha1, 256, name);
    requireLength(pkcs1Sha256, 256, name);
    requireLength(pssSha256, 256, name);
    const key = createPublicKey({
      key: Buffer.from(publicKeyDer),
      format: "der",
      type: "pkcs1",
    });

    const pkcs1Sha1Valid = cryptoVerify(
      "RSA-SHA1",
      Buffer.from(message),
      { key, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(pkcs1Sha1),
    );
    const pkcs1Sha256Valid = cryptoVerify(
      "RSA-SHA256",
      Buffer.from(message),
      { key, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(pkcs1Sha256),
    );
    const pssSha256Valid = cryptoVerify(
      "sha256",
      Buffer.from(message),
      {
        key,
        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      },
      Buffer.from(pssSha256),
    );
    if (!pkcs1Sha1Valid || !pkcs1Sha256Valid || !pssSha256Valid) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }

    pssSha256[0] ^= 0x01;
    const tamperedValid = cryptoVerify(
      "sha256",
      Buffer.from(message),
      {
        key,
        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
        saltLength,
      },
      Buffer.from(pssSha256),
    );
    if (tamperedValid) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }
  } finally {
    publicKeyDer.fill(0);
    pkcs1Sha1.fill(0);
    pkcs1Sha256.fill(0);
    pssSha256.fill(0);
  }
}

async function verifyX25519() {
  const name = "x25519.json";
  const vector = await loadVector(name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
  const peerSecretKey = decodeBase64Url(fieldString(vector, "peer_secret_key", name), name);
  const peerPublicKey = decodeBase64Url(fieldString(vector, "peer_public_key", name), name);
  const sharedSecret = decodeBase64Url(fieldString(vector, "shared_secret", name), name);

  try {
    requireLength(secretKey, 32, name);
    if (!equalBytes(x25519.getPublicKey(secretKey), publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(x25519.getPublicKey(peerSecretKey), peerPublicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }
    if (!equalBytes(x25519.getSharedSecret(secretKey, peerPublicKey), sharedSecret)) {
      throw new VectorVerificationError(ErrorCode.SharedSecretMismatch, name);
    }
    if (!equalBytes(x25519.getSharedSecret(peerSecretKey, publicKey), sharedSecret)) {
      throw new VectorVerificationError(ErrorCode.SharedSecretMismatch, name);
    }
  } finally {
    secretKey.fill(0);
    peerSecretKey.fill(0);
  }
}

async function verifyAes256Gcm() {
  const name = "aes256gcm.json";
  const vector = await loadVector(name);
  const key = decodeBase64Url(fieldString(vector, "key", name), name);
  const nonce = decodeBase64Url(fieldString(vector, "nonce", name), name);
  const aad = decodeBase64Url(fieldString(vector, "aad", name), name);
  const plaintext = decodeBase64Url(fieldString(vector, "plaintext", name), name);
  const ciphertext = decodeBase64Url(fieldString(vector, "ciphertext_with_tag", name), name);

  try {
    const decrypted = gcm(key, nonce, aad).decrypt(ciphertext);
    if (!equalBytes(decrypted, plaintext)) {
      throw new VectorVerificationError(ErrorCode.DecryptionMismatch, name);
    }
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

async function verifyAes256Kw() {
  const name = "aes256kw.json";
  const vector = await loadVector(name);
  const kek = decodeBase64Url(fieldString(vector, "kek", name), name);
  const keyData = decodeBase64Url(fieldString(vector, "key_data", name), name);
  const wrappedKey = decodeBase64Url(fieldString(vector, "wrapped_key", name), name);

  try {
    if (fieldString(vector, "alg", name) !== "AES-256-KW") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(kek, 32, name);
    requireLength(keyData, 32, name);
    requireLength(wrappedKey, 40, name);

    const cipher = createCipheriv("id-aes256-wrap", Buffer.from(kek), Buffer.from(aesKwDefaultIv));
    const computedWrapped = new Uint8Array(Buffer.concat([cipher.update(keyData), cipher.final()]));
    if (!equalBytes(computedWrapped, wrappedKey)) {
      throw new VectorVerificationError(ErrorCode.DecryptionMismatch, name);
    }

    const decipher = createDecipheriv("id-aes256-wrap", Buffer.from(kek), Buffer.from(aesKwDefaultIv));
    const unwrapped = new Uint8Array(Buffer.concat([decipher.update(wrappedKey), decipher.final()]));
    if (!equalBytes(unwrapped, keyData)) {
      throw new VectorVerificationError(ErrorCode.DecryptionMismatch, name);
    }

    const tampered = wrappedKey.slice();
    tampered[0] ^= 0x01;
    try {
      const tamperDecipher = createDecipheriv("id-aes256-wrap", Buffer.from(kek), Buffer.from(aesKwDefaultIv));
      Buffer.concat([tamperDecipher.update(tampered), tamperDecipher.final()]);
      throw new VectorVerificationError(ErrorCode.IntegrityAccepted, name);
    } catch (error) {
      if (error instanceof VectorVerificationError) {
        throw error;
      }
    } finally {
      tampered.fill(0);
      computedWrapped.fill(0);
      unwrapped.fill(0);
    }
  } finally {
    kek.fill(0);
    keyData.fill(0);
  }
}

function decryptChaCha20Poly1305(key, nonce, aad, ciphertextWithTag, vectorName) {
  requireLength(key, 32, vectorName);
  requireLength(nonce, 12, vectorName);
  if (ciphertextWithTag.length < 16) {
    throw new VectorVerificationError(ErrorCode.UnexpectedLength, vectorName);
  }

  const tagStart = ciphertextWithTag.length - 16;
  const ciphertext = ciphertextWithTag.subarray(0, tagStart);
  const tag = ciphertextWithTag.subarray(tagStart);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

async function verifyChaCha20Poly1305() {
  const name = "chacha20poly1305.json";
  const vector = await loadVector(name);
  const chacha = fieldObject(vector, "chacha20_poly1305", name);
  const xchacha = fieldObject(vector, "xchacha20_poly1305", name);
  const key = decodeBase64Url(fieldString(chacha, "key", name), name);
  const nonce = decodeBase64Url(fieldString(chacha, "nonce", name), name);
  const aad = decodeBase64Url(fieldString(chacha, "aad", name), name);
  const plaintext = decodeBase64Url(fieldString(chacha, "plaintext", name), name);
  const ciphertext = decodeBase64Url(fieldString(chacha, "ciphertext_with_tag", name), name);
  const xkey = decodeBase64Url(fieldString(xchacha, "key", name), name);
  const xnonce = decodeBase64Url(fieldString(xchacha, "nonce", name), name);
  const xciphertext = decodeBase64Url(fieldString(xchacha, "ciphertext_with_tag", name), name);
  let decrypted = new Uint8Array();

  try {
    decrypted = decryptChaCha20Poly1305(key, nonce, aad, ciphertext, name);
    if (!equalBytes(decrypted, plaintext)) {
      throw new VectorVerificationError(ErrorCode.DecryptionMismatch, name);
    }
    requireLength(xkey, 32, name);
    requireLength(xnonce, 24, name);
    if (xciphertext.length < 16) {
      throw new VectorVerificationError(ErrorCode.UnexpectedLength, name);
    }
  } finally {
    key.fill(0);
    xkey.fill(0);
    plaintext.fill(0);
    decrypted.fill(0);
  }
}

async function verifyHashes() {
  const name = "hashes.json";
  const vector = await loadVector(name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const sha2 = decodeBase64Url(fieldString(vector, "sha2_256", name), name);
  const wideSha2_384 = decodeBase64Url(fieldString(vector, "sha2_384", name), name);
  const wideSha2_512 = decodeBase64Url(fieldString(vector, "sha2_512", name), name);
  const sha3_224Digest = decodeBase64Url(fieldString(vector, "sha3_224", name), name);
  const sha3 = decodeBase64Url(fieldString(vector, "sha3_256", name), name);
  const sha3_384Digest = decodeBase64Url(fieldString(vector, "sha3_384", name), name);
  const sha3_512Digest = decodeBase64Url(fieldString(vector, "sha3_512", name), name);

  if (!equalBytes(sha256(message), sha2)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha384(message), wideSha2_384)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha512(message), wideSha2_512)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha3_224(message), sha3_224Digest)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha3_256(message), sha3)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha3_384(message), sha3_384Digest)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
  if (!equalBytes(sha3_512(message), sha3_512Digest)) {
    throw new VectorVerificationError(ErrorCode.DigestMismatch, name);
  }
}

function verifyHmacCase(caseValue, algorithm, expectedLength, vectorName) {
  const key = decodeBase64Url(fieldString(caseValue, "key", vectorName), vectorName);
  const message = decodeBase64Url(fieldString(caseValue, "message", vectorName), vectorName);
  const tag = decodeBase64Url(fieldString(caseValue, "tag", vectorName), vectorName);

  try {
    requireLength(tag, expectedLength, vectorName);
    const recomputed = new Uint8Array(createHmac(algorithm, key).update(message).digest());
    if (!equalBytes(recomputed, tag)) {
      throw new VectorVerificationError(ErrorCode.MacMismatch, vectorName);
    }
  } finally {
    key.fill(0);
  }
}

async function verifyHmac() {
  const name = "hmac.json";
  const vector = await loadVector(name);
  verifyHmacCase(fieldObject(vector, "hmac_sha256", name), "sha256", 32, name);
  verifyHmacCase(fieldObject(vector, "hmac_sha512", name), "sha512", 64, name);
}

function verifyPbkdf2Case(caseValue, algorithm, expectedLength, vectorName) {
  const password = decodeBase64Url(fieldString(caseValue, "password", vectorName), vectorName);
  const salt = decodeBase64Url(fieldString(caseValue, "salt", vectorName), vectorName);
  const derivedKey = decodeBase64Url(fieldString(caseValue, "derived_key", vectorName), vectorName);
  const iterations = fieldNumber(caseValue, "iterations", vectorName);
  const outputLength = fieldNumber(caseValue, "output_len", vectorName);

  try {
    requireLength(derivedKey, expectedLength, vectorName);
    if (outputLength !== expectedLength || iterations < 1) {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, vectorName);
    }
    const computed = new Uint8Array(pbkdf2Sync(password, salt, iterations, outputLength, algorithm));
    if (!equalBytes(computed, derivedKey)) {
      throw new VectorVerificationError(ErrorCode.KdfMismatch, vectorName);
    }
  } finally {
    password.fill(0);
    salt.fill(0);
  }
}

async function verifyPbkdf2() {
  const name = "pbkdf2.json";
  const vector = await loadVector(name);
  const sha256 = fieldObject(vector, "pbkdf2_hmac_sha256", name);
  const sha512 = fieldObject(vector, "pbkdf2_hmac_sha512", name);
  if (fieldString(sha256, "alg", name) !== "PBKDF2-HMAC-SHA-256") {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
  }
  if (fieldString(sha512, "alg", name) !== "PBKDF2-HMAC-SHA-512") {
    throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
  }
  verifyPbkdf2Case(sha256, "sha256", 32, name);
  verifyPbkdf2Case(sha512, "sha512", 64, name);
}

async function verifyMlKemVector(name, kem) {
  const vector = await loadVector(name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const secretKeyFormat = fieldString(vector, "secret_key_format", name);
  let providerSecretKey = secretKey;

  try {
    requireLength(publicKey, kem.lengths.publicKey, name);
    if (secretKeyFormat !== "fips-203-seed") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(secretKey, kem.lengths.seed, name);

    const generated = kem.keygen(secretKey);
    providerSecretKey = generated.secretKey;
    if (!equalBytes(generated.publicKey, publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }

    const encapsulated = kem.encapsulate(publicKey, kemRandomness);
    const decapsulated = kem.decapsulate(encapsulated.cipherText, providerSecretKey);
    if (!equalBytes(encapsulated.sharedSecret, decapsulated)) {
      throw new VectorVerificationError(ErrorCode.KemSharedSecretMismatch, name);
    }
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    if (providerSecretKey !== secretKey) {
      providerSecretKey.fill(0);
    }
  }
}

function verifyXWingCase(caseName, vector, kem, mlKemPublicKeyLength, mlKemCiphertextLength) {
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", caseName), caseName);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", caseName), caseName);
  const encapsSeed = decodeBase64Url(fieldString(vector, "encaps_seed", caseName), caseName);
  const expectedCiphertext = decodeBase64Url(fieldString(vector, "ciphertext", caseName), caseName);
  const expectedSharedSecret = decodeBase64Url(fieldString(vector, "shared_secret", caseName), caseName);
  const secretKeyFormat = fieldString(vector, "secret_key_format", caseName);

  try {
    if (secretKeyFormat !== "x-wing-seed") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, caseName);
    }
    requireLength(secretKey, 32, caseName);
    requireLength(encapsSeed, 64, caseName);
    requireLength(publicKey, mlKemPublicKeyLength + 32, caseName);
    requireLength(expectedCiphertext, mlKemCiphertextLength + 32, caseName);
    requireLength(expectedSharedSecret, 32, caseName);

    const expanded = shake256(secretKey, { dkLen: 96 });
    const mlKemSeed = expanded.subarray(0, 64);
    const xWingSecret = expanded.subarray(64, 96);
    const generatedMlKem = kem.keygen(mlKemSeed);
    const xWingPublic = x25519.getPublicKey(xWingSecret);
    const generatedPublic = concatBytes([generatedMlKem.publicKey, xWingPublic], caseName);
    if (!equalBytes(generatedPublic, publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, caseName);
    }

    const mlKemPublicKey = publicKey.subarray(0, mlKemPublicKeyLength);
    const receiverX25519PublicKey = publicKey.subarray(mlKemPublicKeyLength);
    const mlKemRandomness = encapsSeed.subarray(0, 32);
    const ephemeralX25519Secret = encapsSeed.subarray(32);
    const mlKemEncapsulated = kem.encapsulate(mlKemPublicKey, mlKemRandomness);
    const x25519Ciphertext = x25519.getPublicKey(ephemeralX25519Secret);
    const x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, receiverX25519PublicKey);
    const combinedInput = concatBytes(
      [
        mlKemEncapsulated.sharedSecret,
        x25519SharedSecret,
        x25519Ciphertext,
        receiverX25519PublicKey,
        xWingLabel,
      ],
      caseName,
    );
    const sharedSecret = sha3_256(combinedInput);
    const ciphertext = concatBytes([mlKemEncapsulated.cipherText, x25519Ciphertext], caseName);
    if (!equalBytes(ciphertext, expectedCiphertext) || !equalBytes(sharedSecret, expectedSharedSecret)) {
      throw new VectorVerificationError(ErrorCode.XWingMismatch, caseName);
    }

    const decapsulatedMlKem = kem.decapsulate(
      expectedCiphertext.subarray(0, mlKemCiphertextLength),
      generatedMlKem.secretKey,
    );
    const decapsulatedX25519 = x25519.getSharedSecret(
      xWingSecret,
      expectedCiphertext.subarray(mlKemCiphertextLength),
    );
    const decapsulated = sha3_256(
      concatBytes(
        [
          decapsulatedMlKem,
          decapsulatedX25519,
          expectedCiphertext.subarray(mlKemCiphertextLength),
          receiverX25519PublicKey,
          xWingLabel,
        ],
        caseName,
      ),
    );
    if (!equalBytes(decapsulated, expectedSharedSecret)) {
      throw new VectorVerificationError(ErrorCode.XWingMismatch, caseName);
    }

    expanded.fill(0);
    generatedMlKem.secretKey.fill(0);
    mlKemEncapsulated.sharedSecret.fill(0);
    decapsulatedMlKem.fill(0);
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    encapsSeed.fill(0);
    expectedSharedSecret.fill(0);
  }
}

async function verifyXWing() {
  const name = "x_wing.json";
  const vectors = await loadVector(name);
  verifyXWingCase("x_wing_768", fieldObject(vectors, "x_wing_768", name), ml_kem768, 1184, 1088);
  verifyXWingCase("x_wing_1024", fieldObject(vectors, "x_wing_1024", name), ml_kem1024, 1568, 1568);
}

function verifyHpkeCase(caseName, vector, expected) {
  const name = `hpke.json/${caseName}`;
  const secretKey = decodeBase64Url(fieldString(vector, "recipient_secret_key", name), name);
  const publicKey = decodeBase64Url(fieldString(vector, "recipient_public_key", name), name);
  const encapsSeed = decodeBase64Url(fieldString(vector, "encaps_seed", name), name);
  const info = decodeBase64Url(fieldString(vector, "info", name), name);
  const aad = decodeBase64Url(fieldString(vector, "aad", name), name);
  const plaintext = decodeBase64Url(fieldString(vector, "plaintext", name), name);
  const encapsulatedKey = decodeBase64Url(fieldString(vector, "encapsulated_key", name), name);
  const ciphertext = decodeBase64Url(fieldString(vector, "ciphertext", name), name);
  const tamperedCiphertext = decodeBase64Url(fieldString(vector, "tampered_ciphertext", name), name);

  try {
    if (fieldString(vector, "mode", name) !== "base") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    if (
      fieldNumber(vector, "kem_id", name) !== expected.kemId ||
      fieldNumber(vector, "kdf_id", name) !== expected.kdfId ||
      fieldNumber(vector, "aead_id", name) !== expected.aeadId
    ) {
      throw new VectorVerificationError(ErrorCode.HpkeMismatch, name);
    }
    requireLength(secretKey, expected.secretKeyLength, name);
    requireLength(publicKey, expected.publicKeyLength, name);
    requireLength(encapsSeed, 32, name);
    requireLength(encapsulatedKey, expected.encapsulatedKeyLength, name);
    if (info.length === 0 || aad.length === 0 || plaintext.length === 0) {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(ciphertext, plaintext.length + 16, name);
    requireLength(tamperedCiphertext, ciphertext.length, name);
  } finally {
    secretKey.fill(0);
    encapsSeed.fill(0);
    plaintext.fill(0);
  }
}

async function verifyHpke() {
  const name = "hpke.json";
  const vectors = await loadVector(name);
  verifyHpkeCase("p256_sha256_aes256gcm", fieldObject(vectors, "p256_sha256_aes256gcm", name), {
    kemId: 0x0010,
    kdfId: 0x0001,
    aeadId: 0x0002,
    secretKeyLength: 32,
    publicKeyLength: 65,
    encapsulatedKeyLength: 65,
  });
  verifyHpkeCase(
    "x25519_sha256_chacha20poly1305",
    fieldObject(vectors, "x25519_sha256_chacha20poly1305", name),
    {
      kemId: 0x0020,
      kdfId: 0x0001,
      aeadId: 0x0003,
      secretKeyLength: 32,
      publicKeyLength: 32,
      encapsulatedKeyLength: 32,
    },
  );
}

async function verifyMlDsaVector(name, dsa) {
  const vector = await loadVector(name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const expectedSignature = decodeBase64Url(fieldString(vector, "signature", name), name);
  const secretKeyFormat = fieldString(vector, "secret_key_format", name);
  let expandedSecretKey = secretKey;

  try {
    requireLength(publicKey, dsa.lengths.publicKey, name);
    requireLength(expectedSignature, dsa.lengths.signature, name);

    let derivedPublicKey;
    if (secretKeyFormat === "fips-204-seed") {
      requireLength(secretKey, dsa.lengths.seed, name);
      const generated = dsa.keygen(secretKey);
      derivedPublicKey = generated.publicKey;
      expandedSecretKey = generated.secretKey;
    } else if (secretKeyFormat === "expanded-secret-key") {
      requireLength(secretKey, dsa.lengths.secretKey, name);
      derivedPublicKey = dsa.getPublicKey(secretKey);
    } else {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }

    if (!equalBytes(derivedPublicKey, publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }

    const signature = dsa.sign(message, expandedSecretKey, { extraEntropy: false });
    const signatureMatches = equalBytes(signature, expectedSignature);
    const verified = dsa.verify(expectedSignature, message, publicKey);
    signature.fill(0);
    if (!signatureMatches) {
      throw new VectorVerificationError(ErrorCode.SignatureMismatch, name);
    }
    if (!verified) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    if (expandedSecretKey !== secretKey) {
      expandedSecretKey.fill(0);
    }
  }
}

async function verifySlhDsaShape() {
  const name = "slh_dsa_sha2_128s.json";
  const vector = await loadVector(name);
  const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
  const secretKey = decodeBase64Url(fieldString(vector, "secret_key", name), name);
  const skSeed = decodeBase64Url(fieldString(vector, "keygen_sk_seed", name), name);
  const skPrf = decodeBase64Url(fieldString(vector, "keygen_sk_prf", name), name);
  const pkSeed = decodeBase64Url(fieldString(vector, "keygen_pk_seed", name), name);
  const message = decodeBase64Url(fieldString(vector, "message", name), name);
  const signature = decodeBase64Url(fieldString(vector, "signature", name), name);
  try {
    if (fieldString(vector, "secret_key_format", name) !== "fips-205-serialized-secret-key") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(publicKey, 32, name);
    requireLength(secretKey, 64, name);
    requireLength(skSeed, 16, name);
    requireLength(skPrf, 16, name);
    requireLength(pkSeed, 16, name);
    requireLength(signature, 7856, name);
    if (
      fieldNumber(vector, "public_key_length", name) !== publicKey.length ||
      fieldNumber(vector, "secret_key_length", name) !== secretKey.length ||
      fieldNumber(vector, "signature_length", name) !== signature.length ||
      message.length === 0
    ) {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    skSeed.fill(0);
    skPrf.fill(0);
    pkSeed.fill(0);
  }
}

async function verifyJwk() {
  const name = "jwk.json";
  const vectorFile = await loadVector(name);
  const vectors = fieldArray(vectorFile, "vectors", name);

  for (const vector of vectors) {
    const alg = fieldString(vector, "alg", name);
    const publicKey = decodeBase64Url(fieldString(vector, "public_key", name), name);
    const expectedLength = fieldNumber(vector, "public_key_length", name);
    const expectedJcs = fieldString(vector, "jwk_jcs", name);
    const multikey = fieldNullableString(vector, "multikey", name);
    const multikeyStatus = fieldString(vector, "multikey_status", name);

    try {
      requireLength(publicKey, expectedLength, name);
      const jwk = ReallyMeJwk.toJwk(alg, publicKey);
      const actualJcs = ReallyMeJwk.toJcs(jwk);
      if (actualJcs !== expectedJcs) {
        throw new VectorVerificationError(ErrorCode.JwkMismatch, name);
      }

      const parsed = ReallyMeJwk.fromJwk(parseJson(expectedJcs, name));
      if (parsed.algorithm !== alg || !equalBytes(parsed.publicKey, publicKey)) {
        throw new VectorVerificationError(ErrorCode.JwkMismatch, name);
      }
      if (ReallyMeJwk.toJcs(parsed.jwk) !== expectedJcs) {
        throw new VectorVerificationError(ErrorCode.JwkMismatch, name);
      }

      if (multikeyStatus === "supported") {
        if (typeof multikey !== "string" || !multikey.startsWith("z")) {
          throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
        }
      } else if (multikeyStatus === "multicodec-missing") {
        if (multikey !== null) {
          throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
        }
      } else {
        throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
      }
    } finally {
      publicKey.fill(0);
    }
  }
}

await verifyOracleMetadata();
await verifyP256();
await verifyP384();
await verifyP521();
await verifyEd25519();
await verifySecp256k1();
await verifyBip340Schnorr();
await verifyRsa();
await verifyX25519();
await verifyAes256Gcm();
await verifyAes256Kw();
await verifyChaCha20Poly1305();
await verifyHmac();
await verifyPbkdf2();
await verifyHashes();
await verifyMlDsaVector("ml_dsa_44.json", ml_dsa44);
await verifyMlDsaVector("ml_dsa_65.json", ml_dsa65);
await verifyMlDsaVector("ml_dsa_87.json", ml_dsa87);
await verifySlhDsaShape();
await verifyMlKemVector("mlkem512.json", ml_kem512);
await verifyMlKemVector("mlkem768.json", ml_kem768);
await verifyMlKemVector("mlkem1024.json", ml_kem1024);
await verifyXWing();
await verifyHpke();
await verifyJwk();
