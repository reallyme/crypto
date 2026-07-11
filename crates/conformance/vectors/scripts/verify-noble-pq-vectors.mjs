// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Cross-implementation conformance: every byte compared here was produced
// by the Rust (RustCrypto ml-kem / ml-dsa) generator; this script must
// reproduce it exactly with @noble/post-quantum. Keygen, deterministic
// encapsulation, decapsulation, implicit rejection, and deterministic
// signing all fail closed on the first mismatch.

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024, ml_kem512, ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const ErrorCode = Object.freeze({
  InvalidJson: "InvalidJson",
  InvalidVectorShape: "InvalidVectorShape",
  InvalidBase64Url: "InvalidBase64Url",
  InvalidOracleMetadata: "InvalidOracleMetadata",
  UnexpectedLength: "UnexpectedLength",
  PublicKeyMismatch: "PublicKeyMismatch",
  CiphertextMismatch: "CiphertextMismatch",
  KemSharedSecretMismatch: "KemSharedSecretMismatch",
  ImplicitRejectionMismatch: "ImplicitRejectionMismatch",
  SignatureMismatch: "SignatureMismatch",
  SignatureRejected: "SignatureRejected",
  TamperedSignatureAccepted: "TamperedSignatureAccepted",
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

function requiredBytes(value, fieldName, vectorName) {
  return decodeBase64Url(fieldString(value, fieldName, vectorName), vectorName);
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

async function verifyMlKemVector(name, kem) {
  const vector = await loadVector(name);
  const publicKey = requiredBytes(vector, "public_key", name);
  const secretKey = requiredBytes(vector, "secret_key", name);
  const encapsRandomness = requiredBytes(vector, "encaps_randomness", name);
  const expectedCiphertext = requiredBytes(vector, "ciphertext", name);
  const expectedSharedSecret = requiredBytes(vector, "shared_secret", name);
  const tamperedCiphertext = requiredBytes(vector, "tampered_ciphertext", name);
  const expectedTamperedSecret = requiredBytes(vector, "tampered_shared_secret", name);
  const secretKeyFormat = fieldString(vector, "secret_key_format", name);
  let providerSecretKey = secretKey;

  try {
    requireLength(publicKey, kem.lengths.publicKey, name);
    requireLength(encapsRandomness, kem.lengths.msg, name);
    requireLength(expectedCiphertext, kem.lengths.cipherText, name);
    requireLength(tamperedCiphertext, kem.lengths.cipherText, name);
    if (secretKeyFormat !== "fips-203-seed") {
      throw new VectorVerificationError(ErrorCode.InvalidVectorShape, name);
    }
    requireLength(secretKey, kem.lengths.seed, name);

    // Keygen: seed must expand to the Rust-generated public key.
    const generated = kem.keygen(secretKey);
    providerSecretKey = generated.secretKey;
    if (!equalBytes(generated.publicKey, publicKey)) {
      throw new VectorVerificationError(ErrorCode.PublicKeyMismatch, name);
    }

    // Deterministic encapsulation: same randomness must yield the exact
    // Rust-generated ciphertext and shared secret.
    const encapsulated = kem.encapsulate(publicKey, encapsRandomness);
    if (!equalBytes(encapsulated.cipherText, expectedCiphertext)) {
      throw new VectorVerificationError(ErrorCode.CiphertextMismatch, name);
    }
    if (!equalBytes(encapsulated.sharedSecret, expectedSharedSecret)) {
      throw new VectorVerificationError(ErrorCode.KemSharedSecretMismatch, name);
    }

    // Decapsulation of the committed ciphertext.
    const decapsulated = kem.decapsulate(expectedCiphertext, providerSecretKey);
    if (!equalBytes(decapsulated, expectedSharedSecret)) {
      throw new VectorVerificationError(ErrorCode.KemSharedSecretMismatch, name);
    }
    decapsulated.fill(0);

    // Implicit rejection: a tampered ciphertext must decapsulate to the
    // same pseudorandom secret in every implementation (FIPS 203 J
    // derivation), never to an error and never to the real secret.
    const rejected = kem.decapsulate(tamperedCiphertext, providerSecretKey);
    if (!equalBytes(rejected, expectedTamperedSecret)) {
      throw new VectorVerificationError(ErrorCode.ImplicitRejectionMismatch, name);
    }
    if (equalBytes(rejected, expectedSharedSecret)) {
      throw new VectorVerificationError(ErrorCode.ImplicitRejectionMismatch, name);
    }
    rejected.fill(0);
    encapsulated.sharedSecret.fill(0);
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    if (providerSecretKey !== secretKey) {
      providerSecretKey.fill(0);
    }
  }
}

async function verifyMlDsaVector(name, dsa) {
  const vector = await loadVector(name);
  const publicKey = requiredBytes(vector, "public_key", name);
  const secretKey = requiredBytes(vector, "secret_key", name);
  const message = requiredBytes(vector, "message", name);
  const expectedSignature = requiredBytes(vector, "signature", name);
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

    // Deterministic signing must reproduce the Rust-generated signature
    // byte-for-byte.
    const signature = dsa.sign(message, expandedSecretKey, { extraEntropy: false });
    const signatureMatches = equalBytes(signature, expectedSignature);
    signature.fill(0);
    if (!signatureMatches) {
      throw new VectorVerificationError(ErrorCode.SignatureMismatch, name);
    }

    if (!dsa.verify(expectedSignature, message, publicKey)) {
      throw new VectorVerificationError(ErrorCode.SignatureRejected, name);
    }

    // Negative path: a tampered signature must be rejected.
    const tamperedSignature = expectedSignature.slice();
    tamperedSignature[0] ^= 0x01;
    if (dsa.verify(tamperedSignature, message, publicKey)) {
      throw new VectorVerificationError(ErrorCode.TamperedSignatureAccepted, name);
    }
  } finally {
    publicKey.fill(0);
    secretKey.fill(0);
    if (expandedSecretKey !== secretKey) {
      expandedSecretKey.fill(0);
    }
  }
}

await verifyOracleMetadata();
await verifyMlDsaVector("ml_dsa_44.json", ml_dsa44);
await verifyMlDsaVector("ml_dsa_65.json", ml_dsa65);
await verifyMlDsaVector("ml_dsa_87.json", ml_dsa87);
await verifyMlKemVector("mlkem512.json", ml_kem512);
await verifyMlKemVector("mlkem768.json", ml_kem768);
await verifyMlKemVector("mlkem1024.json", ml_kem1024);
