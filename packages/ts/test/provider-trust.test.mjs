// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ReallyMeAead, ReallyMeAesKw, ReallyMeArgon2id, ReallyMeCryptoError,
  ReallyMeHpke, ReallyMeKmac, ReallyMeMlDsa, ReallyMeMlKem, ReallyMeRsa,
  ReallyMeSlhDsa, ReallyMeXWing, createReallyMeWasmProvider,
} from "../dist/index.js";
import { createWasmProviderFromModule } from "../dist/wasmProvider.js";
import { processOperationResponseWithProvider, processOperationResponseJsonWithProvider } from "../dist/operationResponse.js";
import { deriveSlhDsaSha2128sKeypairWithProviderForTest } from "../dist/slhDsa.js";
import { readIndependentByteArrayProperty, readIndependentProviderBytes } from "../dist/validateBytes.js";
import { initializeWasm, wasmProviderModule } from "./wasm-provider-module.mjs";

initializeWasm(readFileSync(new URL("../dist/wasm/reallyme_crypto_wasm_bg.wasm", import.meta.url)));
const trustedProvider = createReallyMeWasmProvider(wasmProviderModule);
const empty = new Uint8Array();
const bytes = (length) => new Uint8Array(length);
const assertError = (operation, code = "provider-failure", label) => {
  assert.throws(operation, (error) => error instanceof ReallyMeCryptoError && error.code === code, label);
};

const routes = [];
const add = (name, call) => routes.push({ name, call });
for (const [algorithm, keyLength, nonceLength] of [
  ["AES-128-GCM", 16, 12], ["AES-192-GCM", 24, 12], ["AES-256-GCM", 32, 12],
  ["AES-256-GCM-SIV", 32, 12], ["ChaCha20-Poly1305", 32, 12], ["XChaCha20-Poly1305", 32, 24],
]) {
  add("Aead.sealWithProvider", (provider) => ReallyMeAead.sealWithProvider(provider, algorithm, bytes(keyLength), bytes(nonceLength), empty, empty));
  add("Aead.openWithProvider", (provider) => ReallyMeAead.openWithProvider(provider, algorithm, bytes(keyLength), bytes(nonceLength), empty, bytes(16)));
}
for (const [algorithm, keyLength] of [["AES-128-KW", 16], ["AES-192-KW", 24], ["AES-256-KW", 32]]) {
  add("AesKw.wrapKeyWithProvider", (provider) => ReallyMeAesKw.wrapKeyWithProvider(algorithm, provider, bytes(keyLength), bytes(16)));
  add("AesKw.unwrapKeyWithProvider", (provider) => ReallyMeAesKw.unwrapKeyWithProvider(algorithm, provider, bytes(keyLength), bytes(24)));
}
add("Argon2id.deriveKeyWithProvider", (provider) => ReallyMeArgon2id.deriveKeyWithProvider(provider, 1, bytes(32), bytes(16)));
add("Kmac.deriveKmac256WithProvider", (provider) => ReallyMeKmac.deriveKmac256WithProvider(provider, bytes(32), empty, empty, 32));
const hpkeSuite = "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305";
add("Hpke.sealBaseWithProvider", (provider) => ReallyMeHpke.sealBaseWithProvider(provider, hpkeSuite, bytes(32), empty, empty, empty));
add("Hpke.openBaseWithProvider", (provider) => ReallyMeHpke.openBaseWithProvider(provider, hpkeSuite, bytes(32), bytes(32), empty, empty, bytes(16)));
for (const [algorithm, publicLength, signatureLength] of [["ML-DSA-44", 1312, 2420], ["ML-DSA-65", 1952, 3309], ["ML-DSA-87", 2592, 4627]]) {
  add("MlDsa.generateKeyPairWithProvider", (provider) => ReallyMeMlDsa.generateKeyPairWithProvider(provider, algorithm));
  add("MlDsa.deriveKeyPairWithProvider", (provider) => ReallyMeMlDsa.deriveKeyPairWithProvider(provider, algorithm, bytes(32)));
  add("MlDsa.signWithProvider", (provider) => ReallyMeMlDsa.signWithProvider(provider, algorithm, empty, bytes(32)));
  add("MlDsa.verifyWithProvider", (provider) => ReallyMeMlDsa.verifyWithProvider(provider, algorithm, bytes(signatureLength), empty, bytes(publicLength)));
}
for (const [algorithm, publicLength, ciphertextLength] of [["ML-KEM-512", 800, 768], ["ML-KEM-768", 1184, 1088], ["ML-KEM-1024", 1568, 1568]]) {
  add("MlKem.generateKeyPairWithProvider", (provider) => ReallyMeMlKem.generateKeyPairWithProvider(provider, algorithm));
  add("MlKem.deriveKeyPairWithProvider", (provider) => ReallyMeMlKem.deriveKeyPairWithProvider(provider, algorithm, bytes(64)));
  add("MlKem.encapsulateWithProvider", (provider) => ReallyMeMlKem.encapsulateWithProvider(provider, algorithm, bytes(publicLength)));
  add("MlKem.decapsulateWithProvider", (provider) => ReallyMeMlKem.decapsulateWithProvider(provider, algorithm, bytes(ciphertextLength), bytes(64)));
}
add("SlhDsa.generateKeyPairWithProvider", (provider) => ReallyMeSlhDsa.generateKeyPairWithProvider(provider, "SLH-DSA-SHA2-128s"));
add("SlhDsa.signWithProvider", (provider) => ReallyMeSlhDsa.signWithProvider(provider, "SLH-DSA-SHA2-128s", empty, bytes(64)));
add("SlhDsa.verifyWithProvider", (provider) => ReallyMeSlhDsa.verifyWithProvider(provider, "SLH-DSA-SHA2-128s", bytes(7856), empty, bytes(32)));
add("SlhDsa.deriveForTest", (provider) => deriveSlhDsaSha2128sKeypairWithProviderForTest(provider, bytes(16), bytes(16), bytes(16)));
add("XWing.generateKeyPairWithProvider", (provider) => ReallyMeXWing.generateKeyPairWithProvider(provider, "X-Wing-768"));
add("XWing.deriveKeyPairWithProvider", (provider) => ReallyMeXWing.deriveKeyPairWithProvider(provider, "X-Wing-768", bytes(32)));
add("XWing.encapsulateWithProvider", (provider) => ReallyMeXWing.encapsulateWithProvider(provider, "X-Wing-768", bytes(1216)));
add("XWing.decapsulateWithProvider", (provider) => ReallyMeXWing.decapsulateWithProvider(provider, "X-Wing-768", bytes(1120), bytes(32)));
for (const algorithm of [
  "RSA-PKCS1v15-SHA1", "RSA-PKCS1v15-SHA256", "RSA-PKCS1v15-SHA384", "RSA-PKCS1v15-SHA512",
  "RSA-PSS-SHA1-MGF1-SHA1", "RSA-PSS-SHA256-MGF1-SHA256", "RSA-PSS-SHA384-MGF1-SHA384", "RSA-PSS-SHA512-MGF1-SHA512",
]) {
  add("Rsa.verifyWithProvider", (provider) => ReallyMeRsa.verifyWithProvider(provider, algorithm, bytes(256), empty, bytes(256), "SPKI"));
}
add("Operations.binary", (provider) => processOperationResponseWithProvider(provider, bytes(1)));
add("Operations.json", (provider) => processOperationResponseJsonWithProvider(provider, bytes(1)));

test("every explicit provider method has trust-boundary coverage", () => {
  const covered = new Set(routes.map(({ name }) => name));
  for (const [name, api] of Object.entries({ Aead: ReallyMeAead, AesKw: ReallyMeAesKw, Argon2id: ReallyMeArgon2id, Hpke: ReallyMeHpke, Kmac: ReallyMeKmac, MlDsa: ReallyMeMlDsa, MlKem: ReallyMeMlKem, Rsa: ReallyMeRsa, SlhDsa: ReallyMeSlhDsa, XWing: ReallyMeXWing })) {
    for (const method of Object.keys(api).filter((key) => key.endsWith("WithProvider"))) {
      assert.equal(covered.has(`${name}.${method}`), true, `${name}.${method}`);
    }
  }
});

test("all explicit provider routes reject fabricated identities before reading hooks", () => {
  let hookReads = 0;
  let hookCalls = 0;
  const noOpVerifier = () => { hookCalls += 1; };
  const forgedProvider = createWasmProviderFromModule({
    ...wasmProviderModule,
    mlDsa44Verify: noOpVerifier, mlDsa65Verify: noOpVerifier, mlDsa87Verify: noOpVerifier,
    slhDsaSha2128sVerify: noOpVerifier, rsaVerifyPkcs1v15: noOpVerifier, rsaVerifyPss: noOpVerifier,
  });
  const trappingProvider = new Proxy({}, { get() { hookReads += 1; return noOpVerifier; } });
  for (const provider of [undefined, null, 0, {}, Object.create(trustedProvider), { ...trustedProvider }, forgedProvider, trappingProvider]) {
    for (const { name, call } of routes) assertError(() => call(provider), "provider-failure", name);
  }
  assert.equal(hookReads, 0);
  assert.equal(hookCalls, 0);
});

const vector = (file) => JSON.parse(readFileSync(new URL(`../../../vectors/${file}`, import.meta.url), "utf8"));
const decode = (encoded) => Uint8Array.from(Buffer.from(encoded, "base64url"));
for (const [algorithm, file, api] of [
  ["ML-DSA-44", "ml_dsa_44.json", ReallyMeMlDsa],
  ["ML-DSA-65", "ml_dsa_65.json", ReallyMeMlDsa],
  ["ML-DSA-87", "ml_dsa_87.json", ReallyMeMlDsa],
  ["SLH-DSA-SHA2-128s", "slh_dsa_sha2_128s.json", ReallyMeSlhDsa],
]) {
  test(`trusted explicit ${algorithm} verification preserves valid and invalid results`, () => {
    const data = vector(file);
    const signature = decode(data.signature);
    const message = decode(data.message);
    const publicKey = decode(data.public_key);
    api.verifyWithProvider(trustedProvider, algorithm, signature, message, publicKey);
    signature[0] ^= 1;
    assertError(() => api.verifyWithProvider(trustedProvider, algorithm, signature, message, publicKey), "invalid-signature");
  });
}

test("provider byte readers accept owned outputs and wipe malformed independent outputs", () => {
  const input = bytes(32).fill(0x51);
  const valid = bytes(32).fill(0x62);
  assert.equal(readIndependentProviderBytes(valid, 32, [input]), valid);
  for (const length of [0, 31, 33]) {
    const output = bytes(length).fill(0x73);
    assertError(() => readIndependentProviderBytes(output, 32, [input]));
    assert.deepEqual(output, bytes(length));
  }
  const before = input.slice();
  for (const alias of [input, input.subarray(0, 31)]) {
    assertError(() => readIndependentProviderBytes(alias, 32, [input]));
    assert.deepEqual(input, before);
  }
  for (const malformed of [undefined, null, {}, []]) assertError(() => readIndependentProviderBytes(malformed, 32, [input]));
});

test("composite provider readers reject overlapping, malformed and throwing properties", () => {
  const input = bytes(64).fill(0x51);
  const publicKey = bytes(32).fill(0x62);
  const secretKey = bytes(32).fill(0x73);
  const pair = { publicKey, secretKey };
  assert.equal(readIndependentByteArrayProperty(pair, "secretKey", 32, [input, publicKey]), secretKey);
  for (const alias of [input.subarray(0, 32), publicKey]) {
    assertError(() => readIndependentByteArrayProperty({ secretKey: alias }, "secretKey", 32, [input, publicKey]));
  }
  assert.deepEqual(input, bytes(64).fill(0x51));
  assert.deepEqual(publicKey, bytes(32).fill(0x62));
  const storage = bytes(64).fill(0x73);
  const overlappingPair = { publicKey: storage.subarray(0, 32), secretKey: storage.subarray(16, 48) };
  const first = readIndependentByteArrayProperty(overlappingPair, "publicKey", 32, [input]);
  assertError(() => readIndependentByteArrayProperty(overlappingPair, "secretKey", 32, [input, first]));
  assert.deepEqual(storage, bytes(64).fill(0x73));
  const malformed = bytes(31).fill(0x84);
  assertError(() => readIndependentByteArrayProperty({ secretKey: malformed }, "secretKey", 32, []));
  assert.deepEqual(malformed, bytes(31));
  const throwing = Object.defineProperty(Object.create(null), "secretKey", { get() { throw 1; } });
  for (const object of [undefined, null, {}, { secretKey: [] }, throwing]) {
    assertError(() => readIndependentByteArrayProperty(object, "secretKey", 32, []));
  }
});
