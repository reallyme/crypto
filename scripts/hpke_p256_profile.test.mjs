// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createCipheriv, createECDH, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const vector = JSON.parse(readFileSync(new URL("../crates/hpke/tests/data/base_p256.json", import.meta.url), "utf8"));
const bytes = (hex) => Buffer.from(hex, "hex");
const text = (value) => Buffer.from(value, "ascii");
const concat = (...values) => Buffer.concat(values);
const hmac = (key, input) => createHmac("sha256", key).update(input).digest();
const kemSuite = concat(text("KEM"), bytes("0010"));
const suite = concat(text("HPKE"), bytes("001000010001"));

function extract(suiteId, salt, label, ikm) {
  return hmac(salt, concat(text("HPKE-v1"), suiteId, text(label), ikm));
}

function expand(suiteId, prk, label, info, length) {
  assert.ok(length <= 32);
  const size = Buffer.alloc(2);
  size.writeUInt16BE(length);
  return hmac(prk, concat(size, text("HPKE-v1"), suiteId, text(label), info, bytes("01"))).subarray(0, length);
}

function derive(ikm) {
  const prk = extract(kemSuite, Buffer.alloc(0), "dkp_prk", ikm);
  const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  for (let counter = 0; counter <= 255; counter += 1) {
    const scalar = expand(kemSuite, prk, "candidate", Buffer.from([counter]), 32);
    const value = BigInt(`0x${scalar.toString("hex")}`);
    if (value > 0n && value < order) {
      const key = createECDH("prime256v1");
      key.setPrivateKey(scalar);
      return { scalar, key, public: key.getPublicKey(undefined, "uncompressed") };
    }
  }
  assert.fail("published derivation input did not produce a key");
}

test("P-256 Base profile agrees with an independent RFC 9180 calculation", () => {
  const recipient = derive(bytes(vector.ikmR));
  const sender = derive(bytes(vector.ikmE));
  assert.equal(recipient.scalar.toString("hex"), vector.skRm);
  assert.equal(recipient.public.toString("hex"), vector.pkRm);
  assert.equal(sender.public.toString("hex"), vector.enc);
  const dh = sender.key.computeSecret(recipient.public);
  const eae = extract(kemSuite, Buffer.alloc(0), "eae_prk", dh);
  const secret = expand(kemSuite, eae, "shared_secret", concat(sender.public, recipient.public), 32);
  const pskIdHash = extract(suite, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = extract(suite, Buffer.alloc(0), "info_hash", bytes(vector.info));
  const context = concat(bytes("00"), pskIdHash, infoHash);
  const schedule = extract(suite, secret, "secret", Buffer.alloc(0));
  const key = expand(suite, schedule, "key", context, 16);
  const nonce = expand(suite, schedule, "base_nonce", context, 12);
  assert.equal(key.toString("hex"), vector.key);
  assert.equal(nonce.toString("hex"), vector.base_nonce);
  const encrypt = (aad) => {
    const cipher = createCipheriv("aes-128-gcm", key, nonce);
    cipher.setAAD(aad);
    return concat(cipher.update(bytes(vector.encryption.pt)), cipher.final(), cipher.getAuthTag()).toString("hex");
  };
  // Retain the RFC's nonempty AAD case unchanged; the profile has a distinct
  // expected tag because it supplies empty AAD to exactly the same context.
  assert.equal(encrypt(bytes(vector.encryption.aad)), vector.encryption.ct);
  assert.equal(encrypt(Buffer.alloc(0)), vector.empty_aad_ciphertext);
});
