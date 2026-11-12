// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign, verify, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const load = (name) => JSON.parse(readFileSync(new URL(`../crates/crypto/tests/data/${name}.json`, import.meta.url), "utf8"));
const bytes = (hex) => Buffer.from(hex, "hex");
const concatenate = (...values) => Buffer.concat(values);
const curveOids = new Map([
  ["P256", "06082a8648ce3d030107"], ["P384", "06052b81040022"], ["P521", "06052b81040023"],
  ["BrainpoolP256r1", "06092b2403030208010107"], ["BrainpoolP320r1", "06092b2403030208010109"],
  ["BrainpoolP384r1", "06092b240303020801010b"], ["BrainpoolP512r1", "06092b240303020801010d"],
]);

function der(tag, content) {
  assert.ok(content.length <= 255);
  const length = content.length < 128 ? Buffer.from([content.length]) : Buffer.from([0x81, content.length]);
  return concatenate(Buffer.from([tag]), length, content);
}

function spki(curve, point) {
  const oid = curveOids.get(curve);
  assert.ok(oid);
  return der(0x30, concatenate(der(0x30, concatenate(bytes("06072a8648ce3d0201"), bytes(oid))), der(0x03, concatenate(bytes("00"), point))));
}

test("all 21 explicit curve/hash signature answers verify independently", () => {
  const vectors = load("ecdsa_explicit").vectors;
  assert.equal(vectors.length, 7);
  let executed = 0;
  for (const vector of vectors) {
    const key = createPublicKey({ key: spki(vector.curve, bytes(vector.public)), format: "der", type: "spki" });
    for (const signature of vector.signatures) {
      const options = { key, dsaEncoding: "ieee-p1363" };
      assert.ok(verify(signature.hash, bytes(vector.message), options, bytes(signature.raw)));
      assert.ok(verify(signature.hash, bytes(vector.message), options, bytes(signature.high_s_raw)));
      const changed = bytes(vector.message);
      changed[0] ^= 1;
      assert.equal(verify(signature.hash, changed, options, bytes(signature.raw)), false);
      executed += 1;
    }
  }
  assert.equal(executed, 21);
});

test("ordinary Ed448 vectors agree with an independent implementation", () => {
  let executed = 0;
  for (const vector of load("ed448_rfc8032").vectors) {
    const publicKey = createPublicKey({ key: concatenate(bytes("3043300506032b6571033a00"), bytes(vector.public)), format: "der", type: "spki" });
    if (vector.prehash === "false" && vector.context === "") {
      const privateKey = createPrivateKey({ key: concatenate(bytes("3047020100300506032b6571043b0439"), bytes(vector.seed)), format: "der", type: "pkcs8" });
      assert.equal(sign(null, bytes(vector.message), privateKey).toString("hex"), vector.signature);
      assert.ok(verify(null, bytes(vector.message), publicKey, bytes(vector.signature)));
      executed += 1;
    } else {
      assert.equal(verify(null, bytes(vector.message), publicKey, bytes(vector.signature)), false);
    }
  }
  assert.equal(executed, 8);
});

test("certificate and CRL answers bind the exact externally supplied TBS spans", () => {
  const vectors = load("certificate_crl_signatures").vectors;
  assert.equal(vectors.length, 42);
  for (const vector of vectors) {
    const key = createPublicKey({ key: spki(vector.curve, bytes(vector.public)), format: "der", type: "spki" });
    assert.ok(verify(vector.hash, bytes(vector.tbs), key, bytes(vector.signature_der)));
    assert.equal(verify(vector.hash, bytes(vector.der), key, bytes(vector.signature_der)), false);
    if (vector.kind === "certificate") {
      const certificate = new X509Certificate(bytes(vector.der));
      assert.ok(certificate.verify(key));
      assert.deepEqual(certificate.publicKey.export({ type: "spki", format: "der" }), spki(vector.curve, bytes(vector.public)));
    }
  }
});

test("legacy key identifiers hash the subjectPublicKey value alone", () => {
  const sha1 = (value) => createHash("sha1").update(value).digest("hex");
  const vectors = load("key_identifiers").vectors;
  assert.equal(vectors.length, 7);
  for (const vector of vectors) {
    const bits = bytes(vector.subject_public_key_bits);
    assert.equal(sha1(bits), vector.identifier);
    assert.notEqual(sha1(bits.subarray(1)), vector.identifier);
    assert.equal(sha1(bytes(vector.compressed_key_bits)), vector.compressed_identifier);
    assert.notEqual(vector.compressed_identifier, vector.identifier);
    assert.notEqual(sha1(concatenate(bytes("00"), bits)), vector.identifier);
    assert.notEqual(sha1(der(0x03, concatenate(bytes("00"), bits))), vector.identifier);
    assert.notEqual(sha1(spki(vector.curve, bits)), vector.identifier);
  }
});

test("SHA-2 leaves retain protected state through output serialization", () => {
  for (const crate of ["sha2-256", "sha2"]) {
    const source = (file) => readFileSync(new URL(`../crates/${crate}/src/${file}.rs`, import.meta.url), "utf8");
    const leaf = source("digest");
    const implementation = source("hash_message");
    assert.doesNotMatch(leaf + implementation, /\.finalize(?:_into)?\s*\(/, "fixed-output wrappers must not stage an unguarded finalized array");
    assert.match(leaf, /crate::hash_message::hash\(/);
    assert.match(leaf, /ZeroizeOnDrop/);
    assert.match(implementation, /let mut state = Zeroizing::new\(/);
    assert.match(implementation, /let mut buffer = Zeroizing::new\(Buffer/);
    assert.match(implementation, /let encoded = Zeroizing::new\(word.to_be_bytes\(\)\)/);
    assert.match(implementation, /destination.copy_from_slice\(encoded.as_ref\(\)\)/);
    assert.doesNotMatch(implementation, /(?:Sha256|Sha384|Sha512)::(?:new|digest)\(/);
  }
});

test("HKDF expansion writes through its clearing output owner", () => {
  for (const file of ["derive", "sha384"]) {
    const source = readFileSync(new URL(`../crates/hkdf/src/${file}.rs`, import.meta.url), "utf8");
    assert.match(source, /let mut output = HkdfOutput::from_array\(\[0u8; N\]\)/);
    assert.match(source, /\.expand\([^;]*output\.as_mut_bytes\(\)\)/s);
    assert.doesNotMatch(source, /let mut (?:output|bytes) = \[0u8;/);
    assert.doesNotMatch(source, /Ok\(HkdfOutput::from_array\(output\)\)/);
  }
});
