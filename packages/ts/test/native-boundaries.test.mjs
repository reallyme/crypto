// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import {
  ReallyMeBip340Schnorr,
  ReallyMeCryptoError,
  ReallyMeDigest,
  ReallyMeEd25519,
  ReallyMeHkdf,
  ReallyMeHmac,
  ReallyMeJwaConcatKdf,
  ReallyMeP256Ecdh,
  ReallyMeP256Ecdsa,
  ReallyMeP384Ecdh,
  ReallyMeP384Ecdsa,
  ReallyMeP521Ecdh,
  ReallyMeP521Ecdsa,
  ReallyMePbkdf2,
  ReallyMeSecp256k1,
  ReallyMeX25519,
} from "../dist/index.js";

const invalidInput = (error) =>
  error instanceof ReallyMeCryptoError && error.code === "invalid-input";
const bytes = new Uint8Array([1]);
const empty = new Uint8Array();
const keyFacades = [
  [ReallyMeEd25519, 32],
  [ReallyMeX25519, 32],
  [ReallyMeP256Ecdh, 32],
  [ReallyMeP384Ecdh, 48],
  [ReallyMeP521Ecdh, 66],
  [ReallyMeP256Ecdsa, 32],
  [ReallyMeP384Ecdsa, 48],
  [ReallyMeP521Ecdsa, 66],
  [ReallyMeSecp256k1, 32],
  [ReallyMeBip340Schnorr, 32],
];

test("imported keys own their bytes for Uint8Array and Node Buffer inputs", () => {
  for (const [facade, length] of keyFacades) {
    for (const input of [new Uint8Array(length), Buffer.alloc(length)]) {
      input[length - 1] = 1;
      const expected = new Uint8Array(input);
      const imported = facade.deriveKeyPair(input);
      assert.notEqual(imported.secretKey.buffer, input.buffer);
      input.fill(0);
      assert.deepEqual(new Uint8Array(imported.secretKey), expected);
      assert.deepEqual(facade.derivePublicKey(imported.secretKey), imported.publicKey);
      input.set(expected);
      imported.secretKey.fill(0);
      assert.deepEqual(new Uint8Array(input), expected);
    }
  }
});

test("native crypto boundaries reject non-byte arrays with typed errors", () => {
  const detached = new Uint8Array(1);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const malformed = [
    null, undefined, "secret", [1], { length: 1, 0: 1 },
    new Uint16Array([1]), new Uint8ClampedArray([1]), new Int8Array([1]),
    new DataView(new ArrayBuffer(1)),
    Object.create(Uint8Array.prototype), detached,
  ];
  const calls = [
    ...Object.values(ReallyMeDigest).map((digest) => (value) => digest(value)),
    (value) => ReallyMeHmac.authenticateSha256(value, bytes),
    (value) => ReallyMeHmac.authenticateSha384(bytes, value),
    (value) => ReallyMeHmac.authenticateSha512(value, bytes),
    (value) => ReallyMeHkdf.deriveSha256(value, empty, empty, 32),
    (value) => ReallyMeHkdf.deriveSha384(bytes, value, empty, 32),
    (value) => ReallyMeHkdf.deriveSha256(bytes, empty, value, 32),
    (value) => ReallyMePbkdf2.deriveHmacSha256(value, bytes, 100_000, 32),
    (value) => ReallyMePbkdf2.deriveHmacSha512(bytes, value, 100_000, 32),
    (value) => ReallyMeJwaConcatKdf.deriveSha256(value, bytes, empty, empty, 32),
    (value) => ReallyMeJwaConcatKdf.deriveSha256(bytes, value, empty, empty, 32),
    (value) => ReallyMeJwaConcatKdf.deriveSha256(bytes, bytes, value, empty, 32),
    (value) => ReallyMeJwaConcatKdf.deriveSha256(bytes, bytes, empty, value, 32),
  ];
  for (const [facade, length] of keyFacades) {
    const secretKey = new Uint8Array(length);
    secretKey[length - 1] = 1;
    const publicKey = facade.derivePublicKey(secretKey);
    calls.push((value) => facade.deriveKeyPair(value));
    if (facade.deriveSharedSecret) {
      calls.push((value) => facade.deriveSharedSecret(value, secretKey));
      calls.push((value) => facade.deriveSharedSecret(publicKey, value));
    } else {
      const message = new Uint8Array(32);
      const aux = new Uint8Array(32);
      const signature = facade.sign(message, secretKey, aux);
      calls.push((value) => facade.sign(value, secretKey, aux));
      calls.push((value) => facade.sign(message, value, aux));
      calls.push((value) => facade.verify(value, message, publicKey));
      calls.push((value) => facade.verify(signature, value, publicKey));
      calls.push((value) => facade.verify(signature, message, value));
    }
  }
  for (const value of malformed) {
    for (const call of calls) assert.throws(() => call(value), invalidInput);
    // undefined is the supported default for optional BIP-340 auxiliary entropy.
    if (value !== undefined) {
      assert.throws(
        () => ReallyMeBip340Schnorr.sign(new Uint8Array(32), new Uint8Array(32).fill(1), value),
        invalidInput,
      );
    }
  }
});

test("HMAC rejects shape-only tags and ignores overridden iterators", () => {
  for (const [authenticate, verify, length] of [
    [ReallyMeHmac.authenticateSha256, ReallyMeHmac.verifySha256, 32],
    [ReallyMeHmac.authenticateSha384, ReallyMeHmac.verifySha384, 48],
    [ReallyMeHmac.authenticateSha512, ReallyMeHmac.verifySha512, 64],
  ]) {
    const tag = authenticate(bytes, empty);
    assert.equal(verify(tag, bytes, empty), true);
    assert.throws(() => verify({ length, entries: () => [] }, bytes, empty), invalidInput);
    assert.throws(() => verify(Array.from(tag), bytes, empty), invalidInput);
    tag[0] ^= 1;
    tag.entries = () => [];
    assert.equal(verify(tag, bytes, empty), false);
  }
});

test("native byte boundaries preserve cross-realm Uint8Array interoperability", () => {
  const foreignBytes = runInNewContext("new Uint8Array([1, 2, 3])");
  const localBytes = new Uint8Array([1, 2, 3]);
  for (const digest of Object.values(ReallyMeDigest)) {
    assert.deepEqual(digest(foreignBytes), digest(localBytes));
  }
  assert.deepEqual(
    ReallyMeHmac.authenticateSha256(foreignBytes, foreignBytes),
    ReallyMeHmac.authenticateSha256(localBytes, localBytes),
  );
  for (const [facade, length] of keyFacades) {
    const input = runInNewContext("const key = new Uint8Array(length); key[length - 1] = 1; key", { length });
    const expected = facade.derivePublicKey(new Uint8Array(input));
    const imported = facade.deriveKeyPair(input);
    assert.deepEqual(imported.publicKey, expected);
    assert.notEqual(imported.secretKey.buffer, input.buffer);
    input.fill(0);
    assert.deepEqual(facade.derivePublicKey(imported.secretKey), expected);
  }
});

test("typed-array branding cannot be spoofed by element kind or toStringTag", () => {
  const impostor = new Int8Array([1, 2, 3]);
  Object.defineProperty(impostor, Symbol.toStringTag, { value: "Uint8Array" });
  assert.throws(() => ReallyMeDigest.sha256(impostor), invalidInput);
  const foreignWords = runInNewContext("new Uint16Array([1, 2, 3])");
  assert.throws(() => ReallyMeDigest.sha256(foreignWords), invalidInput);
});

test("HMAC compares every byte position without using a caller iterator", () => {
  const expected = ReallyMeHmac.authenticateSha512(bytes, empty);
  for (let position = 0; position < expected.length; position += 1) {
    const changed = new Uint8Array(expected);
    changed[position] ^= 1;
    assert.equal(ReallyMeHmac.verifySha512(changed, bytes, empty), false);
  }
});
