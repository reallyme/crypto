// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ReallyMeBip340Schnorr, ReallyMeCryptoError } from "../dist/index.js";

const vector = JSON.parse(readFileSync(new URL("../../../vectors/bip340_schnorr.json", import.meta.url), "utf8"));
const bytes = (field) => Uint8Array.from(Buffer.from(vector[field], "base64url"));

test("BIP-340 shared invalid public keys map to invalid-input across SDK lanes", () => {
  const signature = bytes("signature");
  const message = bytes("message");
  const publicKey = bytes("public_key_xonly");
  ReallyMeBip340Schnorr.verify(signature, message, publicKey);
  for (const field of ["invalid_off_curve_public_key_xonly", "invalid_out_of_range_public_key_xonly"]) {
    assert.throws(
      () => ReallyMeBip340Schnorr.verify(signature, message, bytes(field)),
      (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-input",
    );
  }
  signature[0] ^= 1;
  assert.throws(
    () => ReallyMeBip340Schnorr.verify(signature, message, publicKey),
    (error) => error instanceof ReallyMeCryptoError && error.code === "invalid-signature",
  );
});
