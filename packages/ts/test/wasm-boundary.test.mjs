// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  ReallyMeAead,
  ReallyMeArgon2id,
  ReallyMeCryptoError,
  ReallyMeEd25519,
  ReallyMeHpke,
  ReallyMeKmac,
  ReallyMeMlKem,
  ReallyMeP256Ecdsa,
  ReallyMeRsa,
  ReallyMeSecp256k1,
  ReallyMeX25519,
  createReallyMeWasmProvider,
} from "../dist/index.js";
import {
  CryptoOperationRequestSchema,
  CryptoOperationResponseSchema,
  KeyAgreementAlgorithm,
  SignatureAlgorithm,
} from "../dist/proto.js";
import {
  initializeWasm,
  mlDsa44DeriveKeypair,
  mlKem512DeriveKeypair,
  processOperationResponse,
  slhDsaSha2128sDeriveKeypair,
  wasmProviderModule,
} from "./wasm-provider-module.mjs";

const WASM_INVALID_INPUT = 1;
const ML_KEM_512_PUBLIC_KEY_LENGTH = 800;
const ML_KEM_SEED_LENGTH = 64;

const wasmBytes = readFileSync(
  new URL("../dist/wasm/reallyme_crypto_wasm_bg.wasm", import.meta.url),
);
initializeWasm(wasmBytes);

const packageProvider = createReallyMeWasmProvider(wasmProviderModule);

const assertReallyMeError = (operation, code) => {
  assert.throws(
    operation,
    (error) => error instanceof ReallyMeCryptoError && error.code === code,
  );
};

const processOperation = (operation, expectedResultCase) => {
  const request = create(CryptoOperationRequestSchema, { operation });
  const response = fromBinary(
    CryptoOperationResponseSchema,
    processOperationResponse(toBinary(CryptoOperationRequestSchema, request)),
  );
  assert.equal(response.outcome.case, "result");
  assert.equal(response.outcome.value.result.case, expectedResultCase);
  return response.outcome.value.result.value;
};

const signatureIdentifier = (algorithm) => ({
  algorithm: { case: "signature", value: algorithm },
});

test("structured WASM operations compile classical derivation without semantic host imports", () => {
  const secretKey = new Uint8Array(32);
  secretKey[31] = 1;

  for (const [algorithm, expectedPublicKey] of [
    [SignatureAlgorithm.ED25519, ReallyMeEd25519.derivePublicKey(secretKey)],
    [SignatureAlgorithm.ECDSA_P256_SHA256, ReallyMeP256Ecdsa.derivePublicKey(secretKey)],
    [
      SignatureAlgorithm.ECDSA_SECP256K1_SHA256,
      ReallyMeSecp256k1.derivePublicKey(secretKey),
    ],
  ]) {
    const keyPair = processOperation(
      {
        case: "signatureDeriveKeyPair",
        value: {
          algorithm: signatureIdentifier(algorithm),
          secretKey,
        },
      },
      "signatureDeriveKeyPair",
    );
    assert.deepEqual(keyPair.publicKey, expectedPublicKey);
    assert.deepEqual(keyPair.secretKey, secretKey);
    keyPair.secretKey.fill(0);
  }

  const x25519KeyPair = processOperation(
    {
      case: "keyAgreementDeriveKeyPair",
      value: {
        algorithm: {
          algorithm: {
            case: "keyAgreement",
            value: KeyAgreementAlgorithm.X25519,
          },
        },
        secretKey,
      },
    },
    "keyAgreementDeriveKeyPair",
  );
  assert.deepEqual(x25519KeyPair.publicKey, ReallyMeX25519.derivePublicKey(secretKey));
  assert.deepEqual(x25519KeyPair.secretKey, secretKey);
  x25519KeyPair.secretKey.fill(0);
  secretKey.fill(0);
});

test("fixed-size WASM inputs reject malformed lengths before copying", () => {
  const oversized = new Uint8Array(2 * 1_048_576);
  const validSlhSeed = new Uint8Array(16);

  for (const invalidSeed of [new Uint8Array(31), new Uint8Array(33), oversized]) {
    assert.throws(
      () => mlDsa44DeriveKeypair(invalidSeed),
      (error) => error === WASM_INVALID_INPUT,
    );
  }
  for (const invalidSeed of [new Uint8Array(63), new Uint8Array(65), oversized]) {
    assert.throws(
      () => mlKem512DeriveKeypair(invalidSeed),
      (error) => error === WASM_INVALID_INPUT,
    );
  }
  for (const invalidSeed of [new Uint8Array(15), new Uint8Array(17), oversized]) {
    assert.throws(
      () => slhDsaSha2128sDeriveKeypair(invalidSeed, validSlhSeed, validSlhSeed),
      (error) => error === WASM_INVALID_INPUT,
    );
  }
  oversized.fill(0);
  validSlhSeed.fill(0);
});

test("variable-length WASM inputs reject oversized buffers before provider dispatch", () => {
  const oversized = new Uint8Array(1_048_577);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);
  const salt = new Uint8Array(16);
  const p256PublicKey = new Uint8Array(65);
  const empty = new Uint8Array();

  for (const operation of [
    () => wasmProviderModule.aes256GcmSivSeal(key, nonce, empty, oversized),
    () => wasmProviderModule.argon2idDeriveKey(1, oversized, salt),
    () => wasmProviderModule.hpkeSealBase(1, p256PublicKey, empty, empty, oversized),
    () => wasmProviderModule.mlDsa44Sign(key, oversized),
    () => wasmProviderModule.slhDsaSha2128sSign(new Uint8Array(64), oversized),
  ]) {
    assert.throws(operation, (error) => error === WASM_INVALID_INPUT);
  }

  let providerCalls = 0;
  const countingProvider = createReallyMeWasmProvider({
    ...wasmProviderModule,
    aes256GcmSivSeal: () => {
      providerCalls += 1;
      return new Uint8Array();
    },
    argon2idDeriveKey: () => {
      providerCalls += 1;
      return new Uint8Array(32);
    },
    hpkeSealBase: () => {
      providerCalls += 1;
      return Object.create(null);
    },
  });
  assertReallyMeError(
    () =>
      ReallyMeAead.sealWithProvider(
        countingProvider,
        "AES-256-GCM-SIV",
        key,
        nonce,
        empty,
        oversized,
      ),
    "invalid-input",
  );
  assertReallyMeError(
    () => ReallyMeArgon2id.deriveKeyWithProvider(countingProvider, 1, oversized, salt),
    "invalid-input",
  );
  assertReallyMeError(
    () =>
      ReallyMeHpke.sealBaseWithProvider(
        countingProvider,
        "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
        p256PublicKey,
        empty,
        empty,
        oversized,
      ),
    "invalid-input",
  );
  assert.equal(providerCalls, 0);

  oversized.fill(0);
  key.fill(0);
  salt.fill(0);
});

test("custom seed-derived providers have an explicit correspondence trust boundary", () => {
  const seed = new Uint8Array(ML_KEM_SEED_LENGTH).fill(0x37);
  const packageKeyPair = ReallyMeMlKem.deriveKeyPairWithProvider(
    packageProvider,
    "ML-KEM-512",
    seed,
  );
  const mismatchedPublicKey = packageKeyPair.publicKey.slice();
  mismatchedPublicKey[0] ^= 1;
  assert.notDeepEqual(mismatchedPublicKey, packageKeyPair.publicKey);

  const customProvider = createReallyMeWasmProvider({
    ...wasmProviderModule,
    mlKem512DeriveKeypair: () => ({
      publicKey: mismatchedPublicKey.slice(),
      secretKey: seed.slice(),
    }),
  });
  const customKeyPair = ReallyMeMlKem.deriveKeyPairWithProvider(
    customProvider,
    "ML-KEM-512",
    seed,
  );

  // The package-owned provider is self-verified because Rust derives both
  // halves. A deliberately supplied provider remains a documented trust
  // boundary and must carry its own correspondence conformance evidence.
  assert.equal(customKeyPair.publicKey.length, ML_KEM_512_PUBLIC_KEY_LENGTH);
  assert.deepEqual(customKeyPair.publicKey, mismatchedPublicKey);
  customKeyPair.secretKey.fill(0);
  packageKeyPair.secretKey.fill(0);
  seed.fill(0);
});

test("facades reject raw-WASM numeric truncation candidates before dispatch", () => {
  let providerCalls = 0;
  const rejectingProvider = createReallyMeWasmProvider({
    ...wasmProviderModule,
    argon2idDeriveKey: () => {
      providerCalls += 1;
      return new Uint8Array(32);
    },
    kmac256Derive: () => {
      providerCalls += 1;
      return new Uint8Array(32);
    },
    hpkeSealBase: () => {
      providerCalls += 1;
      return Object.create(null);
    },
    rsaVerifyPss: () => {
      providerCalls += 1;
    },
  });
  const key = new Uint8Array(32);
  const salt = new Uint8Array(16);
  const wrapsToSupportedU32 = 2 ** 32 + 1;

  assertReallyMeError(
    () => ReallyMeArgon2id.deriveKeyWithProvider(rejectingProvider, wrapsToSupportedU32, key, salt),
    "invalid-input",
  );
  assertReallyMeError(
    () => ReallyMeKmac.deriveKmac256WithProvider(rejectingProvider, key, key, key, 2 ** 32 + 32),
    "invalid-input",
  );
  assertReallyMeError(
    () => ReallyMeHpke.sealBaseWithProvider(rejectingProvider, wrapsToSupportedU32, key, key, key, key),
    "invalid-input",
  );
  assertReallyMeError(
    () => ReallyMeRsa.verifyWithProvider(rejectingProvider, 2 ** 32 + 410, key, key, key, "SPKI"),
    "unsupported-algorithm",
  );
  assert.equal(providerCalls, 0);
  key.fill(0);
  salt.fill(0);
});

test("WASM numeric error codes map to typed SDK errors without untyped strings", () => {
  const key = new Uint8Array(32);
  const salt = new Uint8Array(16);
  const numericProvider = createReallyMeWasmProvider({
    ...wasmProviderModule,
    argon2idDeriveKey: () => {
      throw WASM_INVALID_INPUT;
    },
  });
  const stringErrorProvider = createReallyMeWasmProvider({
    ...wasmProviderModule,
    argon2idDeriveKey: () => {
      throw "invalid-input";
    },
  });

  assertReallyMeError(
    () => ReallyMeArgon2id.deriveKeyWithProvider(numericProvider, 1, key, salt),
    "invalid-input",
  );
  assertReallyMeError(
    () => ReallyMeArgon2id.deriveKeyWithProvider(stringErrorProvider, 1, key, salt),
    "provider-failure",
  );
  key.fill(0);
  salt.fill(0);
});
