#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

const requiredAlgorithms = new Set([
  "DHKEM-P256-HKDF-SHA256-HKDF-SHA256-AES-256-GCM",
  "DHKEM-X25519-HKDF-SHA256-HKDF-SHA256-CHACHA20-POLY1305",
  "ML-KEM-768",
  "ML-DSA-65",
  "SLH-DSA-SHA2-128s",
  "X-Wing-768",
  "AES-256-GCM",
  "AES-256-KW",
  "X25519",
  "PBKDF2-HMAC-SHA-256",
  "RSA-PSS-SHA256-MGF1-SHA256",
  "P-256 platform key",
]);
const allowedBranches = new Set(["primitive", "provider", "backend"]);
const allowedFacadeErrors = new Set([
  "authenticationFailed",
  "invalidInput",
  "invalidSignature",
  "unsupportedAlgorithm",
]);
const requiredLanes = new Set([
  "rust-native",
  "swift-native",
  "kotlin-jvm-native",
  "typescript-wasm",
]);
const evidencePrefixes = Object.freeze({
  "rust-native": "crates/",
  "swift-native": "packages/swift/Tests/",
  "kotlin-jvm-native": "packages/kotlin/src/test/",
  "typescript-wasm": "packages/ts/test/",
});
const evidenceStatuses = new Set(["executable", "guarded", "hardware-skip-aware"]);

const failures = [];

const fail = (message) => {
  failures.push(message);
};

const readJson = (path) => JSON.parse(readFileSync(resolve(root, path), "utf8"));

const isNonEmptyString = (value) => typeof value === "string" && value.length !== 0;

function validateCaseEvidence(testCase) {
  const evidence = testCase.evidence;
  if (typeof evidence !== "object" || evidence === null || Array.isArray(evidence)) {
    fail(`${testCase.id} must bind each lane to an executable test or guard`);
    return;
  }
  if (Object.keys(evidence).length !== requiredLanes.size) {
    fail(`${testCase.id} has missing or unexpected lane evidence`);
  }
  for (const lane of requiredLanes) {
    const item = evidence[lane];
    if (typeof item !== "object" || item === null || Array.isArray(item) ||
        !isNonEmptyString(item.path) || !isNonEmptyString(item.test) ||
        !evidenceStatuses.has(item.status)) {
      fail(`${testCase.id} has invalid ${lane} test evidence`);
      continue;
    }
    if (!item.path.startsWith(evidencePrefixes[lane]) ||
        !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/u.test(item.path) ||
        item.path.split("/").includes("..")) {
      fail(`${testCase.id} has an unsafe ${lane} evidence path`);
      continue;
    }
    const path = resolve(root, item.path);
    if (!existsSync(path)) {
      fail(`${testCase.id} ${lane} evidence file is missing`);
      continue;
    }
    const source = readFileSync(path, "utf8");
    const declaration = lane === "typescript-wasm"
      ? `test("${item.test}"`
      : `${lane === "rust-native" ? "fn" : lane === "swift-native" ? "func" : "fun"} ${item.test}(`;
    if (!source.includes(declaration)) {
      fail(`${testCase.id} ${lane} evidence does not identify a declared test`);
    }
    if (item.status === "hardware-skip-aware" && lane !== "swift-native") {
      fail(`${testCase.id} uses a hardware skip outside Swift`);
    }
    if (item.status === "guarded" && testCase.id !== "platform-key-secure-enclave-duplicate-tag") {
      fail(`${testCase.id} claims a guard for an executable primitive`);
    }
  }
}

const protoSource = readFileSync(
  resolve(root, "crates/proto/proto/reallyme/crypto/v1/crypto.proto"),
  "utf8",
);
const errorReasonBlock = /enum CryptoErrorReason\s*\{(?<body>[\s\S]*?)\n\}/u.exec(protoSource);
if (errorReasonBlock?.groups?.body === undefined) {
  fail("CryptoErrorReason enum could not be read from the canonical protobuf schema");
}
const errorReasonNames = new Set(
  [...(errorReasonBlock?.groups?.body ?? "").matchAll(/\b(CRYPTO_ERROR_REASON_[A-Z0-9_]+)\s*=/gu)]
    .map((match) => match[1]),
);

const expectedReasonPrefix = Object.freeze({
  primitive: "CRYPTO_ERROR_REASON_PRIMITIVE_",
  provider: "CRYPTO_ERROR_REASON_PROVIDER_",
  backend: "CRYPTO_ERROR_REASON_BACKEND_",
});

function validateTypedError(expected, id) {
  if (typeof expected !== "object" || expected === null || Array.isArray(expected)) {
    fail(`${id} must declare expected typed failure semantics`);
    return;
  }
  if (!allowedFacadeErrors.has(expected.facadeError)) {
    fail(`${id} has unknown expected.facadeError ${expected.facadeError}`);
  }
  if (!allowedBranches.has(expected.wireBranch)) {
    fail(`${id} has unknown expected.wireBranch ${expected.wireBranch}`);
    return;
  }
  if (!isNonEmptyString(expected.reason) || !errorReasonNames.has(expected.reason)) {
    fail(`${id} must name an existing CryptoErrorReason`);
    return;
  }
  if (!expected.reason.startsWith(expectedReasonPrefix[expected.wireBranch])) {
    fail(`${id} reason does not belong to its declared wire branch`);
  }
}

const manifest = readJson("vectors/manifest.json");
if (!Array.isArray(manifest.negative_vectors) || manifest.negative_vectors.length === 0) {
  fail("vectors/manifest.json must declare at least one negative vector file");
}

const positiveVectors = new Set(Array.isArray(manifest.vectors) ? manifest.vectors : []);
const lifecycleVectors = new Set(
  Array.isArray(manifest.lifecycle_vectors) ? manifest.lifecycle_vectors : [],
);
const coveredAlgorithms = new Set();
const coveredOperations = new Set();

for (const vectorPath of manifest.negative_vectors ?? []) {
  if (!isNonEmptyString(vectorPath)) {
    fail("negative vector paths must be non-empty strings");
    continue;
  }
  const fullPath = resolve(root, "vectors", vectorPath);
  if (!existsSync(fullPath)) {
    fail(`negative vector file ${vectorPath} does not exist`);
    continue;
  }
  const vector = readJson(`vectors/${vectorPath}`);
  if (vector.schemaVersion !== 1) {
    fail(`${vectorPath} schemaVersion must be 1`);
  }
  if (!Array.isArray(vector.cases) || vector.cases.length === 0) {
    fail(`${vectorPath} must contain at least one negative case`);
    continue;
  }
  const ids = new Set();
  for (const testCase of vector.cases) {
    if (!isNonEmptyString(testCase.id)) {
      fail(`${vectorPath} contains a case without an id`);
      continue;
    }
    if (ids.has(testCase.id)) {
      fail(`${vectorPath} contains duplicate case id ${testCase.id}`);
    }
    ids.add(testCase.id);
    for (const field of ["algorithm", "operation", "positiveVector", "mutation"]) {
      if (!isNonEmptyString(testCase[field])) {
        fail(`${testCase.id} must declare ${field}`);
      }
    }
    if (isNonEmptyString(testCase.algorithm)) {
      coveredAlgorithms.add(testCase.algorithm);
    }
    if (isNonEmptyString(testCase.operation)) {
      coveredOperations.add(testCase.operation);
    }
    if (
      isNonEmptyString(testCase.positiveVector) &&
      !positiveVectors.has(testCase.positiveVector) &&
      !lifecycleVectors.has(testCase.positiveVector)
    ) {
      fail(`${testCase.id} references unknown positive vector ${testCase.positiveVector}`);
    }
    validateTypedError(testCase.expected, testCase.id);
    if (!Array.isArray(testCase.lanes) || testCase.lanes.length === 0) {
      fail(`${testCase.id} must declare executable or guarded lanes`);
      continue;
    }
    for (const lane of requiredLanes) {
      if (!testCase.lanes.includes(lane)) {
        fail(`${testCase.id} must declare ${lane} lane coverage or an explicit guard`);
      }
    }
    validateCaseEvidence(testCase);
  }
}

const requiredLifecycleIds = new Set([
  "swift-secure-enclave-ecdh-handle-validation",
  "swift-secure-enclave-ecdh-round-trip",
  "swift-secure-enclave-ecdh-duplicate-tag",
  "swift-secure-enclave-ecdh-idempotent-delete",
  "swift-secure-enclave-signing-handle-validation",
  "swift-secure-enclave-signing-verifier",
  "swift-secure-enclave-signing-round-trip",
  "swift-secure-enclave-signing-duplicate-tag",
  "android-strongbox-signing-round-trip",
]);
const lifecycleLaneNames = new Set([
  "swift",
  "kotlin_android",
  "kotlin_jvm",
  "typescript_wasm",
]);
const lifecycleLaneStatuses = new Set(["executable", "hardware-skip-aware", "unsupported"]);
const coveredLifecycleIds = new Set();

for (const vectorPath of lifecycleVectors) {
  if (!isNonEmptyString(vectorPath)) {
    fail("lifecycle vector paths must be non-empty strings");
    continue;
  }
  const fullPath = resolve(root, "vectors", vectorPath);
  if (!existsSync(fullPath)) {
    fail(`lifecycle vector file ${vectorPath} does not exist`);
    continue;
  }
  const vector = readJson(`vectors/${vectorPath}`);
  if (vector.schemaVersion !== 1 || !Array.isArray(vector.cases) || vector.cases.length === 0) {
    fail(`${vectorPath} must use schemaVersion 1 and contain lifecycle cases`);
    continue;
  }

  for (const testCase of vector.cases) {
    if (!isNonEmptyString(testCase.id)) {
      fail(`${vectorPath} contains a lifecycle case without an id`);
      continue;
    }
    if (coveredLifecycleIds.has(testCase.id)) {
      fail(`duplicate lifecycle case id ${testCase.id}`);
    }
    coveredLifecycleIds.add(testCase.id);
    for (const field of [
      "provider",
      "securityLevel",
      "purpose",
      "algorithm",
      "operation",
      "handlePrefix",
      "scenario",
    ]) {
      if (!isNonEmptyString(testCase[field])) {
        fail(`${testCase.id} must declare ${field}`);
      }
    }
    if (testCase.tagLength?.min !== 1 || testCase.tagLength?.max !== 256) {
      fail(`${testCase.id} must pin platform-key tag lengths to 1..256 bytes`);
    }
    if (testCase.expected?.outcome === "error") {
      validateTypedError(testCase.expected, testCase.id);
    } else if (
      testCase.expected?.outcome !== "success" ||
      !Array.isArray(testCase.expected.assertions) ||
      testCase.expected.assertions.length === 0 ||
      testCase.expected.assertions.some((assertion) => !isNonEmptyString(assertion))
    ) {
      fail(`${testCase.id} success outcome must declare observable assertions`);
    }

    if (!isNonEmptyString(testCase.evidence?.path) || !isNonEmptyString(testCase.evidence?.test)) {
      fail(`${testCase.id} must bind to executable test evidence`);
    } else {
      const evidencePath = resolve(root, testCase.evidence.path);
      if (!evidencePath.startsWith(`${root}/`) || !existsSync(evidencePath)) {
        fail(`${testCase.id} references missing in-repository evidence`);
      } else if (!readFileSync(evidencePath, "utf8").includes(testCase.evidence.test)) {
        fail(`${testCase.id} references a missing evidence test`);
      }
    }

    const laneEntries = Object.entries(testCase.lanes ?? {});
    if (laneEntries.length !== lifecycleLaneNames.size) {
      fail(`${testCase.id} must classify exactly four SDK lanes`);
    }
    for (const [lane, status] of laneEntries) {
      if (!lifecycleLaneNames.has(lane) || !lifecycleLaneStatuses.has(status)) {
        fail(`${testCase.id} has invalid lifecycle lane classification ${lane}:${status}`);
      }
    }
  }
}

for (const id of requiredLifecycleIds) {
  if (!coveredLifecycleIds.has(id)) {
    fail(`platform-key lifecycle vectors must cover ${id}`);
  }
}

for (const algorithm of requiredAlgorithms) {
  if (!coveredAlgorithms.has(algorithm)) {
    fail(`negative vectors must cover ${algorithm}`);
  }
}

for (const operation of [
  "aead_open",
  "hpke_open",
  "jwk_import",
  "kdf_derive",
  "kem_decapsulate",
  "key_agreement_derive_shared_secret",
  "key_unwrap",
  "platform_key_lifecycle",
  "signature_verify",
]) {
  if (!coveredOperations.has(operation)) {
    fail(`negative vectors must cover ${operation}`);
  }
}

if (failures.length !== 0) {
  for (const message of failures) {
    console.error(`negative vector check failed: ${message}`);
  }
  process.exit(1);
}

console.log(
  `negative vector check passed: ${coveredAlgorithms.size} algorithms and ${coveredLifecycleIds.size} lifecycle cases covered`,
);
