#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
]);
const allowedBranches = new Set(["primitive", "provider", "backend"]);
const requiredLanes = new Set([
  "rust-native",
  "swift-native",
  "kotlin-jvm-native",
  "typescript-wasm",
]);

const failures = [];

const fail = (message) => {
  failures.push(message);
};

const readJson = (path) => JSON.parse(readFileSync(resolve(root, path), "utf8"));

const isNonEmptyString = (value) => typeof value === "string" && value.length !== 0;

const manifest = readJson("vectors/manifest.json");
if (!Array.isArray(manifest.negative_vectors) || manifest.negative_vectors.length === 0) {
  fail("vectors/manifest.json must declare at least one negative vector file");
}

const positiveVectors = new Set(Array.isArray(manifest.vectors) ? manifest.vectors : []);
const coveredAlgorithms = new Set();

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
    if (
      isNonEmptyString(testCase.positiveVector) &&
      !positiveVectors.has(testCase.positiveVector)
    ) {
      fail(`${testCase.id} references unknown positive vector ${testCase.positiveVector}`);
    }
    if (typeof testCase.expected !== "object" || testCase.expected === null) {
      fail(`${testCase.id} must declare expected typed failure semantics`);
      continue;
    }
    if (!isNonEmptyString(testCase.expected.facadeError)) {
      fail(`${testCase.id} must declare expected.facadeError`);
    }
    if (!allowedBranches.has(testCase.expected.wireBranch)) {
      fail(`${testCase.id} has unknown expected.wireBranch ${testCase.expected.wireBranch}`);
    }
    if (
      !isNonEmptyString(testCase.expected.reason) ||
      !testCase.expected.reason.startsWith("CRYPTO_ERROR_REASON_")
    ) {
      fail(`${testCase.id} must declare a stable CryptoErrorReason name`);
    }
    if (!Array.isArray(testCase.lanes) || testCase.lanes.length === 0) {
      fail(`${testCase.id} must declare executable or guarded lanes`);
      continue;
    }
    for (const lane of requiredLanes) {
      if (!testCase.lanes.includes(lane)) {
        fail(`${testCase.id} must declare ${lane} lane coverage or an explicit guard`);
      }
    }
  }
}

for (const algorithm of requiredAlgorithms) {
  if (!coveredAlgorithms.has(algorithm)) {
    fail(`negative vectors must cover ${algorithm}`);
  }
}

if (failures.length !== 0) {
  for (const message of failures) {
    console.error(`negative vector check failed: ${message}`);
  }
  process.exit(1);
}

console.log(`negative vector check passed: ${coveredAlgorithms.size} algorithms covered`);
