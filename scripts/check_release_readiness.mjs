#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rustRootVersion = "0.1.7";
const typescriptPackageVersion = "0.1.6";
const kotlinPackageVersion = "0.1.6";
const requiredLanes = ["swift", "kotlin_jvm", "kotlin_android", "typescript_wasm"];
const allowedStatuses = new Set(["supported", "provider_aware", "partial", "unsupported"]);
const allowedFallbacks = new Set([
  "typed_provider_failure",
  "typed_unsupported_algorithm",
  "explicit_provider_required",
]);

const readText = (path) => readFileSync(resolve(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

const fail = (message) => {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
};

const assertContains = (path, needle) => {
  if (!readText(path).includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
};

const manifest = readJson("provider_manifest.json");
const byId = new Map();
for (const algorithm of manifest.algorithms) {
  byId.set(algorithm.id, algorithm);
}

const resolveAlgorithm = (algorithm) => {
  if (algorithm.lanes) {
    return algorithm;
  }
  const source = byId.get(algorithm.sameAs);
  if (!source || !source.lanes) {
    fail(`unresolved sameAs for ${algorithm.id}`);
  }
  return { ...algorithm, lanes: source.lanes };
};

const statusCounts = new Map();
for (const rawAlgorithm of manifest.algorithms) {
  const algorithm = resolveAlgorithm(rawAlgorithm);
  for (const laneName of requiredLanes) {
    const lane = algorithm.lanes[laneName];
    if (!lane) {
      fail(`${algorithm.id} is missing lane ${laneName}`);
    }
    if (!allowedStatuses.has(lane.status)) {
      fail(`${algorithm.id}/${laneName} has unknown status ${lane.status}`);
    }
    if (!allowedFallbacks.has(lane.fallback)) {
      fail(`${algorithm.id}/${laneName} has unknown fallback ${lane.fallback}`);
    }
    if (!Array.isArray(lane.providers)) {
      fail(`${algorithm.id}/${laneName} providers is not an array`);
    }
    if (typeof lane.usesRust !== "boolean") {
      fail(`${algorithm.id}/${laneName} usesRust is not boolean`);
    }
    if (typeof lane.api !== "string" || lane.api.length === 0) {
      fail(`${algorithm.id}/${laneName} api is empty`);
    }
    const countKey = `${laneName}:${lane.status}`;
    statusCounts.set(countKey, (statusCounts.get(countKey) ?? 0) + 1);
  }
}

const rootCargo = readText("Cargo.toml");
if (!rootCargo.includes(`version = "${rustRootVersion}"`)) {
  fail(`root Cargo.toml is not versioned ${rustRootVersion}`);
}
if (
  !rootCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("root Cargo.toml must use an anchored package include allowlist");
}
if (!rootCargo.includes('messaging-dispatch = ["dispatch", "messaging-primitives"]')) {
  fail("root Cargo.toml must expose the narrow messaging-dispatch feature");
}
if (!rootCargo.includes('"crypto-dispatch?/ed25519"')) {
  fail("root algorithm features must conditionally forward into dispatch");
}
if (!rootCargo.includes('"crypto-signer?/ed25519"')) {
  fail("root signature features must conditionally forward into signer");
}

const ffiCargo = readText("crates/crypto/ffi/Cargo.toml");
if (!ffiCargo.includes("publish = false")) {
  fail("crates/crypto/ffi must remain publish = false");
}

const dispatchCargo = readText("crates/crypto/dispatch/Cargo.toml");
if (!dispatchCargo.includes('"crypto-ed25519?/native"')) {
  fail("dispatch native feature must not enable every algorithm");
}
if (!dispatchCargo.includes('ed25519 = ["dep:crypto-ed25519"]')) {
  fail("dispatch must keep explicit per-algorithm features");
}

const signerCargo = readText("crates/crypto/signer/Cargo.toml");
if (!signerCargo.includes('ed25519 = ["crypto-dispatch/ed25519"]')) {
  fail("signer must keep explicit signature-algorithm features");
}

const codecCargo = readText("crates/codec/Cargo.toml");
if (
  !codecCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/codec/Cargo.toml must use an anchored package include allowlist");
}

const tsPackage = readJson("packages/ts/package.json");
if (tsPackage.version !== typescriptPackageVersion) {
  fail(`packages/ts/package.json is not versioned ${typescriptPackageVersion}`);
}
if (tsPackage.private === true) {
  fail("packages/ts/package.json is still private and cannot be published to npm");
}

const kotlinBuild = readText("packages/kotlin/build.gradle.kts");
if (!kotlinBuild.includes(`version = "${kotlinPackageVersion}"`)) {
  fail(`packages/kotlin/build.gradle.kts is not versioned ${kotlinPackageVersion}`);
}

assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "PROVIDER_POLICY.md");
assertContains("README.md", "CONTRACT.md");
assertContains("SECURITY.md", "PROVIDER_POLICY.md");
assertContains("SECURITY_MEMORY_MODEL.md", "scripts/check_release_readiness.mjs");
assertContains("PROVIDER_POLICY.md", "Generated from `provider_manifest.json`");

const orderedCounts = [...statusCounts.entries()].sort(([left], [right]) =>
  left.localeCompare(right),
);
for (const [key, count] of orderedCounts) {
  console.log(`${key} ${count}`);
}
