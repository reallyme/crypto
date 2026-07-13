#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rustRootVersion = "0.1.8";
const codecPackageVersion = "0.1.8";
const cryptoProtoPackageVersion = "0.1.3";
const codecProtoPackageVersion = "0.1.0";
const typescriptPackageVersion = "0.1.8";
const kotlinPackageVersion = "0.1.8";
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
if (!rootCargo.includes('"crates/proto/codec"')) {
  fail("workspace must include crates/proto/codec");
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
if (!codecCargo.includes(`version = "${codecPackageVersion}"`)) {
  fail(`crates/codec/Cargo.toml is not versioned ${codecPackageVersion}`);
}
if (
  !codecCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/codec/Cargo.toml must use an anchored package include allowlist");
}
assertContains("crates/codec/README.md", `reallyme-codec = "${codecPackageVersion}"`);

const cryptoProtoCargo = readText("crates/proto/crypto/Cargo.toml");
if (!cryptoProtoCargo.includes(`version = "${cryptoProtoPackageVersion}"`)) {
  fail(`crates/proto/crypto/Cargo.toml is not versioned ${cryptoProtoPackageVersion}`);
}
if (!cryptoProtoCargo.includes('name = "reallyme-crypto-proto"')) {
  fail("crypto proto crate must remain named reallyme-crypto-proto");
}
if (
  !cryptoProtoCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/proto/crypto/Cargo.toml must use an anchored package include allowlist");
}
assertContains(
  "crates/proto/crypto/README.md",
  `reallyme-crypto-proto = { version = "${cryptoProtoPackageVersion}", features = ["generated"] }`,
);
const codecProtoCargo = readText("crates/proto/codec/Cargo.toml");
if (!codecProtoCargo.includes(`version = "${codecProtoPackageVersion}"`)) {
  fail(`crates/proto/codec/Cargo.toml is not versioned ${codecProtoPackageVersion}`);
}
if (!codecProtoCargo.includes('name = "reallyme-codec-proto"')) {
  fail("codec proto crate must remain named reallyme-codec-proto");
}
if (
  !codecProtoCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/proto/codec/Cargo.toml must use an anchored package include allowlist");
}
assertContains(
  "crates/proto/codec/README.md",
  `reallyme-codec-proto = { version = "${codecProtoPackageVersion}", features = ["generated"] }`,
);
assertContains("buf.gen.yaml", "out: crates/proto/crypto/src/generated/buffa");
assertContains("buf.gen.yaml", "reallyme.crypto.v1.**");
assertContains("buf.gen.yaml", "out: crates/proto/codec/src/generated/buffa");
assertContains("buf.gen.yaml", "reallyme.codec.v1.**");
assertContains("crates/proto/crypto/src/generated/buffa/mod.rs", "pub mod crypto");
if (readText("crates/proto/crypto/src/generated/buffa/mod.rs").includes("pub mod codec")) {
  fail("crypto proto Buffa package must not export reallyme.codec.v1");
}
assertContains("crates/proto/codec/src/generated/buffa/mod.rs", "pub mod codec");
if (readText("crates/proto/codec/src/generated/buffa/mod.rs").includes("pub mod crypto")) {
  fail("codec proto Buffa package must not export reallyme.crypto.v1");
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
assertContains("README.md", "reallyme-codec-proto");
assertContains("README.md", "PROVIDER_POLICY.md");
assertContains("README.md", "CONTRACT.md");
assertContains("SECURITY.md", "PROVIDER_POLICY.md");
assertContains("SECURITY_MEMORY_MODEL.md", "scripts/check_release_readiness.mjs");
assertContains("PROVIDER_POLICY.md", "Generated from `provider_manifest.json`");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: proto");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "package reallyme.crypto.v1;");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "message CryptoError");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "message CryptoPrimitiveError");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "message CryptoProviderError");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "message CryptoBackendError");
assertContains("proto/reallyme/crypto/v1/crypto.proto", "enum CryptoErrorReason");
assertContains(
  "proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER = 100;",
);
assertContains(
  "proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM = 200;",
);
assertContains(
  "proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE = 300;",
);
assertContains("proto/reallyme/codec/v1/codec.proto", "package reallyme.codec.v1;");
assertContains("proto/reallyme/codec/v1/codec.proto", "message CodecError");
assertContains("proto/reallyme/codec/v1/codec.proto", "message CodecBaseEncodingError");
assertContains("proto/reallyme/codec/v1/codec.proto", "message CodecPemError");
assertContains("proto/reallyme/codec/v1/codec.proto", "message CodecMultiformatError");
assertContains("proto/reallyme/codec/v1/codec.proto", "message CodecCanonicalizationError");
assertContains("proto/reallyme/codec/v1/codec.proto", "enum CodecErrorReason");
assertContains(
  "proto/reallyme/codec/v1/codec.proto",
  "CODEC_ERROR_REASON_BASE_UNSUPPORTED_CODEC = 100;",
);
assertContains(
  "proto/reallyme/codec/v1/codec.proto",
  "CODEC_ERROR_REASON_PEM_INVALID_BOUNDARY = 200;",
);
assertContains(
  "proto/reallyme/codec/v1/codec.proto",
  "CODEC_ERROR_REASON_MULTIFORMAT_INVALID_MULTIBASE_PREFIX = 300;",
);
assertContains(
  "proto/reallyme/codec/v1/codec.proto",
  "CODEC_ERROR_REASON_CANONICAL_INVALID_CBOR = 400;",
);

const orderedCounts = [...statusCounts.entries()].sort(([left], [right]) =>
  left.localeCompare(right),
);
for (const [key, count] of orderedCounts) {
  console.log(`${key} ${count}`);
}
