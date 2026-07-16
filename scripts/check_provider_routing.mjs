#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

const requiredLanes = ["swift", "kotlin_jvm", "kotlin_android", "typescript_wasm"];
const allowedStatuses = new Set(["supported", "provider_aware", "partial", "unsupported"]);
const allowedFallbacks = new Set([
  "typed_provider_failure",
  "typed_unsupported_algorithm",
  "explicit_provider_required",
]);

const laneCatalogPaths = {
  swift: "packages/swift/Sources/ReallyMeCrypto/ProviderCatalog.swift",
  kotlin_jvm: "packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt",
  kotlin_android: "packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt",
  typescript_wasm: "packages/ts/src/providerCatalog.ts",
};

const laneAlgorithmPaths = {
  swift: "packages/swift/Sources/ReallyMeCrypto/Algorithms.swift",
  kotlin_jvm: "packages/kotlin/src/main/kotlin/me/really/crypto/Algorithms.kt",
  kotlin_android: "packages/kotlin/src/main/kotlin/me/really/crypto/Algorithms.kt",
  typescript_wasm: "packages/ts/src/algorithms.ts",
};

const swiftSourcePaths = [
  "packages/swift/Sources/ReallyMeCrypto",
  "packages/swift/Sources/ReallyMeCryptoProtoAdapters",
];

const kotlinSourcePaths = ["packages/kotlin/src/main/kotlin/me/really/crypto"];

const typescriptSourcePaths = ["packages/ts/src"];

const rustRoutePaths = [
  "crates/crypto/core/src/algorithm.rs",
  "crates/crypto/dispatch/src",
  "crates/crypto/ffi/src",
  "crates/crypto/wasm-package/src",
  "crates/crypto/protocols/hpke/src",
];

const routingTestPaths = [
  "packages/swift/Tests",
  "packages/kotlin/src/test",
  "packages/ts/test",
  "crates/crypto/dispatch/tests",
  "crates/crypto/ffi/tests",
  "tests",
];

// Kotlin's catalog names one runtime dependency used by provider plumbing but
// not selected as an algorithm route in provider_manifest.json. All algorithm
// providers still have to be declared by the manifest.
const approvedCatalogOnlyProviders = {
  swift: new Set(),
  kotlin_jvm: new Set(["Kotlin/JDK stdlib"]),
  kotlin_android: new Set(["Kotlin/JDK stdlib"]),
  typescript_wasm: new Set(),
};

const readText = (path) => readFileSync(resolve(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

const failures = [];

const fail = (message) => {
  failures.push(message);
};

const assertContains = (label, text, needle) => {
  if (!text.includes(needle)) {
    fail(`${label} is missing required routing marker ${needle}`);
  }
};

const assertEqualSets = (label, actual, expected) => {
  const missing = [...expected].filter((value) => !actual.has(value));
  const extra = [...actual].filter((value) => !expected.has(value));
  if (missing.length !== 0 || extra.length !== 0) {
    fail(
      `${label} drifted from provider_manifest.json; missing=[${missing.join(
        ", ",
      )}] extra=[${extra.join(", ")}]`,
    );
  }
};

const assertFileExists = (label, path) => {
  try {
    const stat = statSync(resolve(root, path));
    if (!stat.isFile()) {
      fail(`${label} must be a file at ${path}`);
    }
  } catch (_error) {
    fail(`${label} must exist at ${path}`);
  }
};

const runNodeCheck = (scriptPath, args) => {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    fail(`${scriptPath} ${args.join(" ")} failed${output.length === 0 ? "" : `:\n${output}`}`);
  }
};

const quotedStrings = (text) => {
  const values = new Set();
  const matcher = /"((?:\\.|[^"\\])*)"/g;
  let match = matcher.exec(text);
  while (match !== null) {
    values.add(match[1].replace(/\\"/g, '"'));
    match = matcher.exec(text);
  }
  return values;
};

const sourceFromTree = (path) => {
  const absolute = resolve(root, path);
  const rootStat = statSync(absolute);
  if (!rootStat.isDirectory()) {
    return readFileSync(absolute, "utf8");
  }
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory)) {
      const child = resolve(directory, entry);
      const stat = statSync(child);
      if (stat.isDirectory()) {
        walk(child);
      } else if (/\.(rs|swift|kt|ts|mjs)$/.test(entry)) {
        files.push(child);
      }
    }
  };
  walk(absolute);
  return files.map((file) => readFileSync(file, "utf8")).join("\n");
};

const manifest = readJson("provider_manifest.json");
const vectorManifest = readJson("vectors/manifest.json");
const vectorFiles = new Set(vectorManifest.vectors);
const algorithmById = new Map();
for (const algorithm of manifest.algorithms) {
  if (algorithmById.has(algorithm.id)) {
    fail(`provider_manifest.json declares duplicate algorithm id ${algorithm.id}`);
  }
  algorithmById.set(algorithm.id, algorithm);
}

const resolveAlgorithm = (algorithm, seen = new Set()) => {
  if (algorithm.lanes !== undefined) {
    return algorithm;
  }
  if (typeof algorithm.sameAs !== "string" || algorithm.sameAs.length === 0) {
    fail(`${algorithm.id} must have either lanes or sameAs`);
    return algorithm;
  }
  if (seen.has(algorithm.id)) {
    fail(`provider_manifest.json sameAs cycle includes ${algorithm.id}`);
    return algorithm;
  }
  const source = algorithmById.get(algorithm.sameAs);
  if (source === undefined) {
    fail(`${algorithm.id} sameAs target ${algorithm.sameAs} does not exist`);
    return algorithm;
  }
  const nextSeen = new Set(seen);
  nextSeen.add(algorithm.id);
  const resolved = resolveAlgorithm(source, nextSeen);
  return { ...algorithm, lanes: resolved.lanes };
};

const resolvedAlgorithms = manifest.algorithms.map((algorithm) => resolveAlgorithm(algorithm));
const packageAlgorithmIds = new Set(
  manifest.algorithms
    .filter((algorithm) => algorithm.packageApi === true)
    .map((algorithm) => algorithm.id),
);

if (manifest.schemaVersion !== 1) {
  fail("provider_manifest.json schemaVersion must remain 1 until the validator is updated");
}

assertEqualSets(
  "provider_manifest.json requiredLanes",
  new Set(manifest.requiredLanes),
  new Set(requiredLanes),
);

for (const algorithm of resolvedAlgorithms) {
  if (!packageAlgorithmIds.has(algorithm.id)) {
    continue;
  }
  const rawAlgorithm = algorithmById.get(algorithm.id);
  if (rawAlgorithm?.sameAs !== undefined) {
    const source = algorithmById.get(rawAlgorithm.sameAs);
    if (source !== undefined) {
      if (source.family !== rawAlgorithm.family) {
        fail(`${algorithm.id} sameAs source ${rawAlgorithm.sameAs} must use the same family`);
      }
      if (source.packageApi !== rawAlgorithm.packageApi) {
        fail(`${algorithm.id} sameAs source ${rawAlgorithm.sameAs} must use the same packageApi value`);
      }
    }
  }
  if (algorithm.lanes === undefined) {
    fail(`${algorithm.id} did not resolve to lane metadata`);
    continue;
  }
  if (typeof algorithm.family !== "string" || algorithm.family.length === 0) {
    fail(`${algorithm.id} must declare an algorithm family`);
  }
  for (const laneName of requiredLanes) {
    const lane = algorithm.lanes[laneName];
    if (lane === undefined) {
      fail(`${algorithm.id} is missing ${laneName}`);
      continue;
    }
    if (!allowedStatuses.has(lane.status)) {
      fail(`${algorithm.id}/${laneName} has unknown status ${lane.status}`);
    }
    if (!allowedFallbacks.has(lane.fallback)) {
      fail(`${algorithm.id}/${laneName} has unknown fallback ${lane.fallback}`);
    }
    if (lane.fallback === "silent") {
      fail(`${algorithm.id}/${laneName} must not silently fall back`);
    }
    if (typeof lane.usesRust !== "boolean") {
      fail(`${algorithm.id}/${laneName} usesRust must be boolean`);
    }
    if (!Array.isArray(lane.providers)) {
      fail(`${algorithm.id}/${laneName} providers must be an array`);
    }
    if (lane.status === "unsupported" && lane.providers.length !== 0) {
      fail(`${algorithm.id}/${laneName} unsupported lanes must not name providers`);
    }
    if (lane.status !== "unsupported" && lane.providers.length === 0) {
      fail(`${algorithm.id}/${laneName} supported lanes must name at least one provider`);
    }
    if (lane.usesRust !== lane.providers.some((provider) => provider.includes("Rust"))) {
      fail(`${algorithm.id}/${laneName} usesRust must match a declared Rust provider`);
    }
  }
}

for (const [laneName, path] of Object.entries(laneAlgorithmPaths)) {
  const algorithmStrings = quotedStrings(readText(path));
  assertEqualSets(`${laneName} algorithm identifiers`, algorithmStrings, packageAlgorithmIds);
}

for (const laneName of requiredLanes) {
  const manifestProviders = new Set();
  for (const algorithm of resolvedAlgorithms) {
    const lane = algorithm.lanes?.[laneName];
    if (lane === undefined) {
      continue;
    }
    for (const provider of lane.providers) {
      manifestProviders.add(provider);
    }
  }
  const approvedExtras = approvedCatalogOnlyProviders[laneName];
  const catalogProviders = quotedStrings(readText(laneCatalogPaths[laneName]));
  const expectedCatalog = new Set([...manifestProviders, ...approvedExtras]);
  assertEqualSets(`${laneName} provider catalog`, catalogProviders, expectedCatalog);
}

const swiftSource = swiftSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const kotlinSource = kotlinSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const typescriptSource = typescriptSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const rustRouteSource = rustRoutePaths.map((path) => sourceFromTree(path)).join("\n");
const routingTestSource = routingTestPaths.map((path) => sourceFromTree(path)).join("\n");

const sourceForLane = (laneName) => {
  switch (laneName) {
    case "swift":
      return swiftSource;
    case "kotlin_jvm":
    case "kotlin_android":
      return kotlinSource;
    case "typescript_wasm":
      return typescriptSource;
    default:
      return "";
  }
};

const apiMarkersFor = (algorithmId, api) => {
  const markers = new Set();
  const matcher = /ReallyMe[A-Za-z0-9_]+(?:\.[A-Za-z0-9_*]+)?|rustCAbiLibrary|auxRand32|signBip340Schnorr/g;
  let match = matcher.exec(api);
  while (match !== null) {
    const token = match[0];
    if (token.includes(".")) {
      const [owner, member] = token.split(".");
      markers.add(owner);
      const normalizedMember = member.replace("*", "");
      if (normalizedMember.length !== 0 && !normalizedMember.endsWith("_")) {
        markers.add(normalizedMember);
      }
    } else {
      markers.add(token);
    }
    match = matcher.exec(api);
  }
  if (api.includes("ML-DSA")) {
    markers.add("ReallyMeMlDsa");
  }
  if (api.includes("ReallyMeRsa")) {
    markers.add("ReallyMeRsa");
  }
  return [...markers].filter((marker) => marker !== "ReallyMeCrypto");
};

const wasmMarkersFor = (algorithmId) => {
  if (algorithmId.startsWith("RSA-PKCS1v15-")) {
    return { rust: ["rsa_verify_pkcs1v15"], typescript: ["rsaVerifyPkcs1v15"] };
  }
  if (algorithmId.startsWith("RSA-PSS-")) {
    return { rust: ["rsa_verify_pss"], typescript: ["rsaVerifyPss"] };
  }
  if (algorithmId === "ML-DSA-44") {
    return { rust: ["ml_dsa_44_generate_keypair"], typescript: ["mlDsa44GenerateKeypair"] };
  }
  if (algorithmId === "ML-DSA-65") {
    return { rust: ["ml_dsa_65_generate_keypair"], typescript: ["mlDsa65GenerateKeypair"] };
  }
  if (algorithmId === "ML-DSA-87") {
    return { rust: ["ml_dsa_87_generate_keypair"], typescript: ["mlDsa87GenerateKeypair"] };
  }
  if (algorithmId === "SLH-DSA-SHA2-128s") {
    return {
      rust: ["slh_dsa_sha2_128s_generate_keypair"],
      typescript: ["slhDsaSha2128sGenerateKeypair"],
    };
  }
  if (algorithmId === "ML-KEM-512") {
    return { rust: ["ml_kem_512_generate_keypair"], typescript: ["mlKem512GenerateKeypair"] };
  }
  if (algorithmId === "ML-KEM-768") {
    return { rust: ["ml_kem_768_generate_keypair"], typescript: ["mlKem768GenerateKeypair"] };
  }
  if (algorithmId === "ML-KEM-1024") {
    return { rust: ["ml_kem_1024_generate_keypair"], typescript: ["mlKem1024GenerateKeypair"] };
  }
  if (algorithmId === "X-Wing-768") {
    return { rust: ["x_wing_768_generate_keypair"], typescript: ["xWing768GenerateKeypair"] };
  }
  if (algorithmId === "X-Wing-1024") {
    return { rust: ["x_wing_1024_generate_keypair"], typescript: ["xWing1024GenerateKeypair"] };
  }
  if (algorithmId.startsWith("DHKEM-")) {
    return {
      rust: ["hpke_seal_base", "hpke_open_base"],
      typescript: ["hpkeSealBase", "hpkeOpenBase"],
    };
  }
  if (algorithmId === "AES-128-GCM") {
    return { rust: ["aes_128_gcm_seal"], typescript: ["aes128GcmSeal"] };
  }
  if (algorithmId === "AES-192-GCM") {
    return { rust: ["aes_192_gcm_seal"], typescript: ["aes192GcmSeal"] };
  }
  if (algorithmId === "AES-256-GCM") {
    return { rust: ["aes_256_gcm_seal"], typescript: ["aes256GcmSeal"] };
  }
  if (algorithmId === "AES-256-GCM-SIV") {
    return { rust: ["aes_256_gcm_siv_seal"], typescript: ["aes256GcmSivSeal"] };
  }
  if (algorithmId === "ChaCha20-Poly1305") {
    return { rust: ["chacha20_poly1305_seal"], typescript: ["chacha20Poly1305Seal"] };
  }
  if (algorithmId === "XChaCha20-Poly1305") {
    return { rust: ["xchacha20_poly1305_seal"], typescript: ["xchacha20Poly1305Seal"] };
  }
  if (algorithmId === "Argon2id") {
    return { rust: ["argon2id_derive_key"], typescript: ["argon2idDeriveKey"] };
  }
  if (algorithmId === "AES-256-KW") {
    return { rust: ["aes_256_kw_wrap_key"], typescript: ["aes256KwWrapKey"] };
  }
  return { rust: [], typescript: [] };
};

const rustMarkersFor = (algorithmId) => {
  if (algorithmId === "Ed25519") {
    return ["Algorithm::Ed25519"];
  }
  if (algorithmId.startsWith("ECDSA-P256-") || algorithmId === "P-256-ECDH") {
    return ["Algorithm::P256"];
  }
  if (algorithmId.startsWith("ECDSA-P384-") || algorithmId === "P-384-ECDH") {
    return ["Algorithm::P384"];
  }
  if (algorithmId.startsWith("ECDSA-P521-") || algorithmId === "P-521-ECDH") {
    return ["Algorithm::P521"];
  }
  if (algorithmId.includes("secp256k1")) {
    return ["Algorithm::Secp256k1"];
  }
  if (algorithmId === "ML-DSA-44") {
    return ["Algorithm::MlDsa44"];
  }
  if (algorithmId === "ML-DSA-65") {
    return ["Algorithm::MlDsa65"];
  }
  if (algorithmId === "ML-DSA-87") {
    return ["Algorithm::MlDsa87"];
  }
  if (algorithmId === "ML-KEM-512") {
    return ["Algorithm::MlKem512"];
  }
  if (algorithmId === "ML-KEM-768") {
    return ["Algorithm::MlKem768"];
  }
  if (algorithmId === "ML-KEM-1024") {
    return ["Algorithm::MlKem1024"];
  }
  if (algorithmId === "X-Wing-768") {
    return ["Algorithm::XWing768"];
  }
  if (algorithmId === "X-Wing-1024") {
    return ["Algorithm::XWing1024"];
  }
  if (algorithmId === "AES-128-GCM") {
    return ["AeadAlgorithm::Aes128Gcm"];
  }
  if (algorithmId === "AES-192-GCM") {
    return ["AeadAlgorithm::Aes192Gcm"];
  }
  if (algorithmId === "AES-256-GCM") {
    return ["AeadAlgorithm::Aes256Gcm"];
  }
  if (algorithmId === "AES-256-GCM-SIV") {
    return ["AeadAlgorithm::Aes256GcmSiv"];
  }
  if (algorithmId === "ChaCha20-Poly1305") {
    return ["AeadAlgorithm::ChaCha20Poly1305"];
  }
  if (algorithmId === "XChaCha20-Poly1305") {
    return ["AeadAlgorithm::XChaCha20Poly1305"];
  }
  if (algorithmId === "Argon2id") {
    return ["argon2id"];
  }
  if (algorithmId === "AES-256-KW") {
    return ["aes_256_kw"];
  }
  if (algorithmId.startsWith("RSA-")) {
    return ["rsa_verify"];
  }
  if (algorithmId.startsWith("DHKEM-")) {
    return ["hpke"];
  }
  return [];
};

const vectorFileFor = (algorithmId) => {
  if (algorithmId === "Ed25519") {
    return "ed25519.json";
  }
  if (algorithmId.startsWith("ECDSA-P256-") || algorithmId === "P-256-ECDH") {
    return "p256.json";
  }
  if (algorithmId.startsWith("ECDSA-P384-") || algorithmId === "P-384-ECDH") {
    return "p384.json";
  }
  if (algorithmId.startsWith("ECDSA-P521-") || algorithmId === "P-521-ECDH") {
    return "p521.json";
  }
  if (algorithmId === "ECDSA-secp256k1-SHA256") {
    return "secp256k1.json";
  }
  if (algorithmId === "BIP340-Schnorr-secp256k1-SHA256") {
    return "bip340_schnorr.json";
  }
  if (algorithmId.startsWith("RSA-")) {
    return "rsa.json";
  }
  if (algorithmId === "X25519") {
    return "x25519.json";
  }
  if (algorithmId === "ML-DSA-44") {
    return "ml_dsa_44.json";
  }
  if (algorithmId === "ML-DSA-65") {
    return "ml_dsa_65.json";
  }
  if (algorithmId === "ML-DSA-87") {
    return "ml_dsa_87.json";
  }
  if (algorithmId === "SLH-DSA-SHA2-128s") {
    return "slh_dsa_sha2_128s.json";
  }
  if (algorithmId === "ML-KEM-512") {
    return "mlkem512.json";
  }
  if (algorithmId === "ML-KEM-768") {
    return "mlkem768.json";
  }
  if (algorithmId === "ML-KEM-1024") {
    return "mlkem1024.json";
  }
  if (algorithmId.startsWith("X-Wing-")) {
    return "x_wing.json";
  }
  if (algorithmId.startsWith("DHKEM-")) {
    return "hpke.json";
  }
  if (algorithmId === "AES-128-GCM") {
    return "aes128gcm.json";
  }
  if (algorithmId === "AES-192-GCM") {
    return "aes192gcm.json";
  }
  if (algorithmId === "AES-256-GCM") {
    return "aes256gcm.json";
  }
  if (algorithmId === "AES-256-GCM-SIV") {
    return "aes256gcmsiv.json";
  }
  if (algorithmId === "ChaCha20-Poly1305") {
    return "chacha20poly1305.json";
  }
  if (algorithmId === "XChaCha20-Poly1305") {
    return "chacha20poly1305.json";
  }
  if (algorithmId.startsWith("SHA2-") || algorithmId.startsWith("SHA3-")) {
    return "hashes.json";
  }
  if (algorithmId.startsWith("HMAC-")) {
    return "hmac.json";
  }
  if (algorithmId === "HKDF-SHA256") {
    return "hkdf.json";
  }
  if (algorithmId === "Argon2id") {
    return "argon2id.json";
  }
  if (algorithmId.startsWith("PBKDF2-")) {
    return "pbkdf2.json";
  }
  if (algorithmId === "JWA-CONCAT-KDF-SHA256") {
    return "concat_kdf.json";
  }
  if (algorithmId === "AES-256-KW") {
    return "aes256kw.json";
  }
  return undefined;
};

const hasRustRoute = (algorithm) =>
  requiredLanes.some((laneName) => algorithm.lanes?.[laneName]?.usesRust === true);

for (const algorithm of resolvedAlgorithms) {
  if (!packageAlgorithmIds.has(algorithm.id) || algorithm.lanes === undefined) {
    continue;
  }

  const vectorFile = vectorFileFor(algorithm.id);
  if (vectorFile === undefined || !vectorFiles.has(vectorFile)) {
    fail(`${algorithm.id} must have a registered conformance vector file`);
  } else {
    assertFileExists(`${algorithm.id} conformance vector`, `vectors/${vectorFile}`);
  }

  for (const laneName of requiredLanes) {
    const lane = algorithm.lanes[laneName];
    if (lane.status === "unsupported") {
      continue;
    }
    for (const marker of apiMarkersFor(algorithm.id, lane.api)) {
      assertContains(`${algorithm.id} ${laneName} manifest API route`, sourceForLane(laneName), marker);
    }
  }

  if (hasRustRoute(algorithm)) {
    for (const marker of rustMarkersFor(algorithm.id)) {
      assertContains(`${algorithm.id} Rust dispatch/adapter surface`, rustRouteSource, marker);
    }
  }

  if (algorithm.lanes.swift.usesRust) {
    if (algorithm.lanes.swift.fallback !== "explicit_provider_required") {
      fail(`${algorithm.id}/swift Rust routes must require an explicit provider`);
    }
    assertContains(`${algorithm.id} Swift route`, swiftSource, "rustCAbiLibrary");
    assertContains(`${algorithm.id} Swift missing-provider tests`, routingTestSource, "providerFailure");
  }

  for (const laneName of ["kotlin_jvm", "kotlin_android"]) {
    const lane = algorithm.lanes[laneName];
    if (lane.usesRust) {
      if (lane.fallback !== "explicit_provider_required") {
        fail(`${algorithm.id}/${laneName} Rust routes must require an explicit provider`);
      }
      assertContains(`${algorithm.id} ${laneName} route`, kotlinSource, "ReallyMeRustNativeProvider");
      assertContains(`${algorithm.id} ${laneName} JNI bridge`, rustRouteSource, "Java_me_really_crypto_");
      assertContains(`${algorithm.id} ${laneName} missing-provider tests`, routingTestSource, "PROVIDER_UNAVAILABLE");
    }
  }

  if (algorithm.lanes.typescript_wasm.usesRust) {
    if (algorithm.lanes.typescript_wasm.fallback !== "typed_provider_failure") {
      fail(`${algorithm.id}/typescript_wasm missing WASM provider must fail as typed provider failure`);
    }
    const wasmMarkers = wasmMarkersFor(algorithm.id);
    for (const marker of wasmMarkers.rust) {
      assertContains(`${algorithm.id} TypeScript/WASM route`, rustRouteSource, marker);
    }
    for (const marker of wasmMarkers.typescript) {
      assertContains(`${algorithm.id} TypeScript/WASM provider wrapper`, typescriptSource, marker);
    }
    assertContains(
      `${algorithm.id} TypeScript missing-provider tests`,
      routingTestSource,
      "explicit crypto provider instances fail closed without WASM provider",
    );
  }
}

assertContains("generated provider policy", readText("PROVIDER_POLICY.md"), "provider_manifest.json");
assertContains(
  "generated provider policy",
  readText("PROVIDER_POLICY.md"),
  "<!-- BEGIN GENERATED PROVIDER MATRIX -->",
);
assertContains(
  "generated provider policy",
  readText("PROVIDER_POLICY.md"),
  "<!-- END GENERATED PROVIDER MATRIX -->",
);
assertContains(
  "release readiness checks",
  readText("scripts/check_release_readiness.mjs"),
  "check_provider_routing.mjs",
);
runNodeCheck("scripts/generate_provider_matrix.mjs", ["--check"]);

if (failures.length !== 0) {
  for (const message of failures) {
    console.error(`provider routing check failed: ${message}`);
  }
  process.exit(1);
}

console.log(
  `provider routing check passed: ${packageAlgorithmIds.size} algorithms across ${requiredLanes.length} lanes`,
);
