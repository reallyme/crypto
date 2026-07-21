#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { relative, resolve } from "node:path";
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
  swift: ["packages/swift/Sources/ReallyMeCrypto/ProviderCatalog.swift"],
  kotlin_jvm: ["packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt"],
  kotlin_android: [
    "packages/kotlin/src/main/kotlin/me/really/crypto/ProviderCatalog.kt",
    "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidProviderCatalog.kt",
  ],
  typescript_wasm: ["packages/ts/src/providerCatalog.ts"],
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

const kotlinAndroidSourcePaths = [
  ...kotlinSourcePaths,
  "packages/kotlin-android/src/main/kotlin/me/really/crypto",
];

const typescriptSourcePaths = ["packages/ts/src"];

const rustRoutePaths = [
  "crates/crypto/core/src/algorithm.rs",
  "crates/crypto/dispatch/src",
  "crates/ffi/src",
  "crates/wasm/src",
  "crates/hpke/src",
];

const routingTestPaths = [
  "packages/swift/Tests",
  "packages/kotlin/src/test",
  "packages/kotlin-android/src/androidTest",
  "packages/ts/test",
  "crates/crypto/dispatch/tests",
  "crates/ffi/tests",
  "crates/crypto/tests",
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

const assertNotContains = (label, text, needle) => {
  if (text.includes(needle)) {
    fail(`${label} contains forbidden routing marker ${needle}`);
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

const sourceFilesFromTrees = (paths) => {
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory)) {
      const child = resolve(directory, entry);
      const stat = statSync(child);
      if (stat.isDirectory()) {
        walk(child);
      } else if (/\.(swift|kt|ts)$/.test(entry)) {
        files.push({
          path: relative(root, child),
          source: readFileSync(child, "utf8"),
        });
      }
    }
  };
  for (const path of paths) {
    const absolute = resolve(root, path);
    const stat = statSync(absolute);
    if (stat.isDirectory()) {
      walk(absolute);
    } else {
      files.push({
        path: relative(root, absolute),
        source: readFileSync(absolute, "utf8"),
      });
    }
  }
  return files;
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
  const catalogProviders = quotedStrings(
    laneCatalogPaths[laneName].map((path) => readText(path)).join("\n"),
  );
  const expectedCatalog = new Set([...manifestProviders, ...approvedExtras]);
  assertEqualSets(`${laneName} provider catalog`, catalogProviders, expectedCatalog);
}

const swiftSource = swiftSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const kotlinSource = kotlinSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const kotlinAndroidSource = kotlinAndroidSourcePaths
  .map((path) => sourceFromTree(path))
  .join("\n");
const typescriptSource = typescriptSourcePaths.map((path) => sourceFromTree(path)).join("\n");
const sourceFilesByLane = {
  swift: sourceFilesFromTrees(swiftSourcePaths),
  kotlin_jvm: sourceFilesFromTrees(kotlinSourcePaths),
  kotlin_android: sourceFilesFromTrees(kotlinAndroidSourcePaths),
  typescript_wasm: sourceFilesFromTrees(typescriptSourcePaths),
};
const rustRouteSource = rustRoutePaths.map((path) => sourceFromTree(path)).join("\n");
const routingTestSource = routingTestPaths.map((path) => sourceFromTree(path)).join("\n");

const sourceForLane = (laneName) => {
  switch (laneName) {
    case "swift":
      return swiftSource;
    case "kotlin_jvm":
      return kotlinSource;
    case "kotlin_android":
      return kotlinAndroidSource;
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
  if (
    algorithmId === "BIP340-Schnorr-secp256k1-SHA256" &&
    api.includes("signBip340Schnorr")
  ) {
    markers.add("ReallyMeBip340Schnorr");
  }
  if (api.includes("ReallyMeRsa")) {
    markers.add("ReallyMeRsa");
  }
  return [...markers].filter((marker) => marker !== "ReallyMeCrypto");
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const declarationPatternFor = (laneName, owner) => {
  const escapedOwner = escapeRegex(owner);
  switch (laneName) {
    case "swift":
      return new RegExp(`\\bpublic\\s+(?:actor|class|enum|struct)\\s+${escapedOwner}\\b`);
    case "kotlin_jvm":
    case "kotlin_android":
      return new RegExp(`\\bpublic\\s+(?:class|enum\\s+class|object)\\s+${escapedOwner}\\b`);
    case "typescript_wasm":
      return new RegExp(`\\bexport\\s+(?:class|const)\\s+${escapedOwner}\\b`);
    default:
      return undefined;
  }
};

const forbiddenRustRouteMarkers = {
  swift: ["ReallyMeRustCAbi", "rustCAbiLibrary"],
  kotlin_jvm: ["ReallyMeRust"],
  kotlin_android: ["ReallyMeRust"],
  typescript_wasm: [
    "ReallyMeWasmProvider",
    "resolveWasmProvider",
    "requireReallyMeWasmProvider",
    "WithProvider",
  ],
};

const assertNativePackageRoute = (algorithmId, laneName, api) => {
  if (api.includes("ReallyMeRust") || api.includes("rustCAbiLibrary")) {
    fail(`${algorithmId}/${laneName} non-Rust route must not name a Rust API`);
  }
  const owners = apiMarkersFor(algorithmId, api).filter(
    (marker) => marker.startsWith("ReallyMe") && !marker.startsWith("ReallyMeRust"),
  );
  if (owners.length === 0) {
    fail(`${algorithmId}/${laneName} non-Rust route must name a concrete package API owner`);
    return;
  }
  const sourceFiles = sourceFilesByLane[laneName];
  for (const owner of owners) {
    const declarationPattern = declarationPatternFor(laneName, owner);
    if (declarationPattern === undefined) {
      fail(`${algorithmId}/${laneName} has no declaration matcher`);
      continue;
    }
    const declarationFiles = sourceFiles.filter(({ source }) => declarationPattern.test(source));
    if (declarationFiles.length === 0) {
      fail(`${algorithmId}/${laneName} package route owner ${owner} has no source declaration`);
      continue;
    }
    for (const file of declarationFiles) {
      for (const marker of forbiddenRustRouteMarkers[laneName]) {
        assertNotContains(
          `${algorithmId}/${laneName} native package route ${owner} in ${file.path}`,
          file.source,
          marker,
        );
      }
    }
  }
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
  if (algorithmId === "KMAC256") {
    return { rust: ["kmac256_derive"], typescript: ["kmac256Derive"] };
  }
  if (algorithmId === "AES-128-KW") {
    return { rust: ["aes_128_kw_wrap_key"], typescript: ["aes128KwWrapKey"] };
  }
  if (algorithmId === "AES-192-KW") {
    return { rust: ["aes_192_kw_wrap_key"], typescript: ["aes192KwWrapKey"] };
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
  if (algorithmId === "KMAC256") {
    return ["kmac256"];
  }
  if (algorithmId === "AES-128-KW") {
    return ["aes_128_kw"];
  }
  if (algorithmId === "AES-192-KW") {
    return ["aes_192_kw"];
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
  if (algorithmId === "HKDF-SHA384") {
    return "hkdf_sha384.json";
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
  if (algorithmId === "KMAC256") {
    return "kmac256.json";
  }
  if (algorithmId === "AES-128-KW") {
    return "aes128kw.json";
  }
  if (algorithmId === "AES-192-KW") {
    return "aes192kw.json";
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
    if (!lane.usesRust) {
      assertNativePackageRoute(algorithm.id, laneName, lane.api);
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

for (const algorithmId of [
  "RSA-PKCS1v15-SHA1",
  "RSA-PKCS1v15-SHA256",
  "RSA-PKCS1v15-SHA384",
  "RSA-PKCS1v15-SHA512",
  "RSA-PSS-SHA1-MGF1-SHA1",
  "RSA-PSS-SHA256-MGF1-SHA256",
  "RSA-PSS-SHA384-MGF1-SHA384",
  "RSA-PSS-SHA512-MGF1-SHA512",
  "AES-128-GCM",
  "AES-192-GCM",
  "AES-256-GCM",
]) {
  const algorithm = resolvedAlgorithms.find((entry) => entry.id === algorithmId);
  if (algorithm === undefined) {
    fail(`${algorithmId} is missing from the provider manifest`);
    continue;
  }
  for (const laneName of ["kotlin_jvm", "kotlin_android"]) {
    const lane = algorithm.lanes[laneName];
    if (
      lane.providers.length !== 1 ||
      lane.providers[0] !== "BouncyCastle" ||
      lane.fallback !== "typed_provider_failure"
    ) {
      fail(`${algorithmId}/${laneName} must pin the bundled BouncyCastle provider`);
    }
  }
}
assertContains(
  "Kotlin AES-GCM pinned provider route",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/AesGcm.kt"),
  "ReallyMeJceProviders.bouncyCastleCipher",
);
assertNotContains(
  "Kotlin AES-GCM pinned provider route",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/AesGcm.kt"),
  "ReallyMeJceProviders.cipher(",
);
assertContains(
  "Kotlin RSA pinned signature route",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt"),
  "ReallyMeJceProviders.bouncyCastleSignature",
);
assertContains(
  "Kotlin RSA pinned key parser route",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt"),
  "ReallyMeJceProviders.bouncyCastleKeyFactory",
);
assertNotContains(
  "Kotlin RSA pinned provider route",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt"),
  "ReallyMeJceProviders.signature(",
);
assertNotContains(
  "Kotlin provider routing helper",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt"),
  "takeUnless",
);
assertNotContains(
  "Kotlin provider routing helper",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt"),
  "Cipher.getInstance(transformation)",
);
assertNotContains(
  "Kotlin provider routing helper",
  readText("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt"),
  "Signature.getInstance(algorithm)",
);

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
