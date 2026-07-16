#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rustRootVersion = "0.2.0";
const cryptoProtoPackageVersion = "0.2.0";
const typescriptPackageVersion = "0.2.0";
const kotlinPackageVersion = "0.2.0";
const kotlinAndroidPackageVersion = "0.2.0";
const releasePackagesMode = process.argv.includes("--release-packages");
const requiredLanes = ["swift", "kotlin_jvm", "kotlin_android", "typescript_wasm"];
const allowedStatuses = new Set(["supported", "provider_aware", "partial", "unsupported"]);
const allowedFallbacks = new Set([
  "typed_provider_failure",
  "typed_unsupported_algorithm",
  "explicit_provider_required",
]);
const releaseVersionEnv = process.env.RELEASE_VERSION;

const readText = (path) => readFileSync(resolve(root, path), "utf8");
const readJson = (path) => JSON.parse(readText(path));

const fail = (message) => {
  console.error(`release readiness check failed: ${message}`);
  process.exit(1);
};

if (releaseVersionEnv !== undefined && !/^[0-9]+[.][0-9]+[.][0-9]+$/.test(releaseVersionEnv)) {
  fail("RELEASE_VERSION must be an exact semver release such as 0.2.0");
}

const assertContains = (path, needle) => {
  if (!readText(path).includes(needle)) {
    fail(`${path} does not contain ${needle}`);
  }
};

const assertNotContains = (path, needle) => {
  if (readText(path).includes(needle)) {
    fail(`${path} must not contain ${needle}`);
  }
};

const requireMatch = (path, pattern, description) => {
  const match = pattern.exec(readText(path));
  if (match === null) {
    fail(`${path} does not contain ${description}`);
  }
  return match;
};

const runNodeCheck = (scriptPath, args = []) => {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    const command = [scriptPath, ...args].join(" ");
    fail(`${command} failed${output.length === 0 ? "" : `:\n${output}`}`);
  }
};

const workflowDirectory = resolve(root, ".github/workflows");
for (const workflowFile of readdirSync(workflowDirectory).filter((name) => name.endsWith(".yml"))) {
  const workflowPath = `.github/workflows/${workflowFile}`;
  const workflow = readText(workflowPath);
  const jobsOffset = workflow.indexOf("\njobs:\n");
  if (jobsOffset === -1) {
    continue;
  }
  const jobs = workflow.slice(jobsOffset + 1);
  const jobHeaders = [...jobs.matchAll(/^  ([a-zA-Z0-9_-]+):\s*$/gm)];
  for (const [index, header] of jobHeaders.entries()) {
    const nextHeader = jobHeaders[index + 1];
    const job = jobs.slice(header.index, nextHeader?.index ?? jobs.length);
    if (!/\b(?:node|npm|npx|pnpm)\b/.test(job)) {
      continue;
    }
    if (!job.includes("actions/setup-node@")) {
      fail(`${workflowPath} job ${header[1]} uses Node tooling without actions/setup-node`);
    }
    if (!job.includes("node-version: '24'")) {
      fail(`${workflowPath} job ${header[1]} must pin Node 24`);
    }
  }
}

const manifest = readJson("provider_manifest.json");
runNodeCheck("scripts/check_provider_routing.mjs");
runNodeCheck("scripts/check_negative_vectors.mjs");
runNodeCheck("scripts/publish_crates_in_order.mjs", ["order"]);
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
  releaseVersionEnv !== undefined &&
  [
    rustRootVersion,
    cryptoProtoPackageVersion,
    typescriptPackageVersion,
    kotlinPackageVersion,
    kotlinAndroidPackageVersion,
  ].some((version) => version !== releaseVersionEnv)
) {
  fail(`RELEASE_VERSION ${releaseVersionEnv} does not match the source-tree package versions`);
}
assertContains("Cargo.toml", "overflow-checks = true");
assertNotContains("Cargo.toml", "[patch.crates-io]");
for (const path of [
  "crates/crypto/dispatch/Cargo.toml",
  "crates/crypto/primitives/p256/Cargo.toml",
  "crates/envelopes/jwk/Cargo.toml",
  "crates/envelopes/jwk-multikey/Cargo.toml",
]) {
  assertNotContains(path, "../codec");
  assertContains(path, 'version = "0.1.21"');
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

const cryptoProtoCargo = readText("crates/proto/crypto/Cargo.toml");
if (!cryptoProtoCargo.includes(`version = "${cryptoProtoPackageVersion}"`)) {
  fail(`crates/proto/crypto/Cargo.toml is not versioned ${cryptoProtoPackageVersion}`);
}
if (!cryptoProtoCargo.includes('name = "reallyme-crypto-proto"')) {
  fail("crypto proto crate must remain named reallyme-crypto-proto");
}
if (!cryptoProtoCargo.includes("publish = true")) {
  fail("reallyme-crypto-proto must remain publishable as its own crates.io package");
}
if (
  !cryptoProtoCargo.includes(
    'include = ["/proto/**/*.proto", "/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/proto/crypto/Cargo.toml must use an anchored package include allowlist");
}
assertContains(
  "crates/proto/crypto/README.md",
  `reallyme-crypto-proto = { version = "${cryptoProtoPackageVersion}", features = ["generated"] }`,
);
assertContains(
  "scripts/publish_crates_in_order.mjs",
  'requirePublishOrderBefore("reallyme-crypto-proto", "reallyme-crypto")',
);
assertContains("buf.gen.yaml", "out: crates/proto/crypto/src/generated/buffa");
assertNotContains("buf.gen.yaml", "reallyme.crypto.v1.**");
assertNotContains("buf.gen.yaml", "types:");
assertContains("buf.gen.yaml", "buf.build/bufbuild/es:v2.12.1");
assertContains("buf.gen.yaml", "buf.build/apple/swift:v1.38.1");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/java:v35.1");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/kotlin:v35.1");
assertContains("crates/proto/crypto/src/generated/buffa/mod.rs", "pub mod crypto");
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "enum CryptoOperation",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "service CryptoService",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "rpc Process(CryptoServiceProcessRequest) returns (CryptoServiceProcessResponse)",
);
assertContains("crates/proto/crypto/src/wire.rs", "CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT");
assertContains("crates/proto/crypto/src/wire.rs", "with_unknown_field_limit");
assertContains("crates/proto/crypto/src/wire.rs", "Zeroizing<Vec<u8>>");
assertContains("crates/crypto/ffi/src/pointer.rs", "begin_input_range_call");
assertContains("crates/crypto/ffi/src/pointer.rs", "validate_registered_inputs_against_output");

const tsPackage = readJson("packages/ts/package.json");
if (tsPackage.version !== typescriptPackageVersion) {
  fail(`packages/ts/package.json is not versioned ${typescriptPackageVersion}`);
}
if (tsPackage.private === true) {
  fail("packages/ts/package.json is still private and cannot be published to npm");
}
if (JSON.stringify(tsPackage.dependencies ?? {}).includes("../../../codec")) {
  fail("packages/ts/package.json must not depend on a local codec package path");
}
if ((tsPackage.dependencies ?? {})["@reallyme/codec"] !== "0.1.21") {
  fail("packages/ts/package.json must depend on published @reallyme/codec 0.1.21");
}
if ((tsPackage.scripts ?? {}).prepack !== "npm run build") {
  fail("packages/ts/package.json must rebuild dist in prepack");
}
if (!((tsPackage.scripts ?? {}).prepublishOnly ?? "").includes("npm run pack:check")) {
  fail("packages/ts/package.json prepublishOnly must run the npm pack artifact check");
}
if ((tsPackage.scripts ?? {})["pack:check"] !== "node scripts/check-pack.mjs") {
  fail("packages/ts/package.json must expose scripts/check-pack.mjs as pack:check");
}
assertContains("packages/ts/scripts/check-pack.mjs", "reallyme_crypto_wasm_bg.wasm");
assertContains("packages/ts/scripts/check-pack.mjs", "package/LICENSE");
assertContains("packages/ts/scripts/build-wasm.mjs", "const REQUIRED_WASM_PACK_VERSION = [0, 15, 0]");
assertContains("packages/ts/scripts/build-wasm.mjs", "const REQUIRED_WASM_BINDGEN_VERSION = [0, 2, 126]");
assertContains("packages/ts/scripts/build-wasm.mjs", "versionText(wasmPackVersion) !== versionText(REQUIRED_WASM_PACK_VERSION)");
assertContains("packages/ts/scripts/build-wasm.mjs", "versionText(wasmBindgenVersion) !== versionText(REQUIRED_WASM_BINDGEN_VERSION)");
assertNotContains("packages/ts/scripts/build-wasm.mjs", "or newer is required");
assertContains("packages/ts/package.json", '"LICENSE"');
assertNotContains("crates/crypto/wasm-package/src/lib.rs", "canonicalize_json_web_key");
assertNotContains("crates/crypto/wasm-package/src/lib.rs", "base64url_encode");
assertNotContains("packages/ts/src/wasmProvider.ts", "canonicalizeJsonWebKey");
assertNotContains("packages/ts/src/wasmModuleTypes.ts", "base64urlDecode");
assertContains("packages/ts/src/jwk.ts", "from \"@reallyme/codec\"");
assertContains("packages/ts/src/jwk.ts", "rejectPrivateKeyMaterial");
assertContains("packages/ts/src/jwk.ts", "codecBase64urlDecodeCanonical");
assertContains("packages/ts/src/wasmProvider.ts", "createReallyMeWasmProvider");
assertContains("packages/ts/src/wasmProvider.ts", "installedProvider !== undefined");
assertContains("packages/ts/src/wasmModuleTypes.ts", "rsaVerifyPkcs1v15");
assertContains("packages/ts/src/wasmModuleTypes.ts", "rsaVerifyPss");
assertContains("packages/ts/src/aead.ts", "CHACHA20_POLY1305_KEY_LENGTH");
assertContains("packages/ts/src/aead.ts", "return aeadSuiteWithProvider(algorithm, requireReallyMeWasmProvider())");
assertContains("packages/ts/src/validateBytes.ts", "ensureByteArray");
assertContains("packages/ts/src/proto.ts", "invalidInputReasons");
assertContains("packages/ts/src/cryptoFacade.ts", "createReallyMeCrypto");
assertContains("packages/ts/src/cryptoFacade.ts", "ReallyMeCryptoProviders");
assertContains("packages/ts/src/cryptoFacade.ts", "resolveWasmProvider");
assertContains("packages/ts/src/cryptoFacade.ts", "deriveArgon2id");
assertContains("packages/ts/src/cryptoFacade.ts", "deriveKemKeyPair");
assertContains("packages/ts/src/index.ts", "createReallyMeCrypto");
assertContains("packages/ts/src/index.ts", "createReallyMeWasmProvider");
assertContains("packages/ts/src/index.ts", "bestEffortClear");
assertContains("packages/ts/src/memory.ts", "bestEffortClear");
assertContains("packages/ts/src/jwaConcatKdf.ts", "bestEffortClear(hashInput)");
assertContains("packages/ts/src/p256Ecdh.ts", "bestEffortClear(uncompressed)");
assertContains("packages/ts/src/p384Ecdh.ts", "bestEffortClear(uncompressed)");
assertContains("packages/ts/src/p521Ecdh.ts", "bestEffortClear(uncompressed)");
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "explicit crypto provider instances isolate WASM-backed routes",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "package-global WASM provider is frozen after first install",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "JWK facade rejects malformed public-key inputs",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "explicit crypto provider instances fail closed without WASM provider",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "explicit crypto provider instances do not leak into one another",
);
assertContains("packages/ts/test/reallyme-crypto.test.mjs", "deriveArgon2id(ARGON2ID_V1");
assertContains("packages/ts/test/reallyme-crypto.test.mjs", "deriveJwaConcatKdfSha256(bad");
assertContains("packages/ts/test/reallyme-crypto.test.mjs", "deriveKeyPair(bad");
assertContains("packages/ts/test/reallyme-crypto.test.mjs", "deriveKeyAgreementKeyPair(bad");
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "best-effort memory cleanup overwrites caller-owned TypeScript bytes",
);
assertContains("packages/ts/README.md", "createReallyMeCrypto");
assertContains("packages/ts/README.md", "package-global mutable state");
assertContains("packages/ts/README.md", "bestEffortClear(secretBytes)");

const kotlinBuild = readText("packages/kotlin/build.gradle.kts");
if (!kotlinBuild.includes(`version = "${kotlinPackageVersion}"`)) {
  fail(`packages/kotlin/build.gradle.kts is not versioned ${kotlinPackageVersion}`);
}
assertContains("Package.swift", 'url: "https://github.com/reallyme/codec"');
assertContains("Package.swift", 'from: "0.1.21"');
assertContains("Package.swift", 'name: "ReallyMeCryptoFFI"');
assertContains("Package.swift", "ReallyMeCryptoFFI.xcframework.zip");
assertContains("Package.swift", 'let ffiArtifactLocalPathOverride = ""');
assertContains("Package.swift", "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains("Package.swift", "if hasReleasedFfiArtifact && !useRuntimeFfiProvider");
assertContains("Package.swift", 'cryptoTargetDependencies.append("ReallyMeCryptoFFI")');
assertContains("Package.swift", 'cryptoSwiftSettings.append(.define("REALLYME_CRYPTO_LINKED_FFI"))');
assertNotContains("Package.swift", "build/swift/ReallyMeCryptoFFI.xcframework");
for (const path of [
  "packages/swift/Sources/ReallyMeCrypto/DeriveArgon2idWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/EncapsulateMlKemWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/EncapsulateXWingWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SealAeadWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SealHpkeWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignBip340SchnorrWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignEd25519WithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignMlDsaWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignP256WithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignP384WithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignP521WithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/SignSlhDsaWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/VerifyRsaWithRustCAbi.swift",
  "packages/swift/Sources/ReallyMeCrypto/WrapAesKwWithRustCAbi.swift",
]) {
  assertContains(path, "private let library: ReallyMeRustCAbiLibrary");
  assertContains(path, "self.library = library");
}
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "public struct ReallyMeCryptoProviders");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift",
  "public init(providers: ReallyMeCryptoProviders = .default)",
);
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeRustCAbiLibrary.bundledProvider()");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "deriveArgon2idKey");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "auxRand32: [UInt8]");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "deriveMlDsaKeyPair");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "deriveSlhDsaSha2_128sKeyPair");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "deriveXWingKeyPair");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "deriveMlKemKeyPair");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "seed: [UInt8]");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "publicKeyDer: [UInt8]");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "private func requireRustCAbiLibrary()");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "CustomDebugStringConvertible");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "secretKey: <redacted>");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "sharedSecret: <redacted>");
assertContains("packages/swift/Sources/ReallyMeCrypto/MemoryHygiene.swift", "ReallyMeCryptoMemory");
assertContains("packages/swift/Sources/ReallyMeCrypto/JwaConcatKdf.swift", "bestEffortClear(&derived)");
assertContains("packages/swift/Sources/ReallyMeCrypto/Pbkdf2.swift", "bestEffortClear(&block)");
assertContains("packages/swift/Sources/ReallyMeCrypto/SealAeadWithRustCAbi.swift", "bestEffortClear(&plaintext)");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/SealAeadWithRustCAbi.swift",
  "return try ReallyMeAesGcm.sealAes192Gcm",
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/SealAeadWithRustCAbi.swift",
  "return try ReallyMeAesGcm.openAes192Gcm",
);
assertContains("packages/swift/Sources/ReallyMeCrypto/SealHpkeWithRustCAbi.swift", "bestEffortClear(&plaintext)");
assertContains("packages/swift/Sources/ReallyMeCrypto/WrapAesKwWithRustCAbi.swift", "bestEffortClear(&output)");
assertContains("packages/swift/Sources/ReallyMeCrypto/DeriveArgon2idWithRustCAbi.swift", "bestEffortClear(&derivedKey)");
assertContains("packages/swift/Sources/ReallyMeCrypto/SignEd25519WithRustCAbi.swift", "bestEffortClear(&secretKey)");
assertContains("packages/swift/Sources/ReallyMeCrypto/SignP256WithRustCAbi.swift", "bestEffortClear(&returnedSecretKey)");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift",
  "kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave",
);
assertContains("packages/swift/Sources/ReallyMeCrypto/SignMlDsaWithRustCAbi.swift", "bestEffortClear(&returnedSecretKey)");
assertContains("packages/swift/Sources/ReallyMeCrypto/SignSlhDsaWithRustCAbi.swift", "bestEffortClear(&secretKey)");
assertContains("packages/swift/Sources/ReallyMeCrypto/EncapsulateMlKemWithRustCAbi.swift", "bestEffortClear(&sharedSecret)");
assertContains("packages/swift/Sources/ReallyMeCrypto/EncapsulateXWingWithRustCAbi.swift", "bestEffortClear(&sharedSecret)");
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoTests.swift",
  "testBestEffortMemoryCleanupOverwritesCallerOwnedSwiftBytes",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoTests.swift",
  "testSecretBearingContainersRedactStringDescriptions",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoGenericFacadeTests.swift",
  "testExplicitProviderContextFailsClosedWithoutRustProvider",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoGenericFacadeTests.swift",
  "testConfiguredProviderContextPreservesAppleNativeSemantics",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoGenericFacadeTests.swift",
  "testConfiguredProviderContextRoutesRustBackedAlgorithmsWhenConfigured",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoGenericFacadeTests.swift",
  "ciphertextWithTag: [UInt8](repeating: 0, count: ReallyMeAesGcm.tagLength - 1)",
);
assertContains("packages/swift/README.md", "ReallyMeCrypto(providers: ReallyMeCryptoProviders");
assertContains("packages/swift/README.md", "Released SwiftPM packages ship the `ReallyMeCryptoFFI` binary target");
assertContains("packages/swift/README.md", "ReallyMeCryptoMemory.bestEffortClear");
assertContains("packages/kotlin/build.gradle.kts", "junit-jupiter-api");
assertContains("packages/kotlin/build.gradle.kts", "reallyme.crypto.nativeResourcesDir");
assertContains("packages/kotlin/build.gradle.kts", "verifyBundledNativeResources");
assertContains("packages/kotlin/build.gradle.kts", "verifyHostBundledNativeResource");
assertContains("packages/kotlin/build.gradle.kts", "writeHostNativeManifest");
assertContains("packages/kotlin/build.gradle.kts", "inputs.file(stagedLibraryFile)");
assertContains("packages/kotlin/build.gradle.kts", '"package": "reallyme-crypto-native"');
assertContains("packages/kotlin/build.gradle.kts", "me/really/crypto/native/linux-x86_64/libcrypto_ffi.so");
assertContains("packages/kotlin/build.gradle.kts", "me/really/crypto/native/windows-x86_64/crypto_ffi.dll");
assertContains("packages/kotlin/build.gradle.kts", "hostNativeSupported");
assertNotContains("packages/kotlin/build.gradle.kts", 'throw GradleException("unsupported host operating system');
assertNotContains("packages/kotlin/build.gradle.kts", 'throw GradleException("unsupported host architecture');
assertContains(
  "packages/kotlin-android/gradle/wrapper/gradle-wrapper.properties",
  "distributionSha256Sum=f1771298a70f6db5a29daf62378c4e18a17fc33c9ba6b14362e0cdf40610380d",
);
assertContains(
  "packages/kotlin/gradle/wrapper/gradle-wrapper.properties",
  "distributionSha256Sum=9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14",
);
assertContains(
  "crates/conformance/vectors/platform/kotlin/gradle/wrapper/gradle-wrapper.properties",
  "distributionSha256Sum=9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt", "@JvmStatic");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
  "public class ReallyMeSignatureKeyPair",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt", "secretKey=<redacted>");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt", "sharedSecret=<redacted>");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt", "ReallyMeNativeStatus");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt", "decodeRustNativeResult");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt", "PROVIDER_UNAVAILABLE");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt", "encoded.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "loadedLibraryPath");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "loadedLibraryPath == canonicalPath",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Digest.kt", "catch (_: NoSuchAlgorithmException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Hmac.kt", "catch (_: GeneralSecurityException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "cipherProviderName");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "signatureProviderName");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P256Ecdsa.kt", "catch (_: RuntimeException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P384Ecdsa.kt", "catch (_: RuntimeException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P521Ecdsa.kt", "catch (_: RuntimeException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "val cipher = try");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "throw ReallyMeCryptoException.ProviderFailure()");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "throw ReallyMeCryptoException.AuthenticationFailed()");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/MemoryHygiene.kt", "ReallyMeCryptoMemory");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JwaConcatKdf.kt", "derived.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JwaConcatKdf.kt", "otherInfo.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt", "derived.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/MlKem.kt", "sharedSecret.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Hpke.kt", "plaintext.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/XWing.kt", "x25519SharedSecret.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P256Ecdh.kt", "bytes.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P384Ecdh.kt", "bytes.fill(0)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P521Ecdh.kt", "bytes.fill(0)");
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "bestEffortMemoryCleanupOverwritesCallerOwnedKotlinBytes",
);
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "secretBearingContainersDoNotStringifyOrHashSecretBytes",
);
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "jceProviderIdentityIsInspectableForProviderBackedPrimitives",
);
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "ByteArray(ReallyMeAesGcm.TAG_LENGTH - 1)",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustAead.kt", "requireRustNativeBytes");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Argon2id.kt", "requireRustNativeBytes");
assertContains("crates/crypto/ffi/src/kotlin_result.rs", "status_from_crypto_status");
assertContains("crates/crypto/ffi/src/kotlin_aead.rs", "status_from_crypto_status(status)");
assertContains("crates/crypto/ffi/src/kotlin_aead.rs", "plaintext_bytes.zeroize()");
assertContains("crates/crypto/ffi/src/kotlin_argon2id.rs", "status_from_crypto_status(status)");
assertContains("crates/crypto/ffi/src/kotlin_argon2id.rs", "derived.zeroize()");
assertContains("crates/crypto/wasm-package/src/aead.rs", "plaintext.zeroize()");
assertContains(
  "packages/kotlin/src/test/java/me/really/crypto/ReallyMeCryptoJavaTest.java",
  "ReallyMeCrypto.hash",
);
assertContains("packages/kotlin/build.gradle.kts", 'implementation("me.really:codec:0.1.21")');
assertNotContains("packages/kotlin/settings.gradle.kts", "includeBuild");
assertNotContains("packages/kotlin/settings.gradle.kts", "../../../codec");
assertContains(
  "crates/crypto/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeRustNativeProvider_probeNative",
);
assertContains(
  "crates/crypto/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeArgon2id_deriveKeyNative",
);
assertContains(
  "crates/crypto/ffi/src/kotlin_aead.rs",
  "Java_me_really_crypto_ReallyMeRustAead_aes256GcmSivSealNative",
);
if (readText("crates/crypto/ffi/src/kotlin_aead.rs").includes("Java_com_reallyme_crypto")) {
  fail("Kotlin JNI symbols must use the me.really.crypto package prefix");
}
if (readText("crates/crypto/ffi/src/kotlin_argon2id.rs").includes("Java_com_reallyme_crypto")) {
  fail("Kotlin Argon2id JNI symbols must use the me.really.crypto package prefix");
}

const kotlinAndroidBuild = readText("packages/kotlin-android/build.gradle.kts");
if (!kotlinAndroidBuild.includes(`version = "${kotlinAndroidPackageVersion}"`)) {
  fail(`packages/kotlin-android/build.gradle.kts is not versioned ${kotlinAndroidPackageVersion}`);
}
assertContains("packages/kotlin-android/settings.gradle.kts", 'rootProject.name = "reallyme-crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", 'artifactId = "crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", 'implementation("me.really:codec-android:0.1.21")');
assertContains("packages/kotlin-android/build.gradle.kts", "patchAndroidModuleCapabilities");
assertContains("packages/kotlin-android/build.gradle.kts", '"name" to "crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", '"name" to "crypto"');
assertContains("packages/kotlin-android/build.gradle.kts", "releaseVariantReleaseApiPublication");
assertContains("packages/kotlin-android/build.gradle.kts", "releaseVariantReleaseRuntimePublication");
assertContains("packages/kotlin-android/build.gradle.kts", "reallyme.crypto.androidJniLibsDir");
assertContains("packages/kotlin-android/build.gradle.kts", "jniLibs.setSrcDirs(listOf(jniLibsDir.get()))");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyReleaseAarContainsJniLibs");
assertContains("packages/kotlin-android/build.gradle.kts", "assets.srcDir(nativeAssetsDir.get().path)");
assertContains("packages/kotlin-android/build.gradle.kts", "reallyme-crypto/native-manifest.json");
assertContains("packages/kotlin-android/build.gradle.kts", "buildAndroidJniLibs");
assertContains("packages/kotlin-android/build.gradle.kts", 'testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"');
assertContains("packages/kotlin-android/build.gradle.kts", 'consumerProguardFiles("consumer-rules.pro")');
assertContains("packages/kotlin-android/build.gradle.kts", 'androidTestImplementation("androidx.test.ext:junit:1.3.0")');
assertContains("packages/kotlin-android/gradle.properties", "android.useAndroidX=true");
assertContains("packages/kotlin-android/scripts/build-jni-libs.sh", "scripts/build_android_native_resources.sh");
assertContains("packages/kotlin-android/consumer-rules.pro", "org.bouncycastle.**");
assertContains("packages/kotlin-android/consumer-rules.pro", "GeneratedMessageLite");
assertContains("packages/kotlin-android/consumer-rules.pro", "native <methods>");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "aesGcmRoundTripsOnAndroidProviderLane");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "aesKwUsesBundledBouncyCastleProviderOnAndroid");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "rsaPkcs1v15AndPssVerifyOnAndroid");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "rustJniArgon2idRouteLoadsFromBundledAndroidLibrary");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "bip340SchnorrSignsAndVerifiesOnAndroidSecp256k1Lane");
assertContains("packages/kotlin-android/README.md", "native-manifest.json` is a release and");
assertContains("packages/kotlin/README.md", "`me.really:crypto`");
assertContains("packages/kotlin-android/README.md", "`me.really:crypto`");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "BouncyCastleProvider()");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "usesUnapprovedBouncyCastle");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "isBundledBouncyCastleProvider");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "Security.getProvider");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "ReallyMeJceProviders.bouncyCastleCipher");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "loadBundledLibrary",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "platformNativeResource",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "/me/really/crypto/native",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "RESOURCE_MANIFEST_PATH",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "verifyNativeResource(resource, bytes)",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "sha256Hex(bytes)",
);

assertContains("README.md", "actions/workflows/rust-ci.yml/badge.svg");
assertContains("README.md", "PROVIDER_POLICY.md");
assertContains("README.md", "CONTRACT.md");
assertContains("README.md", "The canonical contract is not mechanically generated");
assertContains("SECURITY.md", "PROVIDER_POLICY.md");
assertContains("SECURITY_MEMORY_MODEL.md", "scripts/check_release_readiness.mjs");
assertContains("SECURITY_MEMORY_MODEL.md", "Managed-runtime best-effort cleanup helpers");
assertContains("SECURITY_MEMORY_MODEL.md", "ReallyMeCryptoMemory.bestEffortClear(&bytes)");
assertContains("SECURITY_MEMORY_MODEL.md", "bestEffortClear(bytes)");
assertContains("SECURITY_MEMORY_MODEL.md", "not guaranteed-zeroized storage");
assertContains(
  "SECURITY_MEMORY_MODEL.md",
  "Generic AEAD primitive and dispatch APIs treat `aad` as caller-provided bytes",
);
assertContains("RELEASE_NOTES.md", "## 0.2.0");
assertContains("RELEASE_NOTES.md", "legacy `reallyme.codec.v1` protobuf/package surface was removed");
assertContains("RELEASE_NOTES.md", "not a `reallyme.crypto.v1` wire break");
assertContains("RELEASE_NOTES.md", "permanently retired in this repository");
assertContains("RELEASE_BLOCKERS.md", "Release Readiness Requirements");
assertContains("RELEASE_BLOCKERS.md", "Public SwiftPM releases ship `ReallyMeCryptoFFI`");
assertContains("RELEASE_BLOCKERS.md", "must point at the reviewed manifest commit");
assertContains("RELEASE_BLOCKERS.md", "Release workflows never modify or push source");
assertContains("RELEASE_BLOCKERS.md", "`me.really:crypto-android` as an AAR");
assertContains("RELEASE_BLOCKERS.md", "`npm run pack:check`");
assertContains(".github/workflows/rust-ci.yml", "workflow_dispatch:");
assertContains(".github/workflows/rust-ci.yml", "!PROVIDER_POLICY.md");
assertContains(".github/workflows/rust-ci.yml", "!CONTRACT.md");
assertContains(".github/workflows/rust-ci.yml", "cargo package -p reallyme-crypto --list");
assertContains(".github/workflows/rust-ci.yml", "node scripts/generate_provider_matrix.mjs --check");
assertContains(".github/workflows/rust-ci.yml", "node scripts/check_release_readiness.mjs");
assertContains(".github/workflows/rust-ci.yml", "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains(".github/workflows/fuzz.yml", "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
assertContains(".github/workflows/fuzz.yml", "cargo install cargo-fuzz --version 0.13.2 --locked");
assertContains(".github/workflows/fuzz.yml", "src/proto_process.rs");
assertContains(".github/workflows/fuzz.yml", "crates/proto/crypto/**");
assertContains(".github/workflows/fuzz.yml", "crates/envelopes/jwk/**");
assertContains(".github/workflows/fuzz.yml", "crates/envelopes/jwk-multikey/**");
assertContains(".github/workflows/fuzz.yml", "proto_process");
assertContains(".github/workflows/fuzz.yml", "jwk_multikey");
assertContains("fuzz/Cargo.toml", 'name = "proto_process"');
assertContains("fuzz/Cargo.toml", 'name = "jwk_multikey"');
assertContains("fuzz/Cargo.toml", '"hpke"');
assertContains("fuzz/Cargo.toml", '"ml-dsa-44"');
assertContains("fuzz/Cargo.toml", '"rsa"');
assertContains("fuzz/Cargo.toml", '"x-wing"');
assertContains("fuzz/Cargo.toml", '"aes-kw"');
assertContains("fuzz/Cargo.toml", '"argon2id"');
assertContains("fuzz/fuzz_targets/proto_process.rs", "process_proto(operation, request_bytes)");
assertContains("fuzz/fuzz_targets/jwk_multikey.rs", "serde_json::from_str::<Jwk>");
assertContains("fuzz/fuzz_targets/jwk_multikey.rs", "multikey_to_jwk(input, JwkOptions::default())");
assertContains("fuzz/README.md", "`proto_process`");
assertContains("fuzz/README.md", "`jwk_multikey`");
assertContains("fuzz/README.md", "cargo install cargo-fuzz --version 0.13.2 --locked");
assertContains("PROVIDER_POLICY.md", "Generated from `provider_manifest.json`");
assertContains("PROVIDER_POLICY.md", "Every provider route must implement identical input validation");
assertContains("CONTRACT.md", "## Canonical Contract");
assertContains("CONTRACT.md", "protobuf enums and boundary messages");
assertContains("CONTRACT.md", "provider_manifest.json");
assertContains("CONTRACT.md", "shared positive and negative conformance vectors");
assertContains("CONTRACT.md", "Rust remains the reference implementation");
assertContains("vectors/manifest.json", '"negative_vectors"');
assertContains("vectors/negative/fail_closed.json", '"schemaVersion": 1');
assertContains("scripts/check_negative_vectors.mjs", "negative vector check passed");
assertNotContains("buf.yaml", "reallyme/codec/v1/codec.proto");
assertContains("docs/protobuf.md", "not a generated mirror of the Rust package API");
assertContains("docs/protobuf.md", "`crypto-error` plus serialized `CryptoError` bytes");
assertContains("docs/protobuf.md", "reallyme_crypto::proto_process::process_proto");
assertContains("docs/protobuf.md", "PROVIDER_UNSUPPORTED_ALGORITHM");
assertContains("docs/conformance.md", "Every provider route must prove the same contract");
assertContains("Cargo.toml", "proto-process = [");
assertContains("src/lib.rs", "pub mod proto_process");
assertContains("src/proto_process.rs", "pub const OP_HASH");
assertContains("src/proto_process.rs", "pub const OP_HPKE_OPEN");
assertContains("src/proto_process.rs", "process_proto(operation");
assertContains("src/proto_process.rs", "OP_SIGNATURE_DERIVE_KEY_PAIR");
assertContains("crates/crypto/ffi/src/lib.rs", "pub mod proto_process");
assertContains("crates/crypto/ffi/src/proto_process.rs", "rm_crypto_process_proto");
assertContains("crates/crypto/ffi/src/proto_process.rs", "result.zeroize_bytes()");
assertContains("crates/crypto/ffi/src/status.rs", "CRYPTO_PROTO_ERROR");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_PROTO_ERROR");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_PROTO_OP_HASH");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_process_proto");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_CHACHA20_POLY1305_NONCE_LEN");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_XCHACHA20_POLY1305_NONCE_LEN");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_chacha20_poly1305_encrypt");
assertContains("crates/crypto/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_xchacha20_poly1305_encrypt");
assertContains("crates/crypto/ffi/tests/ffi_boundary_tests.rs", "exported_ffi_symbol_names");
assertContains("crates/crypto/ffi/tests/ffi_boundary_tests.rs", "header_declares_every_exported_ffi_symbol");
assertContains("crates/crypto/ffi/src/kotlin_result.rs", "backend_internal_result");
assertContains("crates/crypto/ffi/src/kotlin_result.rs", "clear_pending_exception");
assertContains("crates/crypto/ffi/src/kotlin_result.rs", "CRYPTO_BUFFER_TOO_SMALL => KOTLIN_NATIVE_BACKEND_INTERNAL");
assertContains(
  "crates/crypto/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeRustNativeProvider_probeNative<'local>",
);
assertContains("crates/crypto/wasm-package/src/ml_kem.rs", "Zeroizing::new(require_len(secret_key, ML_KEM_SECRET_KEY_LEN)?)");
assertContains("crates/crypto/wasm-package/src/ml_dsa.rs", "Zeroizing::new(require_len(secret_key, ML_DSA_SECRET_KEY_LEN)?)");
assertContains("crates/proto/crypto/src/lib.rs", "pub mod wire");
assertContains("crates/proto/crypto/src/wire.rs", "CryptoWireErrorBranch");
assertContains("crates/proto/crypto/src/wire.rs", "CryptoProtoResult");
assertContains("crates/proto/crypto/src/wire.rs", "reason_code");
assertContains("crates/proto/crypto/src/wire.rs", "zeroize_bytes");
assertContains("crates/proto/crypto/src/wire.rs", "Successful result messages may contain plaintext");
assertContains("crates/proto/crypto/src/wire.rs", "#[non_exhaustive]");
assertContains("crates/proto/crypto/src/wire.rs", "pub fn try_new");
assertContains("crates/proto/crypto/src/wire.rs", "decode_protobuf_with_limit");
assertContains("crates/proto/crypto/src/wire.rs", "pub fn decode_json");
assertContains("crates/proto/crypto/src/wire.rs", "encode_proto_result_envelope");
assertContains("crates/proto/crypto/src/wire.rs", "decode_proto_result_envelope");
assertContains("crates/proto/crypto/src/wire.rs", "CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF");
assertContains("crates/proto/crypto/src/wire.rs", "MAX_CRYPTO_PROTO_MESSAGE_BYTES");
assertContains("crates/crypto/core/src/error.rs", "pub enum CryptoError");
assertContains("crates/crypto/core/src/error.rs", "#[non_exhaustive]");
assertContains("crates/crypto/dispatch/src/error.rs", "pub enum AlgorithmError");
assertContains("crates/crypto/dispatch/src/error.rs", "#[non_exhaustive]");
assertContains("crates/crypto/signer/src/error.rs", "pub enum SignerError");
assertContains("crates/crypto/signer/src/error.rs", "#[non_exhaustive]");
assertContains("crates/envelopes/jwk/src/error.rs", "pub enum JwtError");
assertContains("crates/envelopes/jwk/src/error.rs", "#[non_exhaustive]");
assertContains("crates/envelopes/jwk-multikey/src/error.rs", "pub enum JwkMultikeyError");
assertContains("crates/envelopes/jwk-multikey/src/error.rs", "#[non_exhaustive]");
assertContains("crates/crypto/protocols/hpke/src/error.rs", "pub enum HpkeError");
assertContains("crates/crypto/protocols/hpke/src/error.rs", "#[non_exhaustive]");
assertContains("packages/ts/src/proto.ts", "ReallyMeCryptoWireError");
assertContains("packages/ts/src/proto.ts", "cryptoProtoErrorResult");
assertContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "ReallyMeCryptoWireError");
assertContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "ReallyMeCryptoProtoResult");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "ReallyMeCryptoWireError");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "ReallyMeCryptoProtoResult");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "wireErrorFromNativeStatus");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: crates/proto/crypto/proto");
assertContains(".github/workflows/protobuf-ci.yml", "BUFFA_VERSION: 0.8.1");
assertContains(".github/workflows/protobuf-ci.yml", "BUF_VERSION: 1.71.0");
assertContains(".github/workflows/protobuf-ci.yml", "buf lint");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "bufbuild/buf-setup-action@a47c93e0b1648d5651a065437926377d060baa99",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "buf breaking --against '.git#branch=origin/main' --exclude-path proto/reallyme/codec/v1/codec.proto",
);
assertContains(".github/workflows/protobuf-ci.yml", "buf generate");
assertContains(".github/workflows/protobuf-ci.yml", "redact_crypto_proto_debug.mjs");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "git diff --exit-code -- crates/proto/crypto/proto crates/proto/crypto/src/generated packages/ts/src/proto/generated gen",
);
assertContains("crates/proto/crypto/Cargo.toml", '"/proto/**/*.proto"');
assertContains(".github/workflows/protobuf-ci.yml", 'protoc-gen-buffa --version "$BUFFA_VERSION"');
assertContains(
  ".github/workflows/protobuf-ci.yml",
  'protoc-gen-buffa-packaging --version "$BUFFA_VERSION"',
);
assertNotContains("buf.gen.yaml", "json=true");
assertNotContains("Cargo.toml", 'buffa = { version = "0.8.1", features = ["json"] }');
assertContains("scripts/redact_crypto_proto_debug.mjs", "byteFieldNames");
assertContains("scripts/redact_crypto_proto_debug.mjs", "byteBearingMessageNames");
assertContains("scripts/redact_crypto_proto_debug.mjs", "debugDescription");
assertContains("scripts/redact_crypto_proto_debug.mjs", "public int hashCode()");
assertNotContains(
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  '.field("secret_key", &self.secret_key)',
);
assertNotContains(
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  '.field("payload", &self.payload)',
);
assertContains(
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  '.field("secret_key", &"<redacted>")',
);
assertContains(
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  '.field("payload", &"<redacted>")',
);
assertContains(
  "crates/proto/crypto/src/wire.rs",
  "public_wire_error_constructor_rejects_invalid_branch_reason_pairs",
);
assertContains(
  "crates/proto/crypto/src/wire.rs",
  "proto_result_envelope_rejects_malformed_crypto_error_payloads",
);
assertContains("packages/ts/src/proto.ts", "cryptoWireErrorTryNew");
assertContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "tryNew");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "tryNew");
assertContains("scripts/stage_kotlin_native_resource.mjs", '["me", "really", "crypto", "native"]');
assertContains("scripts/write_native_manifest.mjs", "reallyme-crypto-native");
assertContains(
  ".github/workflows/package-release.yml",
  "write_native_manifest.mjs build/kotlin-native-resources/me/really/crypto/native build/kotlin-native-resources/me/really/crypto/native/native-manifest.json",
);
assertContains(
  ".github/workflows/release-preflight.yml",
  "write_native_manifest.mjs build/kotlin-native-resources/me/really/crypto/native build/kotlin-native-resources/me/really/crypto/native/native-manifest.json",
);
assertContains("scripts/build_kotlin_native_resource.sh", "cargo build -p crypto-ffi --release");
assertContains("scripts/build_kotlin_native_resource.sh", "-C panic=unwind");
assertContains("scripts/build_android_native_resources.sh", "libcrypto_ffi.so");
assertContains("scripts/build_android_native_resources.sh", "-C panic=unwind");
assertContains("scripts/build_swift_xcframework.sh", "ReallyMeCryptoFFI.xcframework.zip");
assertContains("scripts/build_swift_xcframework.sh", "-C panic=unwind");
assertContains("scripts/build_swift_xcframework.sh", "Modules/module.modulemap");
assertNotContains("scripts/build_swift_xcframework.sh", "HEADERS_DIR}/module.modulemap");
assertContains("scripts/build_swift_xcframework.sh", "verify_xcframework_layout");
assertContains("scripts/build_swift_xcframework.sh", "Headers/module.modulemap");
assertContains("scripts/prepare_swift_binary_manifest.mjs", "ffiArtifactChecksum");
assertContains("scripts/prepare_swift_binary_manifest.mjs", "--local-artifact-path");
assertContains(".github/workflows/rust-ci.yml", "tool: nextest@0.9.140");
assertContains(".github/workflows/rust-ci.yml", "tool: cargo-deny@0.20.2");
assertContains(".github/workflows/rust-ci.yml", "tool: cargo-audit@0.22.2");
assertContains(".github/workflows/rust-ci.yml", "RUSTFLAGS=-Dwarnings cargo check --workspace --all-features");
assertContains("maven-central-bundle.local.sh", "MAVEN_SIGNING_KEY_ID");
assertContains("maven-central-bundle.local.sh", "KOTLIN_NATIVE_RESOURCES_DIR");
assertContains("maven-central-bundle.local.sh", "--passphrase-fd");
assertNotContains("maven-central-bundle.local.sh", '--passphrase "$MAVEN_SIGNING_PASSWORD"');
assertContains("maven-central-bundle.local.sh", "verify_bundle_signatures");
assertContains("maven-central-bundle.local.sh", 'gpg --batch --verify "$signature" "$artifact"');
assertContains("maven-central-bundle.local.sh", "ensure_kotlin_native_resources");
assertContains("maven-central-bundle.local.sh", "jvm-native-resources.yml");
assertContains("maven-central-bundle.local.sh", "gh run download");
assertContains("maven-central-bundle.local.sh", "publishMavenPublicationToLocalReleaseRepository");
assertContains("maven-central-bundle.local.sh", "publishAndroidReleasePublicationToLocalReleaseRepository");
assertContains(".github/workflows/release-preflight.yml", "jvm native preflight");
assertContains(".github/workflows/jvm-native-resources.yml", "jvm native resources");
assertContains(".github/workflows/jvm-native-resources.yml", "kotlin-native-");
assertContains(".github/workflows/jvm-native-resources.yml", "build_kotlin_native_resource.sh");
assertContains(
  ".github/workflows/jvm-native-resources.yml",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
);
assertContains(".github/workflows/release-preflight.yml", "android aar preflight");
assertContains(".github/workflows/release-preflight.yml", "android instrumented preflight");
assertContains(".github/workflows/release-preflight.yml", "connectedDebugAndroidTest");
assertContains(".github/workflows/release-preflight.yml", 'ADB="${ANDROID_HOME}/platform-tools/adb"');
assertContains(".github/workflows/release-preflight.yml", "ANDROID_AVD_HOME");
assertContains(".github/workflows/release-preflight.yml", 'emulator" -list-avds');
assertContains(".github/workflows/release-preflight.yml", 'kill -0 "${EMULATOR_PID}"');
assertNotContains(".github/workflows/release-preflight.yml", '"${ADB}" wait-for-device');
assertContains(".github/workflows/release-preflight.yml", "build_kotlin_native_resource.sh");
assertContains(".github/workflows/release-preflight.yml", "verifyReleaseAarContainsJniLibs");
assertContains(".github/workflows/release-preflight.yml", "packages/kotlin-android/gradlew");
assertContains(".github/workflows/release-preflight.yml", "REALLYME_CRYPTO_FFI_LIBRARY_PATH");
assertContains(".github/workflows/release-preflight.yml", "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains(".github/workflows/release-preflight.yml", "Build SwiftPM binary artifact");
assertContains(".github/workflows/release-preflight.yml", "Prepare local SwiftPM binary manifest");
assertContains(".github/workflows/release-preflight.yml", "--local-artifact-path build/swift/ReallyMeCryptoFFI.xcframework");
assertContains(".github/workflows/release-preflight.yml", "Test Swift package with linked binary target");
assertContains(".github/workflows/release-preflight.yml", "node scripts/check_release_readiness.mjs --release-packages");
assertContains(".github/workflows/release-preflight.yml", "npm run pack:check");
assertContains(".github/workflows/package-release.yml", "Package Release");
assertContains(".github/workflows/package-release.yml", "release metadata");
assertNotContains(".github/workflows/package-release.yml", "require_workflow_success.mjs");
assertNotContains(".github/workflows/package-release.yml", "release-preflight.yml");
assertContains(".github/workflows/package-release.yml", "Check release version matches source tree");
assertContains(".github/workflows/package-release.yml", "RELEASE_VERSION: ${{ inputs.version }}");
assertContains(".github/workflows/package-release.yml", "ReallyMeCryptoFFI.xcframework.zip");
assertContains(".github/workflows/package-release.yml", "Maven package with bundled JNI");
assertContains(".github/workflows/package-release.yml", "Android AAR with bundled JNI");
assertContains(".github/workflows/package-release.yml", "packages/kotlin-android/gradlew");
assertContains(".github/workflows/package-release.yml", "node scripts/check_release_readiness.mjs");
assertContains(".github/workflows/package-release.yml", "Verify SwiftPM manifest");
assertContains(".github/workflows/package-release.yml", "Create or update GitHub release with Swift artifact");
assertContains(".github/workflows/package-release.yml", "gh release upload");
assertContains(".github/workflows/package-release.yml", "--clobber");
assertContains(".github/workflows/package-release.yml", "gh release edit");
assertContains(".github/workflows/package-release.yml", 'release_target="$(git rev-parse HEAD)"');
assertContains(".github/workflows/package-release.yml", "node scripts/check_release_readiness.mjs --release-packages");
assertNotContains(".github/workflows/crates-release.yml", "require_workflow_success.mjs");
assertNotContains(".github/workflows/crates-release.yml", "release-preflight.yml");
assertContains(".github/workflows/crates-release.yml", "node scripts/check_release_readiness.mjs");
assertContains(".github/workflows/crates-release.yml", "node scripts/publish_crates_in_order.mjs order");
assertContains(".github/workflows/crates-release.yml", "RELEASE_VERSION: ${{ inputs.version }}");
assertContains("scripts/publish_crates_in_order.mjs", "REALLYME_CRATES_ALLOW_ALREADY_PUBLISHED");
assertContains("scripts/publish_crates_in_order.mjs", "RELEASE_VERSION must be set when publishing crates");
if (releasePackagesMode) {
  const swiftPackage = readText("Package.swift");
  const swiftFfiArtifactVersion = requireMatch(
    "Package.swift",
    /let ffiArtifactVersion = "([^"]+)"/,
    "ffiArtifactVersion",
  )[1];
  const expectedReleaseVersions = [
    ["root Cargo.toml", rustRootVersion],
    ["reallyme-crypto-proto", cryptoProtoPackageVersion],
    ["packages/ts/package.json", typescriptPackageVersion],
    ["packages/kotlin/build.gradle.kts", kotlinPackageVersion],
    ["packages/kotlin-android/build.gradle.kts", kotlinAndroidPackageVersion],
  ];
  for (const [label, expectedVersion] of expectedReleaseVersions) {
    if (swiftFfiArtifactVersion !== expectedVersion) {
      fail(
        `Package.swift ffiArtifactVersion ${swiftFfiArtifactVersion} does not match ${label} ${expectedVersion}`,
      );
    }
  }
  if (releaseVersionEnv !== undefined && releaseVersionEnv !== swiftFfiArtifactVersion) {
    fail(
      `RELEASE_VERSION ${releaseVersionEnv} does not match Package.swift ffiArtifactVersion ${swiftFfiArtifactVersion}`,
    );
  }
  if (swiftPackage.includes('let ffiArtifactChecksum = "0000000000000000000000000000000000000000000000000000000000000000"')) {
    fail("Package.swift still has the Swift binary artifact checksum placeholder");
  }
  if (!swiftPackage.includes('let ffiArtifactLocalPathOverride = ""')) {
    fail("Package.swift must use the release URL artifact in release package mode");
  }
  assertContains("Package.swift", 'cryptoTargetDependencies.append("ReallyMeCryptoFFI")');
  assertContains("Package.swift", 'cryptoSwiftSettings.append(.define("REALLYME_CRYPTO_LINKED_FFI"))');
}
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "package reallyme.crypto.v1;");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", 'option swift_prefix = "ReallyMeProto";');
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing AEAD key");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing derived key material");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing KEM shared secret");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "Decrypted plaintext may contain secret");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoError");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoPrimitiveError");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoProviderError");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoBackendError");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoProtoResultEnvelope");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "enum CryptoProtoResultStatus");
assertContains("crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto", "enum CryptoErrorReason");
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER = 100;",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM = 200;",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE = 300;",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF = 302;",
);
assertContains(
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED = 304;",
);

const orderedCounts = [...statusCounts.entries()].sort(([left], [right]) =>
  left.localeCompare(right),
);
for (const [key, count] of orderedCounts) {
  console.log(`${key} ${count}`);
}
