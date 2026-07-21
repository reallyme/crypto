#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readdirSync } from "node:fs";

import { assertCryptoOperationRouteReadiness } from "./crypto_operation_route_readiness.mjs";
import { createReleaseReadinessContext } from "./release-readiness/core.mjs";

const {
  readText,
  readJson,
  fail,
  assertContains,
  assertNotContains,
  requireMatch,
  runNodeCheck,
  assertCargoMetadataPolicy,
  assertCargoWorkspacePolicy,
  assertNodeWorkflowJobsPinNode,
  assertReallyMeProtobufReleasePolicy,
  assertProtoContract,
  assertReallyMeRustProtoRepositoryPolicy,
  assertReallyMeVendoredCorePolicy,
  assertSpdxHeaders,
  assertWorkflowActionsPinned,
  assertCargoFuzzWorkflowPolicy,
  assertTextPolicy,
  assertWorkflowPermissionsPolicy,
  assertWorkflowPolicy,
} = createReleaseReadinessContext({
  scriptUrl: import.meta.url,
  requireTrackedFiles: true,
});

const rustRootVersion = "0.3.2";
const cryptoProtoPackageVersion = "0.3.2";
const typescriptPackageVersion = "0.3.2";
const kotlinPackageVersion = "0.3.2";
const kotlinAndroidPackageVersion = "0.3.2";
const codecVersion = "0.2.0";
const rustSemverBaselineCommit = "5b8928f10777d0ce44561bb966b9425a281a05d7";
const rustSemverBaselinePath = ".semver-baseline";
const cargoSemverChecksVersion = "0.49.0";
const buffaVersion = "0.9.0";
const releaseReadinessCommit = "f27973caf9d3a12847cac4032c361f5f553c97e9";
const releaseReadinessCommand = "node .release-readiness/scripts/run-consumer-check.mjs";
const releaseReadinessCheckoutRequired = [
  "repository: reallyme/release-readiness",
  `ref: ${releaseReadinessCommit}`,
  "path: .release-readiness",
];
const checkoutAction = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd";
const gradleWrapperValidationAction =
  "gradle/actions/wrapper-validation@3f131e8634966bd73d06cc69884922b02e6faf92";
const releasePackagesMode = process.argv.includes("--release-packages");
const generatedFreshnessMode = process.argv.includes("--generated-freshness");
const requiredLanes = ["swift", "kotlin_jvm", "kotlin_android", "typescript_wasm"];
const allowedStatuses = new Set(["supported", "provider_aware", "partial", "unsupported"]);
const allowedFallbacks = new Set([
  "typed_provider_failure",
  "typed_unsupported_algorithm",
  "explicit_provider_required",
]);
const releaseVersionEnv = process.env.RELEASE_VERSION;
const escapeRegExpLiteral = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const collectRustProductionSources = (directory) => {
  const paths = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) {
      paths.push(...collectRustProductionSources(path));
    } else if (entry.isFile() && path.includes("/src/") && path.endsWith(".rs")) {
      paths.push(path);
    }
  }
  return paths;
};

const collectCargoManifests = (directory) => {
  const paths = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) {
      paths.push(...collectCargoManifests(path));
    } else if (entry.isFile() && entry.name === "Cargo.toml") {
      paths.push(path);
    }
  }
  return paths;
};

const assertZeroizingGeneratedUnknownFieldOwner = (generatedPath, messageName) => {
  const generated = readText(generatedPath);
  const structNeedle = `pub struct ${messageName} {`;
  const structStart = generated.indexOf(structNeedle);
  if (structStart < 0) {
    fail(`${generatedPath} is missing generated message ${messageName}`);
  }
  const nextStruct = generated.indexOf("\npub struct ", structStart + structNeedle.length);
  const messageRegion = generated.slice(
    structStart,
    nextStruct < 0 ? generated.length : nextStruct,
  );
  if (
    !messageRegion.includes(
      "pub __buffa_unknown_fields: __ReallyMeZeroizingUnknownFields,",
    )
  ) {
    fail(`${generatedPath} message ${messageName} does not own unknown fields in zeroizing storage`);
  }
};

if (releaseVersionEnv !== undefined && !/^[0-9]+[.][0-9]+[.][0-9]+$/.test(releaseVersionEnv)) {
  fail("RELEASE_VERSION must be an exact semver release such as 0.3.2");
}

const manifest = readJson("provider_manifest.json");
runNodeCheck("scripts/check_provider_routing.mjs");
runNodeCheck("scripts/check_negative_vectors.mjs");
runNodeCheck("scripts/crypto_operation_route_readiness.test.mjs");
runNodeCheck("scripts/prepare_semver_baseline.test.mjs");
runNodeCheck("scripts/publish_retry_policy.test.mjs");
runNodeCheck("scripts/verify_release_attestation.test.mjs");
runNodeCheck("scripts/verify_native_artifact_handoff.test.mjs");
runNodeCheck("scripts/publish_crates_in_order.mjs", ["order"]);
runNodeCheck("scripts/redact_crypto_proto_debug.mjs", ["--check-idempotent"]);
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

const rootCargo = readText("crates/crypto/Cargo.toml");
assertContains("Cargo.toml", "[workspace]");
assertContains("Cargo.toml", 'default-members = ["crates/crypto"]');
assertContains("Cargo.toml", '"crates/crypto"');
assertContains(
  "Cargo.toml",
  'aes-gcm = { version = "0.11", features = ["zeroize"] }',
);
assertNotContains("Cargo.toml", "\n[package]\n");

for (const manifestPath of [
  ...collectCargoManifests("crates"),
  ...collectCargoManifests("tools"),
]) {
  for (const line of readText(manifestPath).split("\n")) {
    const firstPartyPathDependency =
      line.includes("path =") &&
      (line.includes('package = "reallyme-crypto') ||
        /^reallyme-crypto[-a-z0-9]*\s*=\s*\{/u.test(line));
    if (
      firstPartyPathDependency &&
      !line.includes(`version = "=${rustRootVersion}"`)
    ) {
      fail(
        `${manifestPath} must pin every first-party path dependency to =${rustRootVersion}`,
      );
    }
  }
}

assertContains(
  "crates/argon2id/src/derive.rs",
  "hash_password_into_with_memory(",
);
assertContains("crates/argon2id/src/derive.rs", "Zeroizing::new(blocks)");
assertNotContains("crates/argon2id/src/derive.rs", ".hash_password_into(");
for (const needle of [
  "enforce_json_operation_policy(bytes)?",
  "JsonOperationPolicy::SecretBearing",
  "ensure_single_top_level_member",
  "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND",
]) {
  assertContains("crates/proto/src/operation_request_wire.rs", needle);
}
const operationSchema = readText(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
);
const operationRequestBlock =
  /message CryptoOperationRequest\s*\{[\s\S]*?oneof operation\s*\{([\s\S]*?)\n\s*\}/u.exec(
    operationSchema,
  );
if (operationRequestBlock === null) {
  fail("crypto.proto must define CryptoOperationRequest.operation");
}
const protoJsonSelectors = [
  ...operationRequestBlock[1].matchAll(
    /^\s*Crypto[A-Za-z0-9]+Request\s+([a-z][a-z0-9_]*)\s*=\s*\d+\s*;/gmu,
  ),
].map((match) =>
  match[1].replace(/_([a-z0-9])/gu, (_whole, character) =>
    character.toUpperCase(),
  ),
);
if (protoJsonSelectors.length === 0) {
  fail("CryptoOperationRequest.operation must define executable selectors");
}
for (const selector of protoJsonSelectors) {
  assertContains(
    "crates/proto/src/operation_request_wire.rs",
    `b"${selector}"`,
  );
}
assertNotContains(
  "crates/proto/src/wire/mod.rs",
  "pub use codec::{decode_json",
);
assertContains("crates/hpke/src/dhkem.rs", "allocate_secret_buffer(");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
  "MessageDigest.isEqual(secretKey, other.secretKey)",
);
if (!rootCargo.includes(`version = "${rustRootVersion}"`)) {
  fail(`crates/crypto/Cargo.toml is not versioned ${rustRootVersion}`);
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
assertTextPolicy({
  files: [
    {
      path: "Cargo.toml",
      required: ["overflow-checks = true"],
      forbidden: ["[patch.crates-io]"],
    },
  ],
});
const assertCodecDependencyProvenance = () => {
  const registryCodecCargoDependencies = [
    [
      "crates/crypto/dispatch/Cargo.toml",
      `codec-multikey = { package = "reallyme-codec-multikey", version = "${codecVersion}" }`,
    ],
    [
      "crates/p256/Cargo.toml",
      `codec-pem = { package = "reallyme-codec-pem", version = "${codecVersion}", optional = true }`,
    ],
    [
      "crates/jwk/Cargo.toml",
      `codec-base64url = { package = "reallyme-codec-base64url", version = "${codecVersion}" }`,
    ],
    [
      "crates/jwk/Cargo.toml",
      `codec-jcs = { package = "reallyme-codec-jcs", version = "${codecVersion}" }`,
    ],
    [
      "crates/jwk-multikey/Cargo.toml",
      `codec-multikey = { package = "reallyme-codec-multikey", version = "${codecVersion}" }`,
    ],
    [
      "crates/jwk-multikey/Cargo.toml",
      `codec-base64url = { package = "reallyme-codec-base64url", version = "${codecVersion}" }`,
    ],
  ];
  for (const [path, dependency] of registryCodecCargoDependencies) {
    assertContains(path, dependency);
    assertNotContains(path, "../../../codec/");
  }

  const registryCodecChecksums = new Map([
    ["reallyme-codec-base64url", "318534e19a178ea727b2e141fde87e892c3b338d4b8a52323b29bd3a5f50cb94"],
    ["reallyme-codec-jcs", "be98f72844bae8c270002805b7e727782f3903a9b244b81bffbc154582422a92"],
    ["reallyme-codec-multibase", "060dbf70afe2e22822c726dc38d4efb24654cca7c02b134624a11777cda966f8"],
    ["reallyme-codec-multicodec", "378589a32bb420707728dc36b693e15aaf34a0baa48cf91f50ec8c15c6b1c6f9"],
    ["reallyme-codec-multikey", "fdce86dc938b3de36f8fd6f7213dd4127cbeb47018263dbbfdeab78adb60165e"],
    ["reallyme-codec-pem", "32bcc148863f3d8d9e347f858e1bbf8f9df6154bab85b46da7da850e747f3633"],
  ]);
  for (const lockPath of ["Cargo.lock", "fuzz/Cargo.lock"]) {
    for (const [packageName, checksum] of registryCodecChecksums) {
      const escapedPackageName = escapeRegExpLiteral(packageName);
      requireMatch(
        lockPath,
        new RegExp(
          `name = "${escapedPackageName}"\\nversion = "${escapeRegExpLiteral(codecVersion)}"\\nsource = "registry\\+https://github\\.com/rust-lang/crates\\.io-index"\\nchecksum = "${checksum}"`,
          "u",
        ),
        `checksum-backed crates.io provenance for ${packageName} ${codecVersion}`,
      );
    }
  }

  const tsPackage = readJson("packages/ts/package.json");
  if (JSON.stringify(tsPackage.dependencies ?? {}).includes("../../../codec")) {
    fail("packages/ts/package.json must not depend on a local codec package path");
  }
  if ((tsPackage.dependencies ?? {})["@reallyme/codec"] !== codecVersion) {
    fail(`packages/ts/package.json must depend on published @reallyme/codec ${codecVersion}`);
  }

  assertContains("Package.swift", 'url: "https://github.com/reallyme/codec"');
  assertContains("Package.swift", `from: "${codecVersion}"`);
  assertContains("packages/kotlin/build.gradle.kts", `implementation("me.really:codec:${codecVersion}")`);
  assertContains(
    "packages/kotlin-android/build.gradle.kts",
    `implementation("me.really:codec-android:${codecVersion}")`,
  );
  assertNotContains("packages/kotlin/settings.gradle.kts", "includeBuild");
  assertNotContains("packages/kotlin/settings.gradle.kts", "../../../codec");
};

assertCodecDependencyProvenance();
if (
  !rootCargo.includes(
    'include = ["/src/**/*.rs", "/Cargo.toml", "/README.md", "/LICENSE", "/NOTICE"]',
  )
) {
  fail("crates/crypto/Cargo.toml must use an anchored package include allowlist");
}
assertNotContains("crates/crypto/Cargo.toml", "messaging-dispatch");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "aes = []");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "aes-gcm-siv = []");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "chacha20-poly1305 = []");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "hmac = []");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "sha2 = []");
assertNotContains("crates/crypto/dispatch/Cargo.toml", "sha3 = []");
assertContains("README.md", "this bundle also enables `dispatch`");
assertContains("README.md", "does not enable `signer`");
assertContains("README.md", "standalone `reallyme-crypto-x448` Rust crate");
assertNotContains("README.md", "It does not enable `dispatch`");
assertContains(
  "crates/conformance/tests/vectors/contract_tests/package_policy_tests.rs",
  '.split_once("## Algorithm Policy")',
);
assertContains(
  "SECURITY.md",
  "creates the immutable `v<version>` GitHub release and tag",
);

for (const primitivePolicy of [
  {
    crateRoot: "crates/aes256-gcm",
    manifestNeedles: [
      'wasm = [\n    "dep:aes",\n    "dep:aes-gcm",\n]',
    ],
    sourceNeedle: '#[cfg(any(feature = "native", feature = "wasm"))]',
    testPath: "crates/aes256-gcm/tests/wasm_backend_tests.rs",
    testNeedle: "package_owned_wasm_matches_nist_vector",
  },
  {
    crateRoot: "crates/ed25519",
    manifestNeedles: [
      'wasm = [\n    "crypto-csprng/wasm",\n    "dep:ed25519-dalek",\n    "dep:crypto-csprng",\n]',
    ],
  },
  ...["44", "65", "87"].map((parameterSet) => ({
    crateRoot: `crates/ml-dsa-${parameterSet}`,
    manifestNeedles: [
      'wasm = [\n    "dep:getrandom",\n    "dep:ml-dsa",\n]',
    ],
    sourceNeedle: '#[cfg(any(feature = "native", feature = "wasm"))]',
    testPath: `crates/ml-dsa-${parameterSet}/tests/ml-dsa-${parameterSet}_tests.rs`,
    testNeedle: '#![cfg(any(feature = "native", feature = "wasm"))]',
  })),
  ...["512", "768", "1024"].map((parameterSet) => ({
    crateRoot: `crates/ml-kem-${parameterSet}`,
    manifestNeedles: [
      'wasm = [\n    "dep:getrandom",\n    "dep:ml-kem",\n]',
    ],
    sourceNeedle: '#[cfg(any(feature = "native", feature = "wasm"))]',
    testPath: `crates/ml-kem-${parameterSet}/tests/ml_kem_${parameterSet}_tests.rs`,
    testNeedle: '#![cfg(any(feature = "native", feature = "wasm"))]',
  })),
  {
    crateRoot: "crates/p256",
    manifestNeedles: ['"p256/getrandom"'],
  },
  {
    crateRoot: "crates/secp256k1",
    manifestNeedles: ['"dep:k256"'],
  },
  {
    crateRoot: "crates/slh-dsa",
    manifestNeedles: [
      'wasm = [\n    "crypto-csprng/wasm",\n    "dep:crypto-csprng",\n    "dep:slh-dsa",\n]',
    ],
    sourceNeedle: '#[cfg(any(feature = "native", feature = "wasm"))]',
    testPath: "crates/slh-dsa/tests/slh_dsa_sha2_128s.rs",
    testNeedle: "sign_and_verify_round_trip",
  },
  {
    crateRoot: "crates/x25519",
    manifestNeedles: ['wasm = [\n    "dep:getrandom",\n    "dep:x25519-dalek",\n]'],
  },
]) {
  const srcEntries = readdirSync(`${primitivePolicy.crateRoot}/src`);
  if (srcEntries.includes("wasm")) {
    fail(`${primitivePolicy.crateRoot}/src/wasm must be removed in the final WASM architecture`);
  }
  for (const needle of primitivePolicy.manifestNeedles) {
    assertContains(`${primitivePolicy.crateRoot}/Cargo.toml`, needle);
  }
  if (primitivePolicy.sourceNeedle !== undefined) {
    assertContains(`${primitivePolicy.crateRoot}/src/lib.rs`, primitivePolicy.sourceNeedle);
  }
  if (primitivePolicy.testPath !== undefined) {
    assertContains(primitivePolicy.testPath, primitivePolicy.testNeedle);
  }
}

assertTextPolicy({
  files: [
    {
      path: "crates/x-wing/src/encapsulate.rs",
      required: [
        "let mut ml_kem_randomness = Zeroizing::new([0u8; ML_KEM_SHARED_SECRET_LEN]);",
        "let x25519_shared_secret = Zeroizing::new(x25519_shared.to_bytes());",
        "&x25519_shared_secret",
      ],
      forbidden: ["let mut ml_kem_randomness = [0u8; ML_KEM_SHARED_SECRET_LEN];"],
    },
  ],
});
assertContains(
  "crates/ed25519/tests/wasm_backend_tests.rs",
  "wasm_lane_uses_package_owned_rust_signing",
);
assertContains(
  "crates/x25519/tests/wasm_backend_tests.rs",
  "wasm_lane_uses_package_owned_rust_key_agreement",
);
assertContains(
  "crates/secp256k1/tests/wasm_boundary_tests.rs",
  "wasm_lane_uses_package_owned_rust_bip340",
);

for (const signatureWasmRoute of [
  "crates/wasm/src/ml_dsa.rs",
  "crates/wasm/src/slh_dsa.rs",
]) {
  assertContains(signatureWasmRoute, "crypto_runtime::");
  assertContains(signatureWasmRoute, "copy_exact(");
  assertNotContains(signatureWasmRoute, "fn require_len(");
}
assertNotContains("crates/wasm/src/ml_dsa.rs", "crypto_ml_dsa_");
assertNotContains("crates/wasm/src/slh_dsa.rs", "crypto_slh_dsa::");

assertContains("crates/csprng/Cargo.toml", "secrecy = { workspace = true }");
for (const keygenPath of [
  "crates/ed25519/src/native/keypair.rs",
  "crates/slh-dsa/src/native/generate.rs",
]) {
  assertContains(keygenPath, "OsSecureRandom");
  assertNotContains(keygenPath, "rand::rng()");
  assertNotContains(keygenPath, "thread_rng()");
}
for (const productionSource of collectRustProductionSources("crates")) {
  assertNotContains(productionSource, "rand::rng()");
  assertNotContains(productionSource, "thread_rng()");
}
for (const sspPolicy of [
  {
    type: "Aes256GcmKeyMaterial",
    generate: "generate_aes256_gcm_key",
    kind: "Aes256GcmKey",
    constant: "AES_256_GCM_KEY_LENGTH",
  },
  {
    type: "MlKem1024Seed",
    generate: "generate_ml_kem_1024_seed",
    kind: "MlKem1024Seed",
    constant: "ML_KEM_1024_SEED_LENGTH",
  },
  {
    type: "MlDsa87Seed",
    generate: "generate_ml_dsa_87_seed",
    kind: "MlDsa87Seed",
    constant: "ML_DSA_87_SEED_LENGTH",
  },
]) {
  assertContains("crates/crypto/core/src/error/rng.rs", `RngOutputKind::${sspPolicy.kind}`);
  assertContains("crates/csprng/src/constants.rs", sspPolicy.constant);
  assertContains("crates/csprng/src/types.rs", `pub struct ${sspPolicy.type}`);
  assertContains("crates/csprng/src/types.rs", "SecretBox<[u8;");
  assertContains("crates/csprng/src/types.rs", "#[derive(Zeroize, ZeroizeOnDrop)]");
  assertContains("crates/csprng/src/generate.rs", `pub fn ${sspPolicy.generate}`);
  assertContains("crates/csprng/tests/csprng_tests.rs", sspPolicy.generate);
}
if (!rootCargo.includes('"crypto-dispatch?/ed25519"')) {
  fail("root algorithm features must conditionally forward into dispatch");
}
if (!rootCargo.includes('"crypto-signer?/ed25519"')) {
  fail("root signature features must conditionally forward into signer");
}

const ffiCargo = readText("crates/ffi/Cargo.toml");
if (!ffiCargo.includes("publish = false")) {
  fail("crates/ffi must remain publish = false");
}
assertContains("crates/ffi/Cargo.toml", 'test-vectors = ["reallyme-crypto/test-vectors"]');
assertNotContains("crates/ffi/abi/reallyme_crypto_ffi.h", "encapsulate_derand");
assertNotContains("crates/wasm/Cargo.toml", 'features = ["wasm", "test-vectors"]');
assertNotContains("packages/ts/src/wasmProvider.ts", "EncapsulateDerand");
assertNotContains("packages/ts/src/wasmProvider.ts", "SealDerand");
assertNotContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "EncapsulateDerand",
);

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

const cryptoProtoCargo = readText("crates/proto/Cargo.toml");
if (!cryptoProtoCargo.includes(`version = "${cryptoProtoPackageVersion}"`)) {
  fail(`crates/proto/Cargo.toml is not versioned ${cryptoProtoPackageVersion}`);
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
  fail("crates/proto/Cargo.toml must use an anchored package include allowlist");
}
assertContains(
  "crates/proto/README.md",
  `reallyme-crypto-proto = { version = "${cryptoProtoPackageVersion}", features = ["generated"] }`,
);
assertContains(
  "scripts/publish_crates_in_order.mjs",
  'requirePublishOrderBefore("reallyme-crypto-proto", "reallyme-crypto")',
);
assertContains("buf.gen.yaml", "out: crates/proto/src/generated/buffa");
assertNotContains("buf.gen.yaml", "reallyme.crypto.v1.**");
assertNotContains("buf.gen.yaml", "types:");
assertContains("buf.gen.yaml", "buf.build/bufbuild/es:v2.12.1");
assertContains("buf.gen.yaml", "buf.build/apple/swift:v1.38.1");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/java:v35.1");
assertContains("buf.gen.yaml", "buf.build/protocolbuffers/kotlin:v35.1");
assertContains("crates/proto/src/generated/buffa/mod.rs", "pub mod crypto");
assertProtoContract("crates/proto/proto/reallyme/crypto/v1/crypto.proto");
if (readdirSync("crates/crypto/src").includes("proto_process.rs")) {
  fail("crates/crypto/src/proto_process.rs must remain absent from the final architecture");
}
if (readdirSync("crates/wasm/src").includes("proto_process.rs")) {
  fail("crates/wasm/src/proto_process.rs must remain absent from the final architecture");
}
if (readdirSync("crates/ffi/src").includes("proto_process.rs")) {
  fail("crates/ffi/src/proto_process.rs must remain absent from the final architecture");
}
assertContains("crates/crypto/src/lib.rs", "pub mod operation_contract");
assertNotContains("crates/crypto/src/lib.rs", "pub mod operation_response");
assertNotContains("crates/crypto/src/lib.rs", "pub mod proto_process");
assertContains(
  "crates/crypto/src/operation_contract/boundary.rs",
  "pub fn process_operation_response(",
);
assertContains(
  "crates/crypto/src/operation_contract/boundary.rs",
  "pub fn process_operation_response_json(",
);
assertContains(
  "crates/wasm/src/operation_response.rs",
  "pub fn process_operation_response(",
);
assertContains(
  "crates/wasm/src/operation_response.rs",
  "pub fn process_operation_response_json(",
);
assertNotContains("packages/ts/src/operationResponse.ts", "processProto");
assertNotContains("packages/ts/src/cryptoFacade.ts", "processProto");
assertNotContains("packages/swift/Sources/ReallyMeCrypto/OperationResponse.swift", "processProto");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt", "processProto");
assertNotContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "enum CryptoOperation",
);
assertNotContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "service CryptoService",
);
assertContains("crates/proto/src/wire/limits.rs", "CRYPTO_PROTO_UNKNOWN_FIELD_LIMIT");
assertContains("crates/proto/src/wire/codec.rs", "with_unknown_field_limit");
assertContains("crates/proto/src/operation_response_wire.rs", "Zeroizing<Vec<u8>>");
assertContains(
  "crates/proto/src/operation_response_wire.rs",
  "MAX_CRYPTO_OPERATION_RESPONSE_BYTES",
);
assertNotContains("crates/proto/src/wire/mod.rs", "mod result");
assertContains("crates/ffi/src/pointer.rs", "begin_input_range_call");
assertContains("crates/ffi/src/pointer.rs", "validate_registered_inputs_against_output");
assertNotContains("crates/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_process_proto");
assertNotContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_PROTO_MAX_REQUEST_LEN",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_PROTOBUF_MAX_REQUEST_LEN",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_PROTO_JSON_MAX_REQUEST_LEN",
);
assertNotContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_PROTO_MAX_RESULT_ENVELOPE_LEN",
);
assertContains(
  "crates/ffi/src/kotlin_proto.rs",
  "MAX_CRYPTO_OPERATION_RESPONSE_BYTES",
);
assertNotContains(
  "crates/ffi/src/kotlin_proto.rs",
  "const MAX_CRYPTO_PROCESS_OUTPUT_BYTES: usize = 1_048_608;",
);
assertContains(
  "crates/ffi/src/kotlin_proto.rs",
  "max_request_len.checked_add(1)",
);
assertContains(
  "crates/ffi/src/kotlin_proto.rs",
  "copying an attacker-sized managed array into native memory",
);
assertContains(
  "crates/ffi/src/kotlin_proto.rs",
  "output.len() > max_output_len",
);
assertContains(
  "packages/ts/src/operationResponse.ts",
  "const MAX_CRYPTO_OPERATION_RESPONSE_BYTES = 1_048_608;",
);
assertContains(
  "packages/ts/src/operationResponse.ts",
  "value.length > MAX_CRYPTO_OPERATION_RESPONSE_BYTES",
);
assertContains(
  "packages/ts/src/validateBytes.ts",
  "value.buffer === view.buffer",
);
assertContains(
  "packages/ts/src/validateBytes.ts",
  "readIndependentProviderBytes",
);
assertContains(
  "packages/ts/src/validateBytes.ts",
  "value.fill(0)",
);
assertContains(
  "packages/ts/src/mlKem.ts",
  "readIndependentProviderBytes(value, ML_KEM_SHARED_SECRET_LENGTH, inputs)",
);
assertNotContains(
  "packages/ts/src/mlKem.ts",
  "ensureBytes(value, ML_KEM_SHARED_SECRET_LENGTH)",
);
assertContains(
  "packages/ts/src/xWing.ts",
  "readIndependentProviderBytes(value, X_WING_SHARED_SECRET_LENGTH, inputs)",
);
assertNotContains(
  "packages/ts/src/xWing.ts",
  "ensureBytes(value, X_WING_SHARED_SECRET_LENGTH)",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "generic operation response lanes reject aliased and invalid provider outputs",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "ambient globals cannot satisfy explicit WASM provider functions",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "KEM providers wipe wrong-length decapsulation shared secrets",
);

const tsPackage = readJson("packages/ts/package.json");
if (tsPackage.version !== typescriptPackageVersion) {
  fail(`packages/ts/package.json is not versioned ${typescriptPackageVersion}`);
}
if (tsPackage.private === true) {
  fail("packages/ts/package.json is still private and cannot be published to npm");
}
if (
  tsPackage.publishConfig?.access !== "public" ||
  tsPackage.publishConfig?.registry !== "https://registry.npmjs.org/"
) {
  fail("packages/ts/package.json must publish the scoped package publicly to npmjs.org");
}
if (
  tsPackage.repository?.url !== "git+https://github.com/reallyme/crypto.git" ||
  tsPackage.repository?.directory !== "packages/ts"
) {
  fail("packages/ts/package.json must identify its public source directory");
}
if (JSON.stringify(tsPackage.dependencies ?? {}).includes("../../../codec")) {
  fail("packages/ts/package.json must not depend on a local codec package path");
}
if ((tsPackage.dependencies ?? {})["@reallyme/codec"] !== codecVersion) {
  fail(`packages/ts/package.json must depend on published @reallyme/codec ${codecVersion}`);
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
assertContains("packages/ts/scripts/check-pack.mjs", "Raw WASM Module Contract");
assertContains("packages/ts/scripts/check-pack.mjs", "Direct raw WASM calls are unsupported");
assertContains("packages/ts/scripts/check-pack.mjs", "generated WASM glue references ambient crypto-provider global");
assertContains("packages/ts/scripts/check-pack.mjs", "dist/wasmModuleTypes.d.ts");
assertContains("packages/ts/scripts/check-pack.mjs", "processOperationResponse");
assertContains("packages/ts/scripts/check-pack.mjs", "argon2idDeriveKey");
assertContains(
  "packages/ts/scripts/build-wasm.mjs",
  'resolve(repositoryDirectory, "crates", "wasm")',
);
assertNotContains("packages/ts/scripts/build-wasm.mjs", '"wasm-package"');
assertContains(
  "crates/wasm/Cargo.toml",
  'crypto-runtime = { package = "reallyme-crypto", version = "=0.3.2", path = "../crypto", default-features = false, features = ["operation-response", "native"',
);
assertNotContains(
  "crates/wasm/Cargo.toml",
  'features = ["operation-response", "wasm"',
);
assertContains(
  "crates/conformance/package.json",
  "npm run --prefix ../../packages/ts build:ts",
);
assertContains(
  "crates/conformance/scripts/verify-ts-native-vectors.mjs",
  'const repoRoot = resolve(packageDir, "..", "..");',
);
assertContains(
  "crates/conformance/scripts/verify-noble-pq-vectors.mjs",
  'const repoRoot = resolve(packageDir, "..", "..");',
);
assertNotContains(
  "crates/conformance/platform/swift/Tests/ReallyMeCryptoVectorTests/RustCryptoFfi.swift",
  '.appendingPathComponent("crypto")',
);
assertContains(
  "crates/conformance/platform/swift/Tests/ReallyMeCryptoVectorTests/VectorConformanceTests.swift",
  '"operation_response.json"',
);
assertContains(
  "crates/conformance/platform/kotlin/src/test/kotlin/me/really/crypto/conformance/VectorConformanceTest.kt",
  '"operation_response.json"',
);
assertContains("packages/ts/scripts/check-pack.mjs", "package/LICENSE");
assertContains("packages/ts/scripts/build-wasm.mjs", "const REQUIRED_WASM_PACK_VERSION = [0, 15, 0]");
assertContains("packages/ts/scripts/build-wasm.mjs", "const REQUIRED_WASM_BINDGEN_VERSION = [0, 2, 126]");
assertContains("packages/ts/scripts/build-wasm.mjs", '"--release"');
assertContains("packages/ts/scripts/build-wasm.mjs", "versionText(wasmPackVersion) !== versionText(REQUIRED_WASM_PACK_VERSION)");
assertContains("packages/ts/scripts/build-wasm.mjs", "versionText(wasmBindgenVersion) !== versionText(REQUIRED_WASM_BINDGEN_VERSION)");
assertNotContains("packages/ts/scripts/build-wasm.mjs", "or newer is required");
assertContains("packages/ts/package.json", '"LICENSE"');
assertNotContains("crates/wasm/src/lib.rs", "canonicalize_json_web_key");
assertNotContains("crates/wasm/src/lib.rs", "base64url_encode");
assertNotContains("packages/ts/src/wasmProvider.ts", "canonicalizeJsonWebKey");
assertNotContains("packages/ts/src/wasmModuleTypes.ts", "base64urlDecode");
assertContains("packages/ts/src/jwk.ts", "from \"@reallyme/codec\"");
assertContains("packages/ts/src/jwk.ts", "rejectPrivateKeyMaterial");
assertContains("packages/ts/src/jwk.ts", "codecBase64urlDecodeCanonical");
assertContains("packages/ts/src/jwk.ts", "ensureExactMembers");
assertContains("packages/ts/src/jwk.ts", "export const MAX_JWKS_KEYS = 1_024");
assertContains("packages/ts/src/proto.ts", "keys.length > MAX_JWKS_KEYS");
assertContains("packages/ts/src/proto.ts", "MAX_JWK_CANONICAL_JCS_LENGTH = 8_192");
assertContains("packages/ts/src/proto.ts", "ensureByteArrayAtMost(bytes, MAX_CRYPTO_INPUT_LENGTH)");
assertNotContains("packages/ts/src/proto.ts", "String.fromCharCode(...codeUnits)");
assertContains("packages/ts/src/mlDsa.ts", "value.length !== suite.signatureLength");
assertContains(
  "packages/ts/src/slhDsa.ts",
  "value.length !== SLH_DSA_SHA2_128S_SIGNATURE_LENGTH",
);
assertContains("packages/ts/README.md", "JWKS ingress routes accept at most 1,024 keys");
assertContains("packages/ts/README.md", "WebAssembly linear memory does not shrink");
assertContains("packages/ts/README.md", "Treat a WebAssembly trap as fatal");
assertContains("packages/ts/README.md", "verify those bytes against a deployment-controlled digest");
assertContains("packages/ts/src/wasmProvider.ts", "createReallyMeWasmProvider");
assertContains("packages/ts/src/wasmProvider.ts", "installedProvider !== undefined");
assertContains("packages/ts/src/wasmModuleTypes.ts", "rsaVerifyPkcs1v15");
assertContains("packages/ts/src/wasmModuleTypes.ts", "rsaVerifyPss");
assertContains("crates/wasm/src/rsa.rs", "use crypto_runtime::rsa::{");
assertContains("crates/wasm/src/rsa.rs", "RSA_PUBLIC_KEY_DER_MAX_LEN");
assertContains("crates/wasm/src/rsa.rs", "RSA_SIGNATURE_MAX_LEN");
assertContains(
  "crates/wasm/src/rsa.rs",
  "Zeroizing::new(copy_bounded(message, MAX_WASM_INPUT_LENGTH)?)",
);
assertNotContains("crates/wasm/src/rsa.rs", "message.to_vec()");
assertNotContains("crates/wasm/src/rsa.rs", "crypto_rsa::");
assertNotContains("crates/wasm/Cargo.toml", "crypto-rsa =");
assertContains(
  "crates/crypto/tests/rsa_operation_response_tests.rs",
  "every_public_rsa_suite_matches_semantic_owner_facade_and_generated_response",
);
assertContains(
  "crates/crypto/tests/rsa_operation_response_tests.rs",
  "CryptoOperationResultBranch::RsaVerify",
);
assertContains(
  "crates/rsa/tests/rsa_pss_edge_tests.rs",
  "pss_accepts_rfc8017_em_len_one_byte_shorter_than_modulus",
);
assertNotContains(
  "crates/crypto/tests/signature_operation_tests.rs",
  "rsa_pss_non_byte_aligned_modulus_fails_closed",
);
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
  "JSON and protobuf JWKS boundaries enforce the same key-count limit",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "protobuf JWK boundaries reject oversized bytes and canonical JCS with typed errors",
);
assertContains(
  "packages/ts/test/reallyme-crypto.test.mjs",
  "signature providers map wrong-length outputs to provider failure",
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
assertContains("packages/ts/README.md", "Direct raw WASM calls are unsupported for application logic.");
assertContains("packages/ts/README.md", "Custom provider objects are trusted providers");
assertContains(
  "packages/ts/test/wasm-boundary.test.mjs",
  "package-owned provider is self-verified",
);
assertContains(
  "packages/ts/src/validateBytes.ts",
  "readIndependentProviderBytes",
);
assertContains(
  "crates/wasm/src/ml_kem.rs",
  "Zeroizing::new(copy_exact",
);

const kotlinBuild = readText("packages/kotlin/build.gradle.kts");
if (!kotlinBuild.includes(`version = "${kotlinPackageVersion}"`)) {
  fail(`packages/kotlin/build.gradle.kts is not versioned ${kotlinPackageVersion}`);
}
assertContains("Package.swift", 'url: "https://github.com/reallyme/codec"');
assertContains("Package.swift", `from: "${codecVersion}"`);
assertContains("Package.swift", 'name: "ReallyMeCryptoFFI"');
assertContains("Package.swift", "ReallyMeCryptoFFI.xcframework.zip");
assertContains("Package.swift", 'let ffiArtifactLocalPathOverride = ""');
assertContains("Package.swift", "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains("Package.swift", "runtimeFfiOverrideMarkerPath");
assertContains("Package.swift", "runtimeFfiOverrideRequested &&");
assertContains("Package.swift", "FileManager.default.fileExists(atPath: runtimeFfiOverrideMarkerPath)");
assertContains("Package.swift", "if !useRuntimeFfiProvider");
assertContains("Package.swift", 'cryptoTargetDependencies.append("ReallyMeCryptoFFI")');
assertContains("Package.swift", 'cryptoSwiftSettings.append(.define("REALLYME_CRYPTO_LINKED_FFI"))');
assertNotContains("Package.swift", "build/swift/ReallyMeCryptoFFI.xcframework");
assertContains(".github/workflows/rust-ci.yml", "touch .reallyme-crypto-runtime-ffi");
assertContains(".github/workflows/swift-package-preflight.yml", "touch .reallyme-crypto-runtime-ffi");
assertContains(".github/workflows/swift-package-preflight.yml", "rm .reallyme-crypto-runtime-ffi");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "enum LinkedRustCAbiSymbol: String, CaseIterable",
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "guard let linkedSymbol = LinkedRustCAbiSymbol(symbol)",
);
assertNotContains("packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift", 'case "rm_crypto_');
assertNotContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "public func loadFunction",
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "ObjectIdentifier(requestedType) == ObjectIdentifier(Concrete.self)",
);
const swiftRustCAbiLibrary = readText(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
);
const swiftLinkedSymbols = new Set(
  [...swiftRustCAbiLibrary.matchAll(/case\s+\w+\s*=\s*"(rm_crypto_[a-z0-9_]+)"/gu)].map(
    (match) => match[1],
  ),
);
const swiftDeclaredLinkedSymbols = new Set(
  [...swiftRustCAbiLibrary.matchAll(/@_silgen_name\("(rm_crypto_[a-z0-9_]+)"\)/gu)].map(
    (match) => match[1],
  ),
);
if (
  swiftLinkedSymbols.size !== swiftDeclaredLinkedSymbols.size ||
  [...swiftLinkedSymbols].some((symbol) => !swiftDeclaredLinkedSymbols.has(symbol))
) {
  fail("Swift linked FFI symbol registry does not exactly cover its typed declarations");
}
const ffiHeader = readText("crates/ffi/abi/reallyme_crypto_ffi.h");
for (const symbol of swiftLinkedSymbols) {
  if (!ffiHeader.includes(`${symbol}(`)) {
    fail(`Swift linked FFI symbol ${symbol} is absent from the canonical C header`);
  }
}
const swiftSourceRoot = "packages/swift/Sources/ReallyMeCrypto";
for (const entry of readdirSync(swiftSourceRoot, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith(".swift")) {
    continue;
  }
  const path = `${swiftSourceRoot}/${entry.name}`;
  const source = readText(path);
  for (const match of source.matchAll(/loadFunction\(\s*"(rm_crypto_[a-z0-9_]+)"/gu)) {
    if (!swiftLinkedSymbols.has(match[1])) {
      fail(`Swift FFI call site ${path} uses unregistered linked symbol ${match[1]}`);
    }
  }
}
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoLinkedRustCAbiTypeSafetyTests.swift",
  "testLinkedSymbolRejectsMismatchedFunctionType",
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/OperationResponse.swift",
  "maxProcessOutputLength = 1_048_608",
);
assertNotContains("packages/swift/Sources/ReallyMeCrypto/OperationResponse.swift", "let sizingStatus");
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoOperationResponseTests.swift",
  "testPrimaryOperationResponseProcessorExecutesNativeOnce",
);
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
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "public enum ReallyMeRustCAbiProviderDiagnostic");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "rustCAbiDiagnostic");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "bundledProviderNotLinked");
assertNotContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeKemKeyPair: Equatable");
assertNotContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeKeyAgreementKeyPair: Equatable");
assertNotContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeKemEncapsulation: Equatable");
assertNotContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeHpkeSealedMessage: Equatable");
assertNotContains(
  "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift",
  "ReallyMeKeyAgreementHandleKeyPair: Equatable",
);
assertNotContains(
  "packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift",
  "ReallyMeKeyAgreementKeyPairProtoValue: Equatable",
);
assertNotContains(
  "packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift",
  "ReallyMeKemKeyPairProtoValue: Equatable",
);
assertNotContains(
  "packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift",
  "ReallyMeKemEncapsulationProtoValue: Equatable",
);
assertNotContains(
  "packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift",
  "ReallyMeHpkeSealedMessageProtoValue: Equatable",
);
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
assertNotContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "seed: [UInt8]");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "publicKeyDer: [UInt8]");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "private func requireRustCAbiLibrary()");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "CustomDebugStringConvertible");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "secretKey: <redacted>");
assertContains("packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "sharedSecret: <redacted>");
assertContains("packages/swift/Sources/ReallyMeCrypto/MemoryHygiene.swift", "ReallyMeCryptoMemory");
assertContains("packages/swift/Sources/ReallyMeCrypto/MemoryHygiene.swift", "memset_s");
assertContains("packages/swift/Sources/ReallyMeCrypto/JwaConcatKdf.swift", "bestEffortClear(&derived)");
assertContains("packages/swift/Sources/ReallyMeCrypto/Pbkdf2.swift", "clear(&derived)");
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/Pbkdf2SecurityTests.swift",
  "testProviderFailureClearsPreviouslyAccumulatedOutput",
);
assertContains(
  "packages/swift/Tests/ReallyMeCryptoTests/Pbkdf2SecurityTests.swift",
  "testMalformedProviderBlockFailsClosedAndIsCleared",
);
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
  "testDefaultProviderReportsBundledRustCAbiState",
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
assertContains("packages/swift/README.md", "non-interactive `.privateKeyUsage`");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/RustCAbiLibrary.swift",
  "isAbsolutePath",
);
assertContains("packages/kotlin/build.gradle.kts", "junit-jupiter-api");
assertContains(
  "packages/kotlin/build.gradle.kts",
  'environment("CARGO_ENCODED_RUSTFLAGS", "")',
);
assertContains("packages/kotlin/build.gradle.kts", "reallyme.crypto.nativeResourcesDir");
assertContains("packages/kotlin/build.gradle.kts", "verifyBundledNativeResources");
assertContains("packages/kotlin/build.gradle.kts", "verifyHostBundledNativeResource");
assertContains("packages/kotlin/build.gradle.kts", "verifyExactNativeResources");
assertContains(
  "packages/kotlin/build.gradle.kts",
  "ReallyMe crypto native resources do not match the exact required file set",
);
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
  "crates/conformance/platform/kotlin/gradle/wrapper/gradle-wrapper.properties",
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
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt",
  "if (status == ReallyMeNativeStatus.OK)",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt",
  "bytes=<redacted>",
);
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt",
  "data class ReallyMeNativeResult",
);
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeResult.kt",
  "bytes.contentHashCode()",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "loadedLibraryPath");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
  "loadedLibraryPath == canonicalPath",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Digest.kt", "catch (_: NoSuchAlgorithmException)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Hmac.kt", "catch (_: GeneralSecurityException)");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "cipherProviderName");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "signatureProviderName");
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
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt", "iterations > MAX_ITERATIONS");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt", "generator.init(password, salt, providerIterations)");
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "pbkdf2IterationConversionEnforcesPublicWorkBounds",
);
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
  "classpathNativeExtractionUsesPrivateDirectoryAndRehashesOnDiskFile",
);
assertContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "secretBearingKeyPairResultsDoNotAliasCallerInputs",
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
assertContains("crates/ffi/src/kotlin_result.rs", "status_from_crypto_status");
assertContains("crates/ffi/src/kotlin_aead.rs", "status_from_crypto_status(status)");
assertContains("crates/ffi/src/kotlin_aead.rs", "let plaintext_bytes = match");
assertContains("crates/ffi/src/kotlin_aead.rs", "Ok(value) => Zeroizing::new(value)");
assertContains("crates/ffi/src/kotlin_aead.rs", "let mut output = Zeroizing::new");
assertContains("crates/ffi/src/kotlin_argon2id.rs", "status_from_crypto_status(status)");
assertContains("crates/ffi/src/kotlin_argon2id.rs", "let secret_bytes = match");
assertContains("crates/ffi/src/kotlin_argon2id.rs", "let mut derived = Zeroizing::new");
assertContains("crates/ffi/src/kotlin_argon2id.rs", "derived.zeroize()");
assertContains(
  "crates/wasm/src/aead.rs",
  "let plaintext_bytes = Zeroizing::new(copy_bounded(plaintext, MAX_WASM_INPUT_LENGTH)?);",
);
assertContains("crates/wasm/src/hpke.rs", "copy_bounded(info, HPKE_INFO_MAX_LENGTH)?");
assertContains(
  "crates/wasm/src/argon2id.rs",
  "copy_bounded_nonempty(secret, ARGON2ID_SECRET_MAX_LENGTH)?",
);
assertNotContains("crates/wasm/src/aead.rs", "plaintext.to_vec()");
assertNotContains("crates/wasm/src/hpke.rs", "plaintext.to_vec()");
assertNotContains("crates/wasm/src/argon2id.rs", "secret.to_vec()");
assertContains("crates/wasm/src/aead.rs", "let plaintext = Zeroizing::new(");
assertContains(
  "packages/kotlin/src/test/java/me/really/crypto/ReallyMeCryptoJavaTest.java",
  "ReallyMeCrypto.hash",
);
assertContains("packages/kotlin/build.gradle.kts", `implementation("me.really:codec:${codecVersion}")`);
assertNotContains("packages/kotlin/settings.gradle.kts", "includeBuild");
assertNotContains("packages/kotlin/settings.gradle.kts", "../../../codec");
assertContains(
  "crates/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeRustNativeProvider_probeNative",
);
assertContains(
  "crates/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeArgon2id_deriveKeyNative",
);
assertContains(
  "crates/ffi/src/kotlin_aead.rs",
  "Java_me_really_crypto_ReallyMeRustAead_aes256GcmSivSealNative",
);
if (readText("crates/ffi/src/kotlin_aead.rs").includes("Java_com_reallyme_crypto")) {
  fail("Kotlin JNI symbols must use the me.really.crypto package prefix");
}
if (readText("crates/ffi/src/kotlin_argon2id.rs").includes("Java_com_reallyme_crypto")) {
  fail("Kotlin Argon2id JNI symbols must use the me.really.crypto package prefix");
}
assertContains("crates/ffi/src/kotlin_proto.rs", "fn process_operation_response");
assertContains("crates/ffi/src/kotlin_proto.rs", "reallyme_crypto::operation_contract");
assertContains("crates/ffi/src/kotlin_proto.rs", "MAX_CRYPTO_OPERATION_RESPONSE_BYTES");
const kotlinProtoBridge = readText("crates/ffi/src/kotlin_proto.rs");
const operationResponseStart = kotlinProtoBridge.indexOf("fn process_operation_response");
if (operationResponseStart < 0) {
  fail("Kotlin operation-response JNI bridge must exist");
}
if (kotlinProtoBridge.includes("fn process_proto_envelope")) {
  fail("Kotlin process-proto forwarding bridge must be removed");
}
const operationResponseBridge = kotlinProtoBridge.slice(operationResponseStart);
if (operationResponseBridge.includes("process_output(") || operationResponseBridge.includes("rm_crypto_process_")) {
  fail("Kotlin operation-response JNI bridge must not use probe/fill process_output");
}
if (!operationResponseBridge.includes("let output = process(request.as_slice())")) {
  fail("Kotlin operation-response JNI bridge must call the canonical Rust operation boundary once");
}
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "extractNativeResourceForLoad");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "Files.createTempDirectory");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "channel.force(true)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "verifyNativeResourceOnDisk");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "System.load(loadedPath.toString())");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "PosixFileAttributeView");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt", "Files.isSymbolicLink(path)");
const kotlinNativeLoader = readText(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RustNativeProvider.kt",
);
const extractedLoadStart = kotlinNativeLoader.indexOf("private fun loadExtractedLibraryStatus(");
const explicitLoadStart = kotlinNativeLoader.indexOf("public fun loadLibraryStatus(");
if (extractedLoadStart < 0 || explicitLoadStart < extractedLoadStart) {
  fail("Kotlin classpath native loader must remain a focused adapter");
}
const extractedLoad = kotlinNativeLoader.slice(extractedLoadStart, explicitLoadStart);
const finalValidation = extractedLoad.indexOf("validateExtractedLibraryForLoad(resource, path)");
const systemLoad = extractedLoad.indexOf("System.load(loadedPath.toString())");
if (finalValidation < 0 || systemLoad <= finalValidation) {
  fail("Kotlin classpath native loader must revalidate the extracted library immediately before load");
}
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P256Ecdh.kt", "FixedPointCombMultiplier");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P384Ecdh.kt", "FixedPointCombMultiplier");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/P521Ecdh.kt", "FixedPointCombMultiplier");
assertNotContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
  "loadCodecProviderForTest",
);
assertNotContains(
  "packages/kotlin/src/test/kotlin/me/really/crypto/ProtoAdapterTest.kt",
  "loadCodecProviderForTest",
);
for (const metadataPath of [
  "packages/kotlin/gradle/verification-metadata.xml",
  "packages/kotlin-android/gradle/verification-metadata.xml",
  "crates/conformance/platform/kotlin/gradle/verification-metadata.xml",
]) {
  assertContains(metadataPath, "<verification-metadata");
  assertContains(metadataPath, "<sha256 value=");
}
assertContains(
  "docs/maven-provenance.md",
  "d05881f156df4b84a1d08ae074c9bd64a179d405b015f4d676fc8e8d9921b65f",
);
assertContains(
  "docs/maven-provenance.md",
  "0cbd62443dc06a775b378c86556c29f87f5e4a6da05575903300cb66e174cba0",
);
assertContains(
  "docs/maven-provenance.md",
  "142c9175ab012f8f715bbf5972117ea2cd867524",
);
assertContains("packages/kotlin/README.md", "intentionally use Gradle 9.6.1");
assertContains("packages/kotlin/README.md", "independently pinned to Gradle 8.14.4");

const kotlinAndroidBuild = readText("packages/kotlin-android/build.gradle.kts");
if (!kotlinAndroidBuild.includes(`version = "${kotlinAndroidPackageVersion}"`)) {
  fail(`packages/kotlin-android/build.gradle.kts is not versioned ${kotlinAndroidPackageVersion}`);
}
assertContains("packages/kotlin-android/settings.gradle.kts", 'rootProject.name = "reallyme-crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", 'artifactId = "crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", `implementation("me.really:codec-android:${codecVersion}")`);
assertContains("packages/kotlin-android/build.gradle.kts", "patchAndroidModuleCapabilities");
assertContains("packages/kotlin-android/build.gradle.kts", '"name" to "crypto-android"');
assertContains("packages/kotlin-android/build.gradle.kts", '"name" to "crypto"');
assertContains("packages/kotlin-android/build.gradle.kts", "releaseVariantReleaseApiPublication");
assertContains("packages/kotlin-android/build.gradle.kts", "releaseVariantReleaseRuntimePublication");
assertContains("packages/kotlin-android/build.gradle.kts", "reallyme.crypto.androidJniLibsDir");
assertContains("packages/kotlin-android/build.gradle.kts", "jniLibs.setSrcDirs(listOf(jniLibsDir.get()))");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyReleaseAarContainsJniLibs");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyAndroidNativeManifest");
assertContains("packages/kotlin-android/build.gradle.kts", "Android native manifest does not match packaged JNI bytes");
assertContains("packages/kotlin-android/build.gradle.kts", "release AAR JNI entry set does not match the approved ABI set");
assertContains("packages/kotlin-android/build.gradle.kts", 'ndkVersion = androidNdkVersion');
assertContains("packages/kotlin-android/build.gradle.kts", 'keepDebugSymbols.add("**/libcrypto_ffi.so")');
assertContains("packages/kotlin-android/build.gradle.kts", "assets.srcDir(nativeAssetsDir.get().path)");
assertContains("packages/kotlin-android/build.gradle.kts", "reallyme-crypto/native-manifest.json");
assertContains("packages/kotlin-android/build.gradle.kts", "buildAndroidJniLibs");
assertContains("packages/kotlin-android/build.gradle.kts", "androidJniLib64BitLoadAlignments");
assertContains("packages/kotlin-android/build.gradle.kts", "verifyElf64LoadAlignment");
assertContains("packages/kotlin-android/build.gradle.kts", "16_384L");
assertContains("packages/kotlin-android/build.gradle.kts", "androidJniLib32BitAlignmentPolicy");
assertContains("scripts/build_android_native_resources.sh", "max-page-size=16384");
assertContains("scripts/build_android_native_resources.sh", 'llvm-strip" --strip-debug');
assertContains("packages/kotlin-android/scripts/build-jni-libs.sh", "29.0.14206865");
assertContains(
  "packages/kotlin-android/gradle/verification-metadata.xml",
  "aapt2-8.13.0-13719691-linux.jar",
);
assertContains(
  "packages/kotlin-android/gradle/verification-metadata.xml",
  "aapt2-8.13.0-13719691-osx.jar",
);
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
assertContains("packages/kotlin-android/README.md", "ReallyMeAndroidPlatformKeys");
assertContains("packages/kotlin-android/README.md", "A StrongBox request is strict and never");
assertContains("packages/kotlin/README.md", "`me.really:crypto`");
assertContains("packages/kotlin-android/README.md", "`me.really:crypto`");
assertContains("provider_manifest.json", '"api": "ReallyMeP256Ecdsa and ReallyMeAndroidPlatformKeys"');
assertContains("provider_manifest.json", '"api": "ReallyMeP256Ecdh and ReallyMeAndroidPlatformKeys"');
assertContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", "KeyProperties.PURPOSE_AGREE_KEY");
assertContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", "KeyProperties.SECURITY_LEVEL_STRONGBOX");
assertContains(
  "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt",
  "KeyFactory.getInstance(EC_ALGORITHM, ANDROID_OPENSSL)",
);
assertContains(
  "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt",
  "return withMappedPlatformErrors {",
);
assertContains(
  "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt",
  "Prefer [deriveSharedSecret] outside that prompt flow",
);
assertNotContains(
  "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt",
  "challenge.fill(0)",
);
assertContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", "privateKey.encoded != null");
assertContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", "private fun requirePlatformKeyApi()");
assertNotContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", "isInsideSecureHardware");
assertNotContains("packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt", '@Suppress("DEPRECATION")');
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "p256AndroidKeystoreSigningIsHardwareBackedOrFailsClosed");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "p256AndroidKeystoreEcdhIsHardwareBackedOrFailsClosed");
assertContains("packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt", "p256AndroidStrongBoxSigningWhenAdvertised");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "BouncyCastleProvider()");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "isBundledBouncyCastleProvider");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "Security.getProvider");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt", "takeUnless");
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt",
  "Cipher.getInstance(transformation)",
);
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/JceProviders.kt",
  "Signature.getInstance(algorithm)",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/AesGcm.kt",
  "ReallyMeJceProviders.bouncyCastleCipher",
);
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/AesGcm.kt",
  "ReallyMeJceProviders.cipher(",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt",
  "ReallyMeJceProviders.bouncyCastleSignature",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt",
  "ReallyMeJceProviders.bouncyCastleKeyFactory",
);
assertNotContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/RsaVerify.kt",
  "ReallyMeJceProviders.signature(",
);
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "ReallyMeJceProviders.bouncyCastleCipher");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt", "ReallyMeJceProviders.cipher(");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt",
  "wrapped.size != keyToWrap.size + INTEGRITY_LENGTH",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/AesKw.kt",
  "encoded.size != wrappedKey.size - INTEGRITY_LENGTH",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/Kmac.kt",
  "derived.size != outputLength",
);
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
assertContains("README.md", "The protobuf schema is the source of truth");
assertContains("SECURITY.md", "PROVIDER_POLICY.md");
assertContains("SECURITY_MEMORY_MODEL.md", "scripts/check_release_readiness.mjs");
assertContains("SECURITY_MEMORY_MODEL.md", "Managed-runtime best-effort cleanup helpers");
assertContains("SECURITY_MEMORY_MODEL.md", "ReallyMeCryptoMemory.bestEffortClear(&bytes)");
assertContains("SECURITY_MEMORY_MODEL.md", "bestEffortClear(bytes)");
assertContains("SECURITY_MEMORY_MODEL.md", "not guaranteed-zeroized storage");
assertContains(
  "SECURITY_MEMORY_MODEL.md",
  "fail serde `Serialize` with a fixed error",
);
assertContains(
  "SECURITY_MEMORY_MODEL.md",
  "Generic AEAD primitive and dispatch APIs treat `aad` as caller-provided bytes",
);
assertContains("RELEASE_NOTES.md", "## 0.3.0");
assertContains("RELEASE_NOTES.md", "## 0.3.2");
assertContains("RELEASE_NOTES.md", "legacy `reallyme.codec.v1` protobuf/package surface was removed");
assertContains("RELEASE_NOTES.md", "not a `reallyme.crypto.v1` wire break");
assertContains("RELEASE_NOTES.md", "permanently retired in this repository");
assertContains("RELEASE_CHECKLIST.md", "# Release Checklist");
assertContains("RELEASE_CHECKLIST.md", "Public SwiftPM releases ship `ReallyMeCryptoFFI`");
assertContains("RELEASE_CHECKLIST.md", "must point at the reviewed manifest commit");
assertContains("RELEASE_CHECKLIST.md", "Release workflows never modify or push source");
assertContains("RELEASE_CHECKLIST.md", "`me.really:crypto-android` as an AAR");
assertContains("RELEASE_CHECKLIST.md", "`npm run pack:check`");
assertContains(".github/workflows/rust-ci.yml", "workflow_dispatch:");
assertContains(".github/workflows/rust-ci.yml", "!PROVIDER_POLICY.md");
assertContains(".github/workflows/rust-ci.yml", "!CONTRACT.md");
assertContains(".github/workflows/rust-ci.yml", "cargo package --locked -p reallyme-crypto --list");
assertContains(".github/workflows/rust-ci.yml", "Verify OpenMLS HPKE dependency isolation");
assertContains(
  ".github/workflows/rust-ci.yml",
  "--no-default-features --features native,hpke-openmls -e normal,build",
);
assertContains(
  ".github/workflows/rust-ci.yml",
  "p256|p521|k256|x448|reallyme-crypto-secp256k1|reallyme-crypto-x448",
);
assertContains(".github/workflows/rust-ci.yml", "node scripts/generate_provider_matrix.mjs --check");
assertContains(".github/workflows/rust-ci.yml", releaseReadinessCommand);
assertContains(".github/workflows/rust-ci.yml", "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains(".github/workflows/fuzz.yml", "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
assertContains(".github/workflows/fuzz.yml", "cargo install cargo-fuzz --version 0.13.2 --locked");
assertContains(".github/workflows/fuzz.yml", "crates/crypto/src/operation_contract/**");
assertNotContains(".github/workflows/fuzz.yml", "crates/crypto/src/operation_response.rs");
assertContains(".github/workflows/fuzz.yml", "crates/proto/**");
assertContains(".github/workflows/fuzz.yml", "crates/p384/**");
assertContains(".github/workflows/fuzz.yml", "crates/p521/**");
assertContains(".github/workflows/fuzz.yml", "crates/secp256k1/**");
assertContains(".github/workflows/fuzz.yml", "crates/jwk/**");
assertContains(".github/workflows/fuzz.yml", "crates/jwk-multikey/**");
assertContains(".github/workflows/fuzz.yml", "operation_response");
assertContains(".github/workflows/fuzz.yml", "jwk_multikey");
assertContains(".github/workflows/fuzz.yml", "key_encodings");
assertNotContains(".github/workflows/fuzz.yml", "proto_result_envelope");
assertContains(".github/workflows/fuzz.yml", "post_quantum_encodings");
assertContains(".github/workflows/fuzz.yml", "operation_family_boundaries");
assertContains("fuzz/Cargo.toml", 'name = "operation_response"');
assertContains("fuzz/Cargo.toml", 'name = "jwk_multikey"');
assertContains("fuzz/Cargo.toml", 'name = "key_encodings"');
assertNotContains("fuzz/Cargo.toml", 'name = "proto_result_envelope"');
assertContains("fuzz/Cargo.toml", 'name = "post_quantum_encodings"');
assertContains("fuzz/Cargo.toml", 'name = "operation_family_boundaries"');
assertContains("fuzz/Cargo.toml", 'crypto-hpke = { package = "reallyme-crypto-hpke"');
assertContains("fuzz/Cargo.toml", 'crypto-pbkdf2 = { package = "reallyme-crypto-pbkdf2"');
assertContains("fuzz/Cargo.toml", '"hpke"');
assertContains("fuzz/Cargo.toml", '"ml-dsa-44"');
assertContains("fuzz/Cargo.toml", '"rsa"');
assertContains("fuzz/Cargo.toml", '"x-wing"');
assertContains("fuzz/Cargo.toml", '"aes-kw"');
assertContains("fuzz/Cargo.toml", '"argon2id"');
assertContains("fuzz/fuzz_targets/operation_response.rs", "process_operation_response(data)");
assertContains(
  "fuzz/fuzz_targets/operation_response.rs",
  "process_operation_response_json(data)",
);
assertNotContains(
  "fuzz/fuzz_targets/operation_response.rs",
  "from_utf8(data)",
);
assertContains(
  "crates/proto/tests/operation_request_wire_tests.rs",
  "proto_json_policy_classifies_every_operation_selector_in_the_schema",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
  "serialization of sensitive protobuf views is disabled",
);
assertContains("fuzz/fuzz_targets/jwk_multikey.rs", "serde_json::from_str::<Jwk>");
assertContains("fuzz/fuzz_targets/jwk_multikey.rs", "multikey_to_jwk(input, JwkOptions::default())");
assertNotContains("crates/jwk/src/jwk.rs", "serde(untagged)");
assertContains("crates/jwk/src/jwk/deserialize.rs", "JwtError::DuplicateMember");
assertContains("crates/jwk/src/jwk/deserialize.rs", "MAX_JWK_MEMBER_COUNT");
assertContains("crates/jwk-multikey/src/to_multikey.rs", ".public_key_bytes()");
assertContains("crates/jwk/tests/public_jwk_envelope_tests.rs", "mismatched_same_parity_y_coordinates");
assertContains("crates/jwk/tests/public_jwk_envelope_tests.rs", "rejects_duplicate_members");
assertContains("packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoJwkTests.swift", "testJwkParserRejectsMismatchedEcCoordinates");
assertContains("packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt", "jwkParserRejectsMismatchedEcCoordinates");
assertContains("packages/ts/test/reallyme-crypto.test.mjs", "rejects mismatched EC coordinates in both parity classes");
assertContains("packages/swift/Sources/ReallyMeCrypto/Jwk.swift", "canonicalizeJson(json)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Jwk.kt", "ReallyMeCodec.canonicalizeJson(json)");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/Jwk.kt", "JsonParser.parseString(canonical)");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/Jwk.kt", "FlatJwkJsonParser");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/Jwk.kt", "FlatJwksJsonParser");
assertContains("packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoJwkTests.swift", "testJwkParserRejectsDuplicateUnknownAndMixedShapeMembers");
assertContains("packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt", "jwkParserRejectsDuplicateUnknownAndMixedShapeMembers");
assertContains("vectors/negative/fail_closed.json", "jwk-ec-mismatched-y-same-parity");
assertContains("vectors/negative/fail_closed.json", "jwk-ec-mismatched-y-opposite-parity");
assertContains("fuzz/fuzz_targets/key_encodings.rs", "private_key_from_pkcs8_der(data)");
assertContains("fuzz/fuzz_targets/key_encodings.rs", "verify_p384_der_prehash");
assertContains("fuzz/fuzz_targets/key_encodings.rs", "verify_p521_der_prehash");
assertContains("fuzz/fuzz_targets/key_encodings.rs", "secp256k1_ecdsa_der_to_jose_signature(data)");
assertNotContains("crates/p256/src/lib.rs", "der_to_jose_signature_permissive");
assertNotContains("crates/secp256k1/src/lib.rs", "der_to_jose_signature_permissive");
assertNotContains("fuzz/fuzz_targets/key_encodings.rs", "der_to_jose_signature_permissive");
assertContains("crates/p256/src/jose_signature.rs", "P256_CURVE_ORDER");
assertContains("crates/secp256k1/src/jose_signature.rs", "SECP256K1_CURVE_ORDER");
assertContains(
  "crates/p256/tests/jose_signature_tests.rs",
  "rejects_zero_and_out_of_range_p256_scalars",
);
assertContains(
  "crates/secp256k1/tests/jose_signature_tests.rs",
  "rejects_zero_and_out_of_range_secp256k1_scalars",
);
if (readdirSync("fuzz/fuzz_targets").includes("proto_result_envelope.rs")) {
  fail("removed proto_result_envelope fuzz target must not return");
}
assertContains("fuzz/fuzz_targets/post_quantum_encodings.rs", "ml_kem_512_decapsulate");
assertContains("fuzz/fuzz_targets/post_quantum_encodings.rs", "verify_ml_dsa_87");
assertContains("fuzz/fuzz_targets/post_quantum_encodings.rs", "verify_slh_dsa_sha2_128s");
assertContains("fuzz/fuzz_targets/operation_family_boundaries.rs", "HpkeKemId::try_from");
assertContains("fuzz/fuzz_targets/operation_family_boundaries.rs", "Pbkdf2Iterations::from_u32_modern");
assertContains(
  "crates/pbkdf2/src/constants.rs",
  "PBKDF2_MAX_ITERATIONS: u32 = 10_000_000",
);
assertContains(
  "crates/pbkdf2/src/types.rs",
  "PBKDF2_MODERN_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS",
);
assertContains(
  "crates/crypto/tests/kdf_operation_response_tests.rs",
  "operation_response_rejects_excessive_pbkdf2_work_before_derivation",
);
assertContains(
  "packages/ts/src/algorithms.ts",
  "export type ReallyMePbkdf2Algorithm = Extract<",
);
assertContains(
  "packages/ts/src/cryptoFacade.ts",
  "algorithm: ReallyMePbkdf2Algorithm",
);
assertContains(
  "packages/ts/src/cryptoFacade.ts",
  "deriveArgon2id(",
);
assertNotContains(
  "packages/ts/src/cryptoFacade.ts",
  'case "Argon2id":\n        throw new ReallyMeCryptoError("unsupported-algorithm")',
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift",
  "case .argon2id:\n            throw ReallyMeCryptoError.unsupportedAlgorithm",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
  "public fun deriveArgon2id(",
);
assertContains(
  "packages/ts/src/pbkdf2.ts",
  "PBKDF2_MAX_ITERATIONS = 10_000_000",
);
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/Pbkdf2.swift",
  "maxIterations: UInt32 = 10_000_000",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt",
  "MAX_ITERATIONS: UInt = 10_000_000u",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_PBKDF2_ITERATIONS_MAX     10000000",
);
assertContains("fuzz/fuzz_targets/operation_family_boundaries.rs", "derive_jwa_concat_kdf_sha256");
assertContains("fuzz/fuzz_targets/operation_family_boundaries.rs", "open_psk");
assertContains("fuzz/README.md", "`operation_response`");
assertContains("fuzz/README.md", "`jwk_multikey`");
assertContains("fuzz/README.md", "`key_encodings`");
assertNotContains("fuzz/README.md", "`proto_result_envelope`");
assertContains("fuzz/README.md", "`post_quantum_encodings`");
assertContains("fuzz/README.md", "`operation_family_boundaries`");
assertContains("fuzz/README.md", "cargo install cargo-fuzz --version 0.13.2 --locked");
assertContains("crates/p256/src/import_pem.rs", "validate_der_input(der)?");
assertContains(
  "crates/p256/src/import_pem.rs",
  "der.len() > P256_MAX_KEY_DER_LEN",
);
assertContains("PROVIDER_POLICY.md", "Generated from `provider_manifest.json`");
assertContains("PROVIDER_POLICY.md", "Every provider route must implement identical input validation");
assertNotContains("PROVIDER_POLICY.md", "JCA/JCE -> BouncyCastle");
assertNotContains("PROVIDER_POLICY.md", "JCA/JCE → BouncyCastle");
assertContains("README.md", "AES-128/192/256-KW");
assertContains("packages/kotlin/README.md", "for AES-GCM, AES-KW, RSA verification");
assertContains("CONTRACT.md", "## Canonical Contract");
assertContains("CONTRACT.md", "CryptoOperationRequest");
assertContains("CONTRACT.md", "provider_manifest.json");
assertContains("CONTRACT.md", "`vectors/`");
assertContains("CONTRACT.md", "Rust remains the reference implementation");
assertContains("vectors/manifest.json", '"negative_vectors"');
assertContains("vectors/manifest.json", '"lifecycle_vectors"');
assertContains("vectors/negative/fail_closed.json", '"schemaVersion": 1');
assertContains("vectors/negative/fail_closed.json", "pbkdf2-hmac-sha256-below-public-minimum");
assertContains("vectors/negative/fail_closed.json", "platform-key-secure-enclave-duplicate-tag");
assertContains("vectors/platform_key_lifecycle.json", "swift-secure-enclave-ecdh-duplicate-tag");
assertContains("vectors/platform_key_lifecycle.json", "swift-secure-enclave-ecdh-round-trip");
assertContains("vectors/platform_key_lifecycle.json", "swift-secure-enclave-ecdh-idempotent-delete");
assertContains("vectors/platform_key_lifecycle.json", "swift-secure-enclave-signing-duplicate-tag");
assertContains("vectors/platform_key_lifecycle.json", "swift-secure-enclave-signing-round-trip");
assertContains("vectors/platform_key_lifecycle.json", '"outcome": "success"');
assertContains("vectors/platform_key_lifecycle.json", '"evidence"');
assertContains("vectors/platform_key_lifecycle.json", "android-strongbox-signing-round-trip");
assertContains("crates/conformance/src/bin/gen_vectors/model.rs", "lifecycle_vectors");
assertContains("crates/conformance/src/bin/gen_vectors/manifest.rs", "platform_key_lifecycle.json");
assertContains("crates/conformance/scripts/verify-ts-native-vectors.mjs", '"hmac_sha384"');
assertContains("crates/conformance/scripts/verify-ts-native-vectors.mjs", '"hkdf_sha384.json"');
assertContains(
  "crates/conformance/tests/vectors/manifest_tests.rs",
  "platform_key_lifecycle_vectors_pin_hardware_provider_policy",
);
assertContains(
  "crates/crypto/tests/provider_manifest_tests.rs",
  "hardware_backed_providers_are_explicit_handle_backed_routes_only",
);
assertContains("scripts/check_negative_vectors.mjs", "negative vector check passed");
assertNotContains("buf.yaml", "reallyme/codec/v1/codec.proto");
assertContains("docs/protobuf.md", "not a generated mirror of the Rust package API");
assertContains("docs/protobuf.md", "CryptoOperationResponse");
assertContains("docs/protobuf.md", "reallyme_crypto::operation_contract::process_operation_response");
assertContains("README.md", "reallyme_crypto::operation_contract::process_operation_response");
assertNotContains("README.md", "reallyme_crypto::operation_response::process_operation_response");
assertContains("docs/protobuf.md", "PROVIDER_UNSUPPORTED_ALGORITHM");
assertContains("docs/conformance.md", "Every provider route must prove the same contract");
assertContains("crates/crypto/Cargo.toml", "operation-response = [");
assertNotContains("crates/crypto/src/lib.rs", "pub mod constant_time");
assertNotContains("crates/crypto/src/lib.rs", "pub mod proto_process");
assertContains("crates/ffi/src/lib.rs", "pub mod operation_response");
assertNotContains("crates/ffi/src/lib.rs", "pub mod proto_process");
assertContains(
  "crates/ffi/src/operation_response.rs",
  "rm_crypto_process_operation_response",
);
assertContains("crates/ffi/src/operation_response.rs", "fn process_request(");
assertContains("crates/ffi/src/operation_response.rs", "let mut result = process(request);");
assertContains("crates/ffi/src/operation_response.rs", "result.zeroize();");
assertNotContains("crates/ffi/src/status.rs", "CRYPTO_PROTO_ERROR");
assertNotContains("crates/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_PROTO_ERROR");
assertNotContains("crates/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_PROTO_OP_");
assertNotContains("crates/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_process_proto");
assertContains("crates/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_CHACHA20_POLY1305_NONCE_LEN");
assertContains("crates/ffi/abi/reallyme_crypto_ffi.h", "RM_CRYPTO_XCHACHA20_POLY1305_NONCE_LEN");
assertContains("crates/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_chacha20_poly1305_encrypt");
assertContains("crates/ffi/abi/reallyme_crypto_ffi.h", "rm_crypto_xchacha20_poly1305_encrypt");
assertContains("crates/ffi/tests/ffi_boundary_tests.rs", "exported_ffi_symbol_names");
assertContains("crates/ffi/tests/ffi_boundary_tests.rs", "header_declares_every_exported_ffi_symbol");
assertContains("crates/ffi/src/kotlin_result.rs", "backend_internal_result");
assertContains("crates/ffi/src/kotlin_result.rs", "clear_pending_exception");
assertContains("crates/ffi/src/kotlin_result.rs", "CRYPTO_BUFFER_TOO_SMALL => KOTLIN_NATIVE_BACKEND_INTERNAL");
assertContains(
  "crates/ffi/src/kotlin_argon2id.rs",
  "Java_me_really_crypto_ReallyMeRustNativeProvider_probeNative<'local>",
);
assertContains("crates/wasm/src/ml_kem.rs", "use crate::validate_bytes::copy_exact;");
assertContains("crates/wasm/src/ml_kem.rs", "Zeroizing::new(copy_exact(secret_key, ML_KEM_SECRET_KEY_LEN)?)");
assertNotContains("crates/wasm/src/ml_kem.rs", "fn require_len(");
assertNotContains("crates/wasm/src/ml_kem.rs", "let bytes = bytes.to_vec();");
assertContains("crates/wasm/src/ml_dsa.rs", "Zeroizing::new(copy_exact(secret_key, ML_DSA_SECRET_KEY_LEN)?)");
assertContains("crates/proto/src/lib.rs", "pub mod wire");
assertContains("crates/proto/src/wire/error.rs", "CryptoWireErrorBranch");
assertNotContains("crates/proto/src/wire/mod.rs", "CryptoProtoResult");
assertContains("crates/proto/src/wire/error.rs", "reason_code");
assertContains("crates/proto/src/operation_response_wire.rs", "Zeroizing<Vec<u8>>");
assertContains("crates/proto/src/operation_response_wire.rs", "validate_operation_response");
assertContains("crates/proto/src/operation_response_wire.rs", "CryptoOperationResponse");
assertContains("crates/proto/src/wire/error.rs", "#[non_exhaustive]");
assertContains("crates/proto/src/wire/error.rs", "pub fn try_new");
assertContains("crates/proto/src/wire/codec.rs", "decode_protobuf_with_limit");
assertContains("crates/proto/src/wire/codec.rs", "pub(crate) fn decode_json");
assertContains("crates/proto/src/operation_response_wire.rs", "encode_operation_response");
assertContains(
  "crates/proto/src/wire/codec.rs",
  "pub fn encode_protobuf<M: Message>(message: &M) -> Zeroizing<Vec<u8>>",
);
assertContains(
  "crates/proto/src/operation_response_wire.rs",
  ") -> Result<Zeroizing<Vec<u8>>, CryptoWireError>",
);
assertContains("crates/proto/src/operation_response_wire.rs", "decode_operation_response");
assertContains("crates/proto/src/operation_response_wire.rs", "with_unknown_field_limit");
assertContains("crates/proto/src/operation_response_wire.rs", "with_max_message_size");
assertContains("crates/proto/src/wire/error.rs", "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF");
assertContains("crates/proto/src/wire/codec.rs", "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_JSON");
assertContains(
  "crates/proto/src/wire/codec.rs",
  "CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED",
);
assertContains("crates/proto/src/wire/limits.rs", "MAX_CRYPTO_PROTO_MESSAGE_BYTES");
assertContains("crates/crypto/core/src/error/taxonomy.rs", "pub enum CryptoError");
assertContains("crates/crypto/core/src/error/taxonomy.rs", "#[non_exhaustive]");
assertContains(
  "crates/crypto/src/lib.rs",
  "AeadAlgorithm, Algorithm, CryptoError, HashAlgorithm, KeyWrapAlgorithm, MacAlgorithm",
);
assertContains("crates/crypto/dispatch/src/error.rs", "pub enum AlgorithmError");
assertContains("crates/crypto/dispatch/src/error.rs", "#[non_exhaustive]");
assertContains("crates/crypto/signer/src/error.rs", "pub enum SignerError");
assertContains("crates/crypto/signer/src/error.rs", "#[non_exhaustive]");
assertContains("crates/jwk/src/error.rs", "pub enum JwtError");
assertContains("crates/jwk/src/error.rs", "#[non_exhaustive]");
assertContains("crates/jwk-multikey/src/error.rs", "pub enum JwkMultikeyError");
assertContains("crates/jwk-multikey/src/error.rs", "#[non_exhaustive]");
assertContains("crates/hpke/src/error.rs", "pub enum HpkeError");
assertContains("crates/hpke/src/error.rs", "#[non_exhaustive]");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn keygen(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn derive_keypair(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn derive_keypair_from_ikm(");
assertContains(
  "crates/crypto/src/operations/hpke.rs",
  "HPKE_OPERATION_MIN_INPUT_KEY_MATERIAL_LEN: usize = 32",
);
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn setup_sender_psk(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn seal_base(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn open_base(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn sender_export(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn receiver_export(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn seal_psk(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn open_psk(");
assertContains("crates/crypto/src/operations/platform_key.rs", "pub enum PlatformKeyOperation");
assertContains("crates/crypto/src/operations/platform_key.rs", "produces_secret_material");
assertContains("crates/crypto/src/hpke.rs", "pub use crate::operations::hpke");
for (const hpkeFunction of [
  "keygen",
  "derive_keypair",
  "derive_keypair_from_ikm",
  "setup_sender_psk",
  "setup_receiver_psk",
  "seal_base",
  "open_base",
  "sender_export",
  "receiver_export",
  "seal_psk",
  "open_psk",
]) {
  assertContains("crates/crypto/src/hpke.rs", `${hpkeFunction} as ${hpkeFunction}_raw`);
  assertContains(
    "crates/crypto/src/hpke.rs",
    `${hpkeFunction} as ${hpkeFunction}_operation`,
  );
}
assertContains("crates/crypto/src/hpke.rs", "RawHpkePskSenderContext");
assertContains("crates/crypto/src/hpke.rs", "RawHpkePskSenderSetupOutput");
assertContains("crates/crypto/src/hpke.rs", "RawHpkeReceiverContext");
assertContains("crates/crypto/src/hpke.rs", "HpkePskRef");
assertContains("crates/crypto/src/hpke.rs", "HpkePskIdRef");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn seal_base_derand(");
assertContains("crates/crypto/src/operations/hpke.rs", "pub fn sender_export_derand(");
assertContains("crates/hpke/src/lib.rs", "sender_export_derand");
assertContains("crates/hpke/src/lib.rs", "setup_receiver_psk");
assertContains("crates/hpke/src/lib.rs", "setup_sender_psk_derand");
assertContains("crates/hpke/src/lib.rs", "HpkePskSenderContext");
// Keep the compatibility one-shot API as a facade over the stateful PSK
// implementation. A second PSK key schedule here would recreate the exact
// protocol divergence that the OpenMLS context API is intended to remove.
assertContains(
  "crates/hpke/src/seal.rs",
  "setup_sender_psk(&HpkePskSenderSetupRequest",
);
assertContains(
  "crates/hpke/src/seal.rs",
  "setup_receiver_psk(&HpkePskReceiverSetupRequest",
);
assertNotContains("crates/hpke/src/seal.rs", "OpModeS::Psk");
assertNotContains("crates/hpke/src/seal.rs", "OpModeR::Psk");
assertContains(
  "crates/hpke/src/identifiers.rs",
  "MLS_192_MLKEM1024_AES256GCM_SHA384_P384",
);
assertContains(
  "crates/hpke/src/identifiers.rs",
  "MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87",
);
assertContains(
  "crates/hpke/tests/identifier_tests.rs",
  "assert_eq!(suite.kdf_id(), 0x0011)",
);
assertContains(
  "crates/hpke/tests/openmls_compatibility_tests.rs",
  "xwing_arbitrary_ikm_matches_the_deployed_openmls_libcrux_vector",
);
assertContains(
  "crates/crypto/src/operation_contract/hpke.rs",
  "crate::operations::hpke::derive_keypair_from_ikm",
);
assertContains(
  "crates/crypto/tests/hpke_operation_contract_tests.rs",
  "post_quantum_hpke_suites_execute_through_the_serialized_contract",
);
assertContains(
  "crates/ffi/tests/operation_response_ffi_tests.rs",
  "ffi_operation_contract_executes_post_quantum_hpke_suite_matrix",
);
assertContains("crates/crypto/src/operations/random.rs", "pub fn fill_bytes(");
assertContains("crates/crypto/src/operations/key_encoding.rs", "pub fn copy_fixed_public_key(");
assertContains(
  "crates/proto/src/operation_response_wire.rs",
  "pub const MAX_CRYPTO_OPERATION_RESPONSE_BYTES",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "Only rm_crypto_process_operation_response",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "Other variable-length scalar helpers do not define probe semantics",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "Ed25519 signing accepts only a 32-byte seed",
);
assertNotContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_ED25519_EXPANDED_SECRET_KEY_LEN",
);
assertContains("crates/ffi/src/pointer.rs", "if ranges.active");
assertContains(
  "crates/ffi/tests/pointer_tests.rs",
  "nested_ffi_guard_fails_without_clearing_outer_input_ranges",
);
assertContains(
  "crates/ffi/src/aes256_gcm_siv.rs",
  "reallyme_crypto::operations::aead::seal",
);
assertContains(
  "crates/ffi/src/hpke.rs",
  "reallyme_crypto::operations",
);
assertContains(
  "crates/ffi/src/hmac.rs",
  "reallyme_crypto::operations::mac::authenticate",
);
assertContains(
  "crates/ffi/src/csprng.rs",
  "reallyme_crypto::operations::random::fill_bytes",
);
assertNotContains("crates/crypto/src/operation_contract/hpke.rs", "crypto_hpke::");
assertContains(
  "crates/crypto/tests/hpke_operation_contract_tests.rs",
  "primary_operation_contract_executes_all_hpke_branches",
);
assertNotContains("Cargo.toml", '"crates/operation-contract"');
assertContains("crates/crypto/src/lib.rs", "pub mod secret_material;");
assertContains(
  "crates/crypto/src/secret_material/policy.rs",
  "pub enum SecretMaterialOperation",
);
assertContains(
  "crates/crypto/src/secret_material/policy.rs",
  "pub struct OperationSecretMaterialPolicy",
);
for (const policyFile of [
  "destruction.rs",
  "export.rs",
  "output.rs",
  "owner.rs",
  "retention.rs",
  "sensitivity.rs",
  "zeroization.rs",
]) {
  assertContains(`crates/crypto/src/secret_material/${policyFile}`, "pub enum ");
}
for (const [operationFile, policyBinding] of [
  ["aead.rs", "SecretMaterialOperation::AeadOpen"],
  ["constant_time.rs", "SecretMaterialOperation::ConstantTimeCompare"],
  ["hash.rs", "SecretMaterialOperation::Hash"],
  ["hpke.rs", "SecretMaterialOperation::HpkeOpen"],
  ["kdf.rs", "SecretMaterialOperation::KeyDerivation"],
  ["kem.rs", "SecretMaterialOperation::KemDecapsulate"],
  ["key_agreement.rs", "SecretMaterialOperation::KeyAgreementSharedSecret"],
  ["key_encoding.rs", "SecretMaterialOperation::PublicKeyEncoding"],
  ["key_wrap.rs", "SecretMaterialOperation::KeyUnwrap"],
  ["mac.rs", "SecretMaterialOperation::MacAuthenticate"],
  ["random.rs", "bind_random_fill_policy(kind)"],
  ["signature.rs", "SecretMaterialOperation::SignatureSign"],
]) {
  assertContains(`crates/crypto/src/operations/${operationFile}`, policyBinding);
}
assertContains(
  "crates/crypto/dispatch/src/provider.rs",
  "pub struct ProviderDecision",
);
for (const field of [
  "pub operation: ProviderOperation",
  "pub algorithm: Algorithm",
  "pub provider_kind: ProviderKind",
  "pub lane: ProviderLane",
  "pub disposition: ProviderDisposition",
  "pub reason: ProviderPolicyReason",
  "pub key_residency: KeyResidency",
  "pub key_copy_boundary: KeyCopyBoundary",
  "pub output_policy: ProviderOutputPolicy",
  "pub fallback: FallbackPolicy",
]) {
  assertContains("crates/crypto/dispatch/src/provider.rs", field);
}
for (const registryFile of ["key_exchange.rs", "key_management.rs", "signature.rs"]) {
  assertContains(
    `crates/crypto/dispatch/src/registry/${registryFile}`,
    "require_provider(",
  );
}
assertNotContains("crates/crypto/src/operations/error.rs", "ContractErrorReason");
assertNotContains("crates/crypto/src/operations/error.rs", "MalformedProtobuf");
assertContains("vectors/manifest.json", '"vectors"');
assertContains("docs/architecture.md", "ReallyMe Crypto is a proto-first");
assertContains("docs/provider-selection.md", "inspectable `ProviderDecision`");
assertContains("packages/ts/src/proto.ts", "ReallyMeCryptoWireError");
assertNotContains("packages/ts/src/proto.ts", "ReallyMeCryptoProtoResult");
assertNotContains("packages/ts/src/proto.ts", "cryptoProtoResult");
assertNotContains("packages/ts/src/proto.ts", "cryptoProtoErrorResult");
assertContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "ReallyMeCryptoWireError");
assertNotContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "ReallyMeCryptoProtoResult");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "ReallyMeCryptoWireError");
assertNotContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "ReallyMeCryptoProtoResult");
if (readdirSync("gen/java/me/really/crypto/v1").some((name) => name.startsWith("CryptoProtoResult"))) {
  fail("retired Java result-envelope bindings must remain absent");
}
if (readdirSync("gen/kotlin/me/really/crypto/v1").some((name) => name.startsWith("CryptoProtoResult"))) {
  fail("retired Kotlin result-envelope bindings must remain absent");
}
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "wireErrorFromNativeStatus");
assertContains("buf.yaml", "modules:");
assertContains("buf.yaml", "- path: crates/proto/proto");
assertContains(".github/workflows/protobuf-ci.yml", `BUFFA_VERSION: ${buffaVersion}`);
assertContains(".github/workflows/protobuf-ci.yml", "BUF_VERSION: 1.71.0");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/release-readiness/core.mjs");
assertContains(".github/workflows/protobuf-ci.yml", "scripts/run_pinned_release_readiness.mjs");
assertNotContains(".github/workflows/protobuf-ci.yml", "buf breaking");
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "contract_tests::protobuf_algorithm_enum_numbers_are_stable",
);
assertContains(
  ".github/workflows/protobuf-ci.yml",
  "contract_tests::every_public_algorithm_has_exactly_one_proto_selector",
);
assertContains("scripts/release-readiness/core.mjs", "assertReallyMeProtobufReleasePolicy");
const protobufReleasePolicy = {
  workflowMode: "delegated",
  buffaVersion,
  generatedFreshnessStepRun:
    `${releaseReadinessCommand} --generated-freshness`,
  installBufUses:
    "bufbuild/buf-setup-action@a47c93e0b1648d5651a065437926377d060baa99",
  hardeningPolicy: {
    hardeningScript: "scripts/redact_crypto_proto_debug.mjs",
    protoSchema: "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
    generatedRust: "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
    generatedView: "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
    protoCargo: "crates/proto/Cargo.toml",
    requiredScriptNeedles: [
      "byteFieldNames",
      "byteBearingMessageNames",
      "messageNames",
      "sensitiveMessageNames",
      "redactedMessageNames",
      "sensitiveViewSerializationError",
      "unknownFieldDropOwnerNames",
      "wrappedUnknownFieldOwnerNames",
      "__ReallyMeZeroizingUnknownFields",
      "impl ::core::ops::Drop for",
      "deserialize_zeroizing_bytes",
      "Zeroize::zeroize",
      "debugDescription",
      "public java.lang.String toString()",
      '"--check-idempotent"',
      '"CryptoOperationRequest"',
    ],
    forbiddenScriptNeedles: ["return 0x524d"],
    requiredCargoNeedles: ['"buffa/json"'],
    // Every bytes/string field is deliberately classified. "Sensitive" here
    // means the generated owner must redact and wipe the value; it includes
    // public keys and protocol transcripts because they are often persistent
    // identity correlators even when they are not cryptographic secrets.
    scalarFieldClassifications: [
      { message: "CryptoHashRequest", field: "input", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHashResult", field: "digest", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadSealRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadSealRequest", field: "nonce", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadSealRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadSealRequest", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadSealResult", field: "ciphertext_with_tag", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadOpenRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadOpenRequest", field: "nonce", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadOpenRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadOpenRequest", field: "ciphertext_with_tag", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoAeadOpenResult", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacAuthenticateRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacAuthenticateRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacAuthenticateResult", field: "tag", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacVerifyRequest", field: "tag", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacVerifyRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoMacVerifyRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoArgon2idDeriveRequest", field: "secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoArgon2idDeriveRequest", field: "salt", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKdfDeriveKeyRequest", field: "password", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKdfDeriveKeyRequest", field: "salt", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKdfDeriveKeyResult", field: "derived_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHkdfDeriveRequest", field: "input_key_material", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHkdfDeriveRequest", field: "salt", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHkdfDeriveRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHkdfDeriveResult", field: "output_key_material", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoJwaConcatKdfSha256DeriveRequest", field: "shared_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoJwaConcatKdfSha256DeriveRequest", field: "algorithm_id", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoJwaConcatKdfSha256DeriveRequest", field: "party_u_info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoJwaConcatKdfSha256DeriveRequest", field: "party_v_info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoJwaConcatKdfSha256DeriveResult", field: "derived_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKmac256DeriveRequest", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKmac256DeriveRequest", field: "context", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKmac256DeriveRequest", field: "customization", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKmac256DeriveResult", field: "derived_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyWrapRequest", field: "wrapping_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyWrapRequest", field: "key_to_wrap", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyWrapResult", field: "wrapped_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyUnwrapRequest", field: "wrapping_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyUnwrapRequest", field: "wrapped_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyUnwrapResult", field: "key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureDeriveKeyPairRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureSignRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureSignRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureSignResult", field: "signature", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoBip340SchnorrSignRequest", field: "message32", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoBip340SchnorrSignRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoBip340SchnorrSignRequest", field: "aux_rand32", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureVerifyRequest", field: "signature", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureVerifyRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoSignatureVerifyRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoRsaVerifyRequest", field: "signature", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoRsaVerifyRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoRsaVerifyRequest", field: "public_key_der", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyAgreementDeriveSharedSecretRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyAgreementDeriveSharedSecretRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyAgreementDeriveSharedSecretResult", field: "shared_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyAgreementDeriveKeyPairRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemDeriveKeyPairRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemEncapsulateRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemDecapsulateRequest", field: "ciphertext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemDecapsulateRequest", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemDecapsulateResult", field: "shared_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealRequest", field: "recipient_public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealRequest", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenRequest", field: "recipient_secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenRequest", field: "encapsulated_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenRequest", field: "ciphertext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeOpenResult", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeDeriveKeyPairRequest", field: "input_key_material", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSenderExportRequest", field: "recipient_public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSenderExportRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSenderExportRequest", field: "exporter_context", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeReceiverExportRequest", field: "recipient_secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeReceiverExportRequest", field: "encapsulated_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeReceiverExportRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeReceiverExportRequest", field: "exporter_context", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSenderExportResult", field: "encapsulated_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSenderExportResult", field: "exporter_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeReceiverExportResult", field: "exporter_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "recipient_public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "plaintext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "psk", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskSealRequest", field: "psk_id", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "recipient_secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "encapsulated_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "info", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "aad", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "ciphertext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "psk", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkePskOpenRequest", field: "psk_id", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyPair", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKeyPair", field: "secret_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemEncapsulation", field: "ciphertext", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoKemEncapsulation", field: "shared_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealedMessage", field: "encapsulated_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoHpkeSealedMessage", field: "ciphertext", kind: "bytes", sensitivity: "sensitive" },
      { message: "AndroidPlatformKeyPolicy", field: "attestation_challenge", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformPrivateKeyHandle", field: "opaque_handle", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformPrivateKeyHandle", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyGenerateRequest", field: "application_tag", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyGetPublicKeyResult", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureSignRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureSignRequest", field: "authentication_prompt", kind: "string", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureSignResult", field: "signature", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureVerifyRequest", field: "signature", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureVerifyRequest", field: "message", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformSignatureVerifyRequest", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyAgreementDeriveSharedSecretRequest", field: "peer_public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyAgreementDeriveSharedSecretResult", field: "shared_secret", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyAttestRequest", field: "challenge", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoPlatformKeyAttestationCertificate", field: "certificate_der", kind: "bytes", sensitivity: "sensitive" },
      { message: "CryptoProviderCapability", field: "provider_names", kind: "string", sensitivity: "public" },
      { message: "JsonWebKey", field: "public_key", kind: "bytes", sensitivity: "sensitive" },
      { message: "JsonWebKey", field: "canonical_jcs", kind: "bytes", sensitivity: "sensitive" },
    ],
    requiredGeneratedNeedles: [
      '.field("secret_key", &"<redacted>")',
      '.field("opaque_handle", &"<redacted>")',
      "impl ::core::ops::Drop for CryptoAeadSealRequest",
      "impl ::core::ops::Drop for CryptoPlatformPrivateKeyHandle",
      "impl ::core::ops::Drop for CryptoPlatformKeyGenerateRequest",
      "impl ::core::ops::Drop for CryptoPlatformKeyAttestRequest",
      "impl ::core::ops::Drop for CryptoPlatformKeyAttestationCertificate",
      "pub struct __ReallyMeZeroizingUnknownFields",
      'formatter.write_str("__ReallyMeZeroizingUnknownFields(<redacted>)")',
      "impl ::core::ops::Drop for __ReallyMeZeroizingUnknownFields",
      "deserialize_zeroizing_bytes",
    ],
    forbiddenGeneratedNeedles: [
      "::buffa::alloc::format!(",
      '.field("secret_key", &self.secret_key)',
      '.field("payload", &self.payload)',
    ],
    requiredViewNeedles: [
      'formatter.write_str("CryptoKmac256DeriveRequestOwnedView(<redacted>)")',
      'formatter.write_str("CryptoOperationRequestOwnedView(<redacted>)")',
      'formatter.write_str("CryptoOperationResponseOwnedView(<redacted>)")',
      'formatter.write_str("CryptoOperationResultOwnedView(<redacted>)")',
    ],
    additionalGeneratedPolicies: [
      {
        path: "gen/swift/reallyme/crypto/v1/crypto.pb.swift",
        required: [
          "ReallyMeProtoCryptoOperationRequest(<redacted>)",
          "ReallyMeProtoCryptoOperationResponse(<redacted>)",
          "ReallyMeProtoCryptoOperationResult(<redacted>)",
        ],
      },
      {
        path: "gen/java/me/really/crypto/v1/CryptoOperationRequest.java",
        required: ["CryptoOperationRequest{<redacted>}"],
      },
      {
        path: "gen/java/me/really/crypto/v1/CryptoOperationResponse.java",
        required: ["CryptoOperationResponse{<redacted>}"],
      },
      {
        path: "gen/java/me/really/crypto/v1/CryptoOperationResult.java",
        required: ["CryptoOperationResult{<redacted>}"],
      },
    ],
  },
  generatedFreshness: {
    generatedPaths: [
      "crates/proto/src/generated",
      "packages/ts/src/proto/generated",
      "gen",
    ],
    commands: [
      ["buf", ["lint"]],
      ["buf", ["generate"]],
      ["node", ["scripts/redact_crypto_proto_debug.mjs"]],
      ["node", ["scripts/redact_crypto_proto_debug.mjs", "--check-idempotent"]],
      ["cargo", ["fmt", "--package", "reallyme-crypto-proto"]],
      ["cargo", ["run", "-p", "crypto-conformance-vectors", "--bin", "gen_vectors"]],
    ],
  },
};

for (const messageName of [
  "CryptoOperationRequest",
  "CryptoOperationResponse",
  "CryptoOperationResult",
]) {
  // These oneof owners contain no directly classified scalar field, so the
  // shared upstream policy cannot infer their unknown-field retention risk.
  // Keep the repository-specific assertion here while the vendored core stays
  // byte-for-byte identical to its independently reviewed upstream pin.
  assertZeroizingGeneratedUnknownFieldOwner(
    protobufReleasePolicy.hardeningPolicy.generatedRust,
    messageName,
  );
}

const primaryOperationBoundaryPolicy = {
  protoPath: "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  operationRequest: "CryptoOperationRequest",
  operationResponse: "CryptoOperationResponse",
  operationResult: "CryptoOperationResult",
  errorMessage: "CryptoError",
  protoReadme: "crates/proto/README.md",
  protoCargo: "crates/proto/Cargo.toml",
  wirePath: "crates/crypto/src/operation_contract/boundary.rs",
  codecPath: "crates/proto/src/operation_response_wire.rs",
  binaryResponseNeedle: "CryptoOperationResponse",
  requiredCodecNeedles: ["MAX_CRYPTO_OPERATION_RESPONSE_BYTES"],
  forbiddenCodecNeedles: ["serde_json::Value"],
  allowServices: false,
  sdkAdapters: [
    {
      path: "crates/wasm/src/operation_response.rs",
      processOperationNeedle: "pub fn process_operation_response(",
      processOperationJsonNeedle: "pub fn process_operation_response_json(",
      binaryResponseNeedle: "CryptoOperationResponse",
    },
    {
      path: "packages/ts/src/operationResponse.ts",
      processOperationNeedle: "export const processOperationResponse =",
      processOperationJsonNeedle: "export const processOperationResponseJson =",
      binaryResponseNeedle: "CryptoOperationResponse",
    },
    {
      path: "packages/swift/Sources/ReallyMeCrypto/OperationResponse.swift",
      processOperationNeedle: "public func processOperationResponse(",
      processOperationJsonNeedle: "public func processOperationResponseJson(",
      binaryResponseNeedle: "CryptoOperationResponse",
    },
    {
      path: "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
      processOperationNeedle: "public fun processOperationResponse(",
      processOperationJsonNeedle: "public fun processOperationResponseJson(",
      binaryResponseNeedle: "CryptoOperationResponse",
    },
  ],
};

const repositoryPolicy = {
  generatedFreshnessMode,
  vendoredCore: {
    contractVersion: 8,
    scriptPath: "scripts/check_release_readiness.mjs",
    corePath: "scripts/release-readiness/core.mjs",
  },
  workflowActions: {},
  nodeWorkflows: {
    nodeVersion: "24",
  },
  cargoFuzz: {
    workflow: ".github/workflows/fuzz.yml",
    version: "0.13.2",
    minimumInstallations: 2,
    requiredInstallSteps: [
      { job: "build", name: "Install cargo-fuzz" },
      { job: "scheduled", name: "Install cargo-fuzz" },
    ],
  },
  cargoWorkspace: {
    requireWorkspaceLints: true,
    requirePublishInclude: true,
    validatePublishablePathDependencies: true,
  },
  spdx: {
    excludedPrefixes: [
      "crates/proto/src/generated",
      "packages/ts/src/proto/generated",
      "gen",
      "target",
      "vectors/external",
    ],
  },
  protobufBoundary: primaryOperationBoundaryPolicy,
  protobufRelease: protobufReleasePolicy,
  cargoMetadata: {
    packages: [
      {
        name: "reallyme-crypto",
        version: rustRootVersion,
        publish: "public",
        dependencies: [
          {
            name: "reallyme-crypto-core",
            requirement: `=${rustRootVersion}`,
            source: "path",
          },
          {
            name: "reallyme-crypto-dispatch",
            requirement: `=${rustRootVersion}`,
            source: "path",
            optional: true,
            defaultFeatures: false,
          },
          {
            name: "reallyme-crypto-proto",
            requirement: `=${cryptoProtoPackageVersion}`,
            source: "path",
            optional: true,
            defaultFeatures: false,
            features: ["generated"],
          },
          {
            name: "reallyme-crypto-signer",
            requirement: `=${rustRootVersion}`,
            source: "path",
            optional: true,
            defaultFeatures: false,
          },
        ],
      },
      {
        name: "reallyme-crypto-proto",
        version: cryptoProtoPackageVersion,
        publish: "public",
      },
      {
        name: "reallyme-crypto-dispatch",
        version: rustRootVersion,
        publish: "public",
        dependencies: [
          {
            name: "reallyme-codec-multikey",
            requirement: `^${codecVersion}`,
            source: "registry",
          },
        ],
      },
      {
        name: "reallyme-crypto-p256",
        version: rustRootVersion,
        publish: "public",
        dependencies: [
          {
            name: "reallyme-codec-pem",
            requirement: `^${codecVersion}`,
            source: "registry",
            optional: true,
          },
        ],
      },
      {
        name: "reallyme-crypto-jwk",
        version: rustRootVersion,
        publish: "public",
        dependencies: [
          {
            name: "reallyme-codec-base64url",
            requirement: `^${codecVersion}`,
            source: "registry",
          },
          {
            name: "reallyme-codec-jcs",
            requirement: `^${codecVersion}`,
            source: "registry",
          },
        ],
      },
      {
        name: "reallyme-crypto-jwk-multikey",
        version: rustRootVersion,
        publish: "public",
        dependencies: [
          {
            name: "reallyme-codec-multikey",
            requirement: `^${codecVersion}`,
            source: "registry",
          },
          {
            name: "reallyme-codec-base64url",
            requirement: `^${codecVersion}`,
            source: "registry",
          },
        ],
      },
      {
        name: "crypto-ffi",
        version: rustRootVersion,
        publish: "private",
      },
      {
        name: "reallyme-crypto-wasm",
        version: rustRootVersion,
        publish: "private",
      },
    ],
  },
  text: {
    files: [
      {
        path: "Cargo.toml",
        required: ["overflow-checks = true"],
        forbidden: ["[patch.crates-io]"],
      },
      {
        path: "scripts/run_pinned_release_readiness.mjs",
        required: [
          `const RELEASE_READINESS_COMMIT = "${releaseReadinessCommit}";`,
          'const RELEASE_READINESS_CORE_SHA256 =\n  "70cc78721738cf352024938e8fc86e73380e71b2cdf7a9a733687543167cbaae";',
        ],
        forbidden: [
          "RELEASE_READINESS_COMMIT = \"main\"",
          "RELEASE_READINESS_COMMIT = \"master\"",
        ],
      },
    ],
  },
  workflows: [
    {
      path: ".github/workflows/rust-ci.yml",
      required: releaseReadinessCheckoutRequired,
      usesSteps: [
        {
          name: "Checkout release-readiness runner",
          uses: checkoutAction,
        },
      ],
      runSteps: [{ name: "Release readiness", run: releaseReadinessCommand }],
    },
    {
      path: ".github/workflows/protobuf-ci.yml",
      required: releaseReadinessCheckoutRequired,
      usesSteps: [
        {
          name: "Checkout release-readiness runner",
          uses: checkoutAction,
        },
      ],
      runSteps: [
        {
          name: "Check release readiness generated freshness",
          run: `${releaseReadinessCommand} --generated-freshness`,
        },
      ],
    },
  ],
};

const primaryOperationBoundaryReady = () => {
  const proto = readText(primaryOperationBoundaryPolicy.protoPath);
  return (
    proto.includes("message CryptoOperationResponse") &&
    proto.includes("message CryptoOperationResult")
  );
};

const assertReleaseWorkflowCredentialGates = () => {
  const releaseWorkflows = [
    ".github/workflows/crates-release.yml",
    ".github/workflows/npm-package-release.yml",
    ".github/workflows/swift-package-release.yml",
    ".github/workflows/kotlin-android-package-release.yml",
  ];
  for (const path of releaseWorkflows) {
    assertContains(path, "Verify reviewed release SHA");
    assertContains(path, '[ "${GITHUB_SHA}" != "${release_sha}" ]');
    assertContains(path, "resolved release SHA does not match the workflow run head SHA");
    assertContains(path, "node scripts/verify_release_attestation.mjs");
    assertContains(path, "actions: read");
    assertContains(path, "GH_TOKEN: ${{ github.token }}");
    assertNotContains(path, "if: inputs.publish");
  }

  for (const path of [
    ".github/workflows/crates-package-preflight.yml",
    ".github/workflows/npm-package-preflight.yml",
    ".github/workflows/swift-package-preflight.yml",
    ".github/workflows/kotlin-android-package-preflight.yml",
  ]) {
    assertContains(path, "release_sha:");
    assertContains(path, "resolved release SHA is not the current origin/main tip");
    assertContains(path, '[ "${GITHUB_SHA}" != "${release_sha}" ]');
    assertContains(path, "resolved release SHA does not match the workflow run head SHA");
    assertContains(path, "ref: ${{ needs.verify-source-sha.outputs.release_sha }}");
  }

  assertContains("scripts/verify_release_attestation.mjs", 'const CODE_CHECK_WORKFLOW = "rust-ci.yml"');
  assertContains("scripts/verify_release_attestation.mjs", '"crates-package-preflight.yml"');
  assertContains("scripts/verify_release_attestation.mjs", '"swift-package-preflight.yml"');
  assertContains("scripts/verify_release_attestation.mjs", '"kotlin-android-package-preflight.yml"');
  assertContains("scripts/verify_release_attestation.mjs", '"npm-package-preflight.yml"');
  assertContains("scripts/verify_release_attestation.mjs", 'latest.status !== "completed"');
  assertContains("scripts/verify_release_attestation.mjs", 'latest.conclusion !== "success"');
  assertContains(
    ".github/workflows/crates-package-preflight.yml",
    `ref: ${rustSemverBaselineCommit}`,
  );
  assertContains(
    "scripts/prepare_semver_baseline.mjs",
    `RUST_SEMVER_BASELINE_COMMIT = "${rustSemverBaselineCommit}"`,
  );

  assertContains(".github/workflows/crates-release.yml", "environment: crates-io-release");
  assertContains(".github/workflows/crates-release.yml", "CARGO_REGISTRY_TOKEN is required");
  assertContains(".github/workflows/crates-release.yml", "CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}");

  assertContains(".github/workflows/npm-package-release.yml", "environment: npm-release");
  assertContains(".github/workflows/npm-package-release.yml", "NPM_TOKEN is required");
  assertContains(".github/workflows/npm-package-release.yml", "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}");
  assertContains(".github/workflows/npm-package-release.yml", "--provenance --access public");
  assertContains(".github/workflows/npm-package-release.yml", "sha256sum --check");
  assertContains(
    ".github/workflows/npm-package-release.yml",
    "EXPECTED_TARBALL_SHA256: ${{ needs.package.outputs.tarball_sha256 }}",
  );
  assertContains(
    ".github/workflows/npm-package-release.yml",
    'actual_tarball_sha256="$(sha256sum',
  );
  assertContains(".github/workflows/npm-package-release.yml", "actions/upload-artifact@");
  assertContains(".github/workflows/npm-package-release.yml", "actions/download-artifact@");

  assertContains(".github/workflows/kotlin-android-package-release.yml", "environment: maven-release");
  assertContains(".github/workflows/kotlin-android-package-release.yml", "remote Maven publishing credentials are incomplete");
  assertContains(".github/workflows/kotlin-android-package-release.yml", "-Preallyme.maven.requireRemote=true");
  assertNotContains(".github/workflows/kotlin-android-package-release.yml", "remote publish is skipped");

  assertContains(".github/workflows/swift-package-release.yml", "environment: github-release");
  assertContains(".github/workflows/swift-package-release.yml", "verify_swift_release_artifact.mjs");
  assertContains(".github/workflows/swift-package-release.yml", "Download verified Swift artifact");
  assertContains(".github/workflows/swift-package-release.yml", "GitHub release v${RELEASE_VERSION} already exists");
  assertContains(".github/workflows/swift-package-release.yml", "Git tag v${RELEASE_VERSION} already exists");
  assertNotContains(".github/workflows/swift-package-release.yml", "--clobber");
  assertNotContains(".github/workflows/swift-package-release.yml", "gh release edit");
};

const assertReleaseWorkflowPermissions = () => {
  const readOnlyWorkflow = { contents: "read" };
  for (const path of [
    ".github/workflows/rust-ci.yml",
    ".github/workflows/fuzz.yml",
    ".github/workflows/protobuf-ci.yml",
    ".github/workflows/jvm-native-resources.yml",
    ".github/workflows/crates-package-preflight.yml",
    ".github/workflows/npm-package-preflight.yml",
    ".github/workflows/swift-package-preflight.yml",
    ".github/workflows/kotlin-android-package-preflight.yml",
  ]) {
    assertWorkflowPermissionsPolicy({ path, workflow: readOnlyWorkflow, jobs: {} });
  }
  assertWorkflowPermissionsPolicy({
    path: ".github/workflows/crates-release.yml",
    workflow: readOnlyWorkflow,
    jobs: {
      "verify-release-sha": { actions: "read", contents: "read" },
      publish: { actions: "read", contents: "read" },
    },
  });
  assertWorkflowPermissionsPolicy({
    path: ".github/workflows/npm-package-release.yml",
    workflow: readOnlyWorkflow,
    jobs: {
      "verify-release-sha": { actions: "read", contents: "read" },
      publish: { actions: "read", contents: "read", "id-token": "write" },
    },
  });
  assertWorkflowPermissionsPolicy({
    path: ".github/workflows/swift-package-release.yml",
    workflow: readOnlyWorkflow,
    jobs: {
      "verify-release-sha": { actions: "read", contents: "read" },
      "swift-release": { actions: "read", contents: "write" },
    },
  });
  assertWorkflowPermissionsPolicy({
    path: ".github/workflows/kotlin-android-package-release.yml",
    workflow: readOnlyWorkflow,
    jobs: {
      "verify-release-sha": { actions: "read", contents: "read" },
      "maven-package": { actions: "read", contents: "read" },
      "android-aar": { actions: "read", contents: "read" },
    },
  });
};

const assertNoTemplateMarkers = (value, path = "repositoryPolicy") => {
  if (typeof value === "string") {
    if (value.includes("REPLACE_")) {
      fail(`${path} still contains an unresolved template marker`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const [index, entry] of value.entries()) {
      assertNoTemplateMarkers(entry, `${path}[${index}]`);
    }
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [name, entry] of Object.entries(value)) {
      assertNoTemplateMarkers(entry, `${path}.${name}`);
    }
  }
};

const assertRepositoryPolicy = () => {
  assertNoTemplateMarkers(repositoryPolicy);
  if (primaryOperationBoundaryReady()) {
    assertReallyMeRustProtoRepositoryPolicy(repositoryPolicy);
  } else {
    assertNotContains(primaryOperationBoundaryPolicy.protoPath, "message CryptoOperationResponse");
    assertNotContains(primaryOperationBoundaryPolicy.protoPath, "message CryptoOperationResult");
    assertReallyMeVendoredCorePolicy(repositoryPolicy.vendoredCore);
    assertWorkflowActionsPinned(repositoryPolicy.workflowActions);
    assertNodeWorkflowJobsPinNode(repositoryPolicy.nodeWorkflows);
    assertCargoFuzzWorkflowPolicy(repositoryPolicy.cargoFuzz);
    assertCargoWorkspacePolicy(repositoryPolicy.cargoWorkspace);
    assertCargoMetadataPolicy(repositoryPolicy.cargoMetadata);
    assertTextPolicy(repositoryPolicy.text);
    assertSpdxHeaders(repositoryPolicy.spdx);
    assertReallyMeProtobufReleasePolicy({
      ...repositoryPolicy.protobufRelease,
      generatedFreshnessMode: repositoryPolicy.generatedFreshnessMode,
    });
    for (const workflow of repositoryPolicy.workflows) {
      assertWorkflowPolicy(workflow);
    }
  }
  assertReleaseWorkflowCredentialGates();
  assertReleaseWorkflowPermissions();
};

assertCryptoOperationRouteReadiness({
  readJson,
  readText,
  fail,
  releasePackagesMode,
});
assertRepositoryPolicy();

assertContains("crates/proto/Cargo.toml", '"/proto/**/*.proto"');
assertContains("buf.gen.yaml", "json=true");
assertContains("crates/proto/Cargo.toml", '"buffa/json"');
assertNotContains("Cargo.toml", 'buffa = { version = "0.8.1", features = ["json"] }');
assertNotContains("crates/crypto/Cargo.toml", 'buffa = { version = "0.8.1", features = ["json"] }');
assertNotContains(
  "crates/crypto/src/operation_contract/response.rs",
  "CryptoProtoResult::from_message",
);
assertNotContains(
  "crates/crypto/src/operation_contract/request.rs",
  "decode_protobuf(",
);
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "Potentially privacy-bearing protocol context",
);
assertContains(
  "packages/ts/src/aesKw.ts",
  "value.length !== expectedLength",
);
assertContains("packages/ts/src/kmac.ts", "value.fill(0);");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/WrapAesKwWithRustCAbi.swift",
  "guard producedLength == output.count else",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  "impl ::core::ops::Drop for CryptoAeadSealRequest",
);
assertContains(
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  "deserialize_zeroizing_bytes",
);
assertContains(
  "crates/proto/tests/wire_tests.rs",
  "public_wire_error_constructor_rejects_invalid_branch_reason_pairs",
);
assertContains(
  "crates/proto/tests/generated_tests.rs",
  "operation_response_codec_rejects_absent_semantic_oneofs",
);
assertContains(
  "crates/proto/tests/operation_contract_schema_tests.rs",
  "opaque_result_envelope_is_absent_from_the_v03_schema",
);
assertContains("packages/ts/src/proto.ts", "cryptoWireErrorTryNew");
assertContains("packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "tryNew");
assertContains("packages/kotlin/src/main/kotlin/me/really/crypto/proto/ProtoAdapters.kt", "tryNew");
assertContains("scripts/stage_kotlin_native_resource.mjs", '["me", "really", "crypto", "native"]');
assertContains("scripts/write_native_manifest.mjs", "reallyme-crypto-native");
assertContains("scripts/verify_native_artifact_handoff.mjs", "NATIVE_SHA256_LINUX_X86_64");
assertContains("scripts/verify_native_artifact_handoff.mjs", "exact expected file set");
assertContains("scripts/verify_native_artifact_handoff.test.mjs", "rejects a substituted native library");
assertContains(
  "scripts/verify_native_artifact_handoff.test.mjs",
  "rejects a non-native class file anywhere in the artifact tree",
);
assertContains(
  ".github/workflows/external-vectors-audit.yml",
  "node scripts/vendor_external_vectors.mjs --check",
);
assertContains(
  "scripts/vendor_external_vectors.mjs",
  "committed supplementary corpora match pinned upstream bytes",
);
assertContains(
  ".github/workflows/kotlin-android-package-release.yml",
  "write_native_manifest.mjs build/kotlin-native-resources/me/really/crypto/native build/kotlin-native-resources/me/really/crypto/native/native-manifest.json",
);
assertContains(
  ".github/workflows/kotlin-android-package-preflight.yml",
  "write_native_manifest.mjs build/kotlin-native-resources/me/really/crypto/native build/kotlin-native-resources/me/really/crypto/native/native-manifest.json",
);
assertContains("Cargo.toml", "[profile.release-ffi]");
assertContains("Cargo.toml", 'panic = "unwind"');
assertNotContains("crates/ffi/Cargo.toml", "require-unwind");
assertContains("crates/ffi/src/lib.rs", '#[cfg(not(panic = "unwind"))]');
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "A probe executes the complete operation",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "Callers must discard every output",
);
assertContains(
  "crates/ffi/abi/reallyme_crypto_ffi.h",
  "RM_CRYPTO_P256_SIGNATURE_DER_MAX_LEN        72",
);
assertContains("crates/p256/abi/p256_abi.h", "P256_SIGNATURE_DER_MAX_LEN       72");
assertContains(
  "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdsa.swift",
  "signatureDerMaxLength = 72",
);
assertContains("scripts/build_kotlin_native_resource.sh", "--profile release-ffi");
assertNotContains("scripts/build_kotlin_native_resource.sh", "-C panic=unwind");
assertContains("scripts/build_kotlin_native_resource.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_android_native_resources.sh", "cargo build --locked -p crypto-ffi");
assertContains("scripts/build_android_native_resources.sh", "libcrypto_ffi.so");
assertContains("scripts/build_android_native_resources.sh", "--profile release-ffi");
assertNotContains("scripts/build_android_native_resources.sh", "-C panic=unwind");
assertContains("scripts/build_android_native_resources.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_android_native_resources.sh", "--strip-debug");
assertContains("scripts/build_swift_xcframework.sh", "cargo build --locked -p crypto-ffi");
assertContains("scripts/build_swift_xcframework.sh", "ReallyMeCryptoFFI.xcframework.zip");
assertContains("scripts/build_swift_xcframework.sh", "--profile release-ffi");
assertNotContains("scripts/build_swift_xcframework.sh", "-C panic=unwind");
assertContains("scripts/build_swift_xcframework.sh", "unset CARGO_ENCODED_RUSTFLAGS");
assertContains("scripts/build_swift_xcframework.sh", "Modules/module.modulemap");
assertNotContains("scripts/build_swift_xcframework.sh", "HEADERS_DIR}/module.modulemap");
assertContains("scripts/build_swift_xcframework.sh", "verify_xcframework_layout");
assertContains("scripts/build_swift_xcframework.sh", "normalize_xcframework_info_plist");
assertContains("scripts/build_swift_xcframework.sh", "Headers/module.modulemap");
assertContains("scripts/prepare_swift_release_candidate.sh", "build_swift_xcframework.sh");
assertContains("scripts/prepare_swift_release_candidate.sh", "prepare_swift_binary_manifest.mjs");
assertContains("scripts/prepare_swift_release_candidate.sh", "verify_swift_release_artifact.mjs");
assertContains("RELEASE_CHECKLIST.md", "prepare_swift_release_candidate.sh <version>");
assertContains("docs/release-process.md", "prepare_swift_release_candidate.sh 0.3.2");
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/OperationResponse.kt",
  "processOperationResponseNative(request: ByteArray): ByteArray?",
);
assertContains(
  "packages/kotlin/src/main/kotlin/me/really/crypto/OperationResponse.kt",
  "requireNativeOperationResponse(response: ByteArray?)",
);
assertContains(
  "packages/kotlin-android/consumer-rules.pro",
  "ReallyMeCryptoException$ProviderFailure",
);
assertContains("scripts/prepare_swift_binary_manifest.mjs", "ffiArtifactChecksum");
assertContains("scripts/prepare_swift_binary_manifest.mjs", "--local-artifact-path");
assertContains("scripts/verify_swift_release_artifact.mjs", '"compute-checksum"');
assertContains("scripts/verify_swift_release_artifact.mjs", "Package.swift checksum does not match");
assertContains("scripts/verify_swift_release_artifact.test.mjs", "rejects a forged sidecar");
assertContains(".github/workflows/rust-ci.yml", "tool: nextest@0.9.140");
assertContains(".github/workflows/rust-ci.yml", "cargo install cargo-deny --version 0.20.2 --locked");
assertContains(".github/workflows/rust-ci.yml", "tool: cargo-audit@0.22.2");
assertContains(".github/workflows/rust-ci.yml", "cargo metadata --locked --format-version 1 --no-deps");
assertContains(
  ".github/workflows/rust-ci.yml",
  "RUSTFLAGS=-Dwarnings cargo check --locked --workspace --all-features",
);
assertContains("packages/ts/scripts/build-wasm.mjs", '"--locked"');
assertContains(".github/workflows/jvm-native-resources.yml", "jvm native resources");
assertContains(".github/workflows/jvm-native-resources.yml", "kotlin-native-");
assertContains(".github/workflows/jvm-native-resources.yml", "build_kotlin_native_resource.sh");
assertContains(
  ".github/workflows/jvm-native-resources.yml",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
);

const kotlinPreflightWorkflow = ".github/workflows/kotlin-android-package-preflight.yml";
assertContains(kotlinPreflightWorkflow, "jvm native preflight");
assertContains(kotlinPreflightWorkflow, "android aar preflight");
assertContains(kotlinPreflightWorkflow, "android instrumented preflight");
assertContains(kotlinPreflightWorkflow, "connectedDebugAndroidTest");
assertContains(kotlinPreflightWorkflow, 'ADB="${ANDROID_HOME}/platform-tools/adb"');
assertContains(kotlinPreflightWorkflow, "ANDROID_AVD_HOME");
assertContains(kotlinPreflightWorkflow, 'emulator" -list-avds');
assertContains(kotlinPreflightWorkflow, 'kill -0 "${EMULATOR_PID}"');
assertNotContains(kotlinPreflightWorkflow, '"${ADB}" wait-for-device');
assertContains(kotlinPreflightWorkflow, "build_kotlin_native_resource.sh");
assertContains(kotlinPreflightWorkflow, "linux_x86_64_sha256:");
assertContains(
  kotlinPreflightWorkflow,
  "verify_native_artifact_handoff.mjs verify build/kotlin-native-resources",
);
assertContains(
  kotlinPreflightWorkflow,
  "NATIVE_SHA256_WINDOWS_X86_64: ${{ needs.jvm-native.outputs.windows_x86_64_sha256 }}",
);
assertContains(kotlinPreflightWorkflow, "verifyReleaseAarContainsJniLibs");
assertContains(kotlinPreflightWorkflow, "verifyAndroidJniLibs");
assertContains(kotlinPreflightWorkflow, "publishToMavenLocal");
assertContains(kotlinPreflightWorkflow, "packages/kotlin-android/gradlew");
assertContains(kotlinPreflightWorkflow, gradleWrapperValidationAction);
assertContains(kotlinPreflightWorkflow, "--dependency-verification strict");
assertNotContains(kotlinPreflightWorkflow, "--no-dependency-verification");
assertNotContains(kotlinPreflightWorkflow, "--dependency-verification off");

const kotlinReleaseWorkflow = ".github/workflows/kotlin-android-package-release.yml";
assertContains(kotlinReleaseWorkflow, "Maven package with bundled JNI");
assertContains(kotlinReleaseWorkflow, "Android AAR with bundled JNI");
assertContains(kotlinReleaseWorkflow, "verifyAndroidJniLibs");
assertContains(kotlinReleaseWorkflow, gradleWrapperValidationAction);
assertContains(kotlinReleaseWorkflow, "--dependency-verification strict");
assertContains(kotlinReleaseWorkflow, "verify_release_attestation.mjs");
assertContains(kotlinReleaseWorkflow, "linux_x86_64_sha256:");
assertContains(
  kotlinReleaseWorkflow,
  "verify_native_artifact_handoff.mjs verify build/kotlin-native-resources",
);
assertContains(
  kotlinReleaseWorkflow,
  "NATIVE_SHA256_WINDOWS_X86_64: ${{ needs.jvm-native.outputs.windows_x86_64_sha256 }}",
);
assertNotContains(kotlinReleaseWorkflow, "--no-dependency-verification");
assertNotContains(kotlinReleaseWorkflow, "--dependency-verification off");

const swiftPreflightWorkflow = ".github/workflows/swift-package-preflight.yml";
assertContains(swiftPreflightWorkflow, "REALLYME_CRYPTO_FFI_LIBRARY_PATH");
assertContains(swiftPreflightWorkflow, "REALLYME_CRYPTO_SWIFTPM_RUNTIME_FFI");
assertContains(swiftPreflightWorkflow, "Build SwiftPM binary artifact");
assertContains(swiftPreflightWorkflow, "Prepare local SwiftPM binary manifest");
assertContains(swiftPreflightWorkflow, "--local-artifact-path build/swift/ReallyMeCryptoFFI.xcframework");
assertContains(swiftPreflightWorkflow, "Test Swift package with linked binary target");
assertContains(swiftPreflightWorkflow, "node scripts/run_pinned_release_readiness.mjs --release-packages");

const swiftReleaseWorkflow = ".github/workflows/swift-package-release.yml";
assertContains(swiftReleaseWorkflow, "ReallyMeCryptoFFI.xcframework.zip");
assertContains(swiftReleaseWorkflow, "Upload Swift artifact");
assertContains(swiftReleaseWorkflow, "Download Swift artifact");
assertContains(swiftReleaseWorkflow, "Verify SwiftPM manifest and downloaded artifact");
assertContains(swiftReleaseWorkflow, "Create immutable GitHub release with Swift artifact");
assertContains(swiftReleaseWorkflow, "verify_swift_release_artifact.mjs");
assertContains(swiftReleaseWorkflow, "verify_release_attestation.mjs");
assertContains(swiftReleaseWorkflow, "gh release create");
const swiftReleaseArtifactVerificationCount = readText(swiftReleaseWorkflow).match(
  /node scripts\/verify_swift_release_artifact[.]mjs/gu,
)?.length;
if (swiftReleaseArtifactVerificationCount !== 2) {
  fail("Swift release workflow must verify the downloaded archive in both verification jobs");
}

assertContains(".github/workflows/npm-package-preflight.yml", "npm package preflight");
assertContains(".github/workflows/npm-package-preflight.yml", "npm run pack:check");
assertContains(".github/workflows/npm-package-release.yml", "npm Package Release");
assertContains(".github/workflows/npm-package-release.yml", "default: 0.3.2");
assertContains(".github/workflows/npm-package-release.yml", "node scripts/run_pinned_release_readiness.mjs --release-packages");
assertContains(".github/workflows/npm-package-release.yml", "wasm-pack@0.15.0");
assertContains(".github/workflows/npm-package-release.yml", "wasm-bindgen-cli@0.2.126");
assertContains(".github/workflows/npm-package-release.yml", "npm test");
assertContains(".github/workflows/npm-package-release.yml", "npm run pack:check");
assertContains(".github/workflows/npm-package-release.yml", "npm pack --ignore-scripts");
assertContains(".github/workflows/npm-package-release.yml", "reallyme-crypto-${RELEASE_VERSION}.tgz");

assertContains(".github/workflows/crates-package-preflight.yml", "cargo semver-checks --workspace");
assertContains(".github/workflows/crates-package-preflight.yml", "node scripts/publish_crates_in_order.mjs inspect");
assertContains(".github/workflows/crates-release.yml", "verify_release_attestation.mjs");
assertContains(".github/workflows/crates-release.yml", "node scripts/publish_crates_in_order.mjs order");
assertContains(
  ".github/workflows/crates-release.yml",
  "RELEASE_VERSION: ${{ needs.verify-release-sha.outputs.release_version }}",
);
assertNotContains("scripts/publish_crates_in_order.mjs", "REALLYME_CRATES_ALLOW_ALREADY_PUBLISHED");
assertContains("scripts/publish_crates_in_order.mjs", "RELEASE_VERSION must be set when publishing crates");
assertContains("scripts/publish_crates_in_order.mjs", "publishWithRetries");
assertContains("scripts/publish_crates_in_order.mjs", "continuing release resume");
assertContains("scripts/publish_retry_policy.mjs", "RateLimitExhausted");
assertContains("scripts/publish_retry_policy.mjs", "IndexLagExhausted");
assertContains("scripts/publish_retry_policy.test.mjs", "permanent rate limiting fails terminally");
assertContains(
  "scripts/publish_retry_policy.test.mjs",
  "already-published output is never accepted without artifact identity proof",
);
if (releasePackagesMode) {
  const swiftPackage = readText("Package.swift");
  const swiftFfiArtifactVersion = requireMatch(
    "Package.swift",
    /let ffiArtifactVersion = "([^"]+)"/,
    "ffiArtifactVersion",
  )[1];
  const expectedReleaseVersions = [
    ["crates/crypto/Cargo.toml", rustRootVersion],
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
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "package reallyme.crypto.v1;");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", 'option swift_prefix = "ReallyMeProto";');
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing AEAD key");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing derived key material");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "Secret-bearing KEM shared secret");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "Decrypted plaintext may contain secret");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoError");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoPrimitiveError");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoProviderError");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoBackendError");
assertNotContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message CryptoProtoResultEnvelope");
assertNotContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "enum CryptoProtoResultStatus");
assertNotContains("docs/proto-json.md", "CRYPTO_PROTO_RESULT_STATUS");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "enum CryptoErrorReason");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "enum HpkeKemId");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "enum HpkeKdfId");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "enum HpkeAeadId");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "message HpkeSuiteIdentifier");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", "reserved 4;");
assertContains("crates/proto/proto/reallyme/crypto/v1/crypto.proto", 'reserved "hpke";');
assertContains("gen/es/reallyme/crypto/v1/crypto_pb.ts", "export enum HpkeKemId");
assertContains("gen/swift/reallyme/crypto/v1/crypto.pb.swift", "enum ReallyMeProtoHpkeKemId");
assertContains("gen/java/me/really/crypto/v1/HpkeKemId.java", "public enum HpkeKemId");
assertContains("gen/kotlin/me/really/crypto/v1/HpkeSuiteIdentifierKt.kt", "HpkeSuiteIdentifierKt");
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER = 100;",
);
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM = 200;",
);
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_BACKEND_INVALID_STATE = 300;",
);
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PRIMITIVE_MALFORMED_PROTOBUF = 130;",
);
assertContains(
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
  "CRYPTO_ERROR_REASON_PRIMITIVE_RESOURCE_LIMIT_EXCEEDED = 132;",
);

const orderedCounts = [...statusCounts.entries()].sort(([left], [right]) =>
  left.localeCompare(right),
);
for (const [key, count] of orderedCounts) {
  console.log(`${key} ${count}`);
}
