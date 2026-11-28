// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { closeSync, constants, copyFileSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MavenPublicationError, publicationLayout, stageMavenPublication, stageMavenPublications } from "./stage_maven_publications.mjs";
import { hashBoundedFile, readBoundedFile } from "./read_bounded_file.mjs";

const BUILD_TIMEOUT_MS = 1_800_000;
const REQUEST_TIMEOUT_MS = 120_000;
const MAX_NATIVE_BYTES = 536_870_912;
const MAX_MANIFEST_BYTES = 65_536;
const NATIVE_ROOT = "me/really/crypto/native";
const LOCAL_PUBLICATION_TOOLS = Object.freeze([
  "scripts/maven-central-bundle.local.sh", "scripts/maven_central_bundle.test.mjs",
  "scripts/build_maven_publications.mjs", "scripts/build_maven_publications.test.mjs",
  "scripts/read_bounded_file.mjs", "scripts/read_bounded_file.test.mjs",
  "scripts/check_release_privacy.py", "scripts/release_privacy_test.py",
]);
const JVM_LIBRARIES = Object.freeze([
  ["linux-x86_64", "libcrypto_ffi.so"],
  ["linux-aarch64", "libcrypto_ffi.so"],
  ["macos-x86_64", "libcrypto_ffi.dylib"],
  ["macos-aarch64", "libcrypto_ffi.dylib"],
  ["windows-x86_64", "crypto_ffi.dll"],
]);

function fail(message) {
  throw new MavenPublicationError(message);
}

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { fail("invalid native resource metadata"); }
}

function runner(root, environment) {
  return (command, args, message, options = {}) => {
    const result = spawnSync(command, args, {
      cwd: root, env: environment, encoding: "utf8", maxBuffer: 16_777_216,
      timeout: REQUEST_TIMEOUT_MS, ...options,
    });
    if (result.error?.code === "ETIMEDOUT") fail("local Maven publication command timed out");
    if (result.error !== undefined || result.status !== 0) fail(message);
    return result.stdout ?? "";
  };
}

export function verifyLocalMavenSource(root, sourceSha, run = runner(root, process.env)) {
  publicationLayout("0.0.0", sourceSha);
  if (run("git", ["rev-parse", "HEAD"], "could not read the local release source").trim() !== sourceSha) {
    fail("the checkout changed during the local Maven build");
  }
  // Local publisher repairs may await review after another SDK has shipped.
  // Every compiled source, schema, dependency pin and package/build setting
  // must still match that release commit; only these publisher tools may vary.
  run("git", ["diff", "--quiet", "--no-ext-diff", sourceSha, "--", ".",
    ...LOCAL_PUBLICATION_TOOLS.map((path) => `:(exclude)${path}`)], "tracked release inputs changed during the local Maven build");
  if (run("git", ["ls-files", "--others", "--exclude-standard", "-z"], "could not check untracked release inputs").length !== 0) {
    fail("untracked files must be removed from the release source before building");
  }
}

async function digest(path) {
  return hashBoundedFile(path, MAX_NATIVE_BYTES);
}

function directory(path) {
  const status = lstatSync(path);
  if (!status.isDirectory() || status.isSymbolicLink()) fail("native inputs must use regular directories");
}

async function verifyNativeResources(resources, sourceSha) {
  if (!isAbsolute(resources)) fail("KOTLIN_NATIVE_RESOURCES_DIR must be absolute");
  directory(resources);
  let native = resources;
  for (const component of NATIVE_ROOT.split("/")) {
    native = join(native, component);
    directory(native);
  }
  const manifestPath = join(native, "native-manifest.json");
  const manifest = parseJson(readBoundedFile(manifestPath, MAX_MANIFEST_BYTES).toString("utf8"));
  if (!record(manifest) || manifest.schemaVersion !== 1 || manifest.package !== "reallyme-crypto-native" ||
      manifest.commitSha !== sourceSha || !Array.isArray(manifest.entries) || manifest.entries.length !== JVM_LIBRARIES.length) {
    fail("native resources must include a checksum manifest for the selected source SHA");
  }
  const rootNames = readdirSync(native).sort();
  const expectedNames = [...JVM_LIBRARIES.map(([platform]) => platform), "native-manifest.json"].sort();
  if (JSON.stringify(rootNames) !== JSON.stringify(expectedNames)) fail("native resources contain unexpected files");
  for (const [platform, filename] of JVM_LIBRARIES) {
    const platformPath = join(native, platform);
    directory(platformPath);
    if (JSON.stringify(readdirSync(platformPath)) !== JSON.stringify([filename])) fail("native resource platform contains unexpected files");
    const entries = manifest.entries.filter((entry) => record(entry) && entry.path === `${platform}/${filename}`);
    const actual = await digest(join(platformPath, filename));
    if (entries.length !== 1 || entries[0].sha256 !== actual.sha256 || entries[0].size !== actual.size) {
      fail("native resource bytes do not match their checksum manifest");
    }
  }
}

export async function verifyLocalNativeResources(resources, sourceSha) {
  try {
    await verifyNativeResources(resources, sourceSha);
  } catch (error) {
    if (error instanceof MavenPublicationError) throw error;
    fail("native resource inputs are missing or unreadable");
  }
}

async function acquireNativeResources(root, sourceSha, scratch, environment, run) {
  const configured = environment.KOTLIN_NATIVE_RESOURCES_DIR;
  if (configured !== undefined && configured.length > 0) {
    await verifyLocalNativeResources(configured, sourceSha);
    const snapshot = join(scratch, "native-resources");
    const files = [...JVM_LIBRARIES.map(([platform, filename]) => `${platform}/${filename}`), "native-manifest.json"];
    for (const path of files) {
      const destination = join(snapshot, NATIVE_ROOT, path);
      mkdirSync(join(destination, ".."), { recursive: true });
      copyFileSync(join(configured, NATIVE_ROOT, path), destination, constants.COPYFILE_EXCL);
    }
    // Gradle reads an owned snapshot, so a concurrent local build cannot
    // replace the caller's inputs between verification and packaging.
    await verifyLocalNativeResources(snapshot, sourceSha);
    return snapshot;
  }
  const repository = "reallyme/crypto";
  const api = (path) => parseJson(run("gh", ["api", "--hostname", "github.com", `repos/${repository}/${path}`], "could not read native-build artifact metadata"));
  const response = api(`actions/workflows/jvm-native-resources.yml/runs?status=success&head_sha=${sourceSha}&per_page=100`);
  if (!record(response) || !Array.isArray(response.workflow_runs)) fail("invalid native-build run metadata");
  const candidates = response.workflow_runs.filter((item) => record(item) && item.head_sha === sourceSha &&
    item.status === "completed" && item.conclusion === "success" && item.path === ".github/workflows/jvm-native-resources.yml" &&
    record(item.repository) && item.repository.full_name === repository && Number.isSafeInteger(item.id) && item.id > 0);
  const selected = candidates.sort((left, right) => right.id - left.id)[0];
  if (selected === undefined) {
    fail("provide KOTLIN_NATIVE_RESOURCES_DIR for this source SHA, or run JVM Native Resources to build the other desktop platforms");
  }
  const inventory = api(`actions/runs/${selected.id}/artifacts?per_page=100`);
  if (!record(inventory) || !Array.isArray(inventory.artifacts)) fail("invalid native-build artifact metadata");
  const resources = join(scratch, "native-resources");
  mkdirSync(resources);
  for (const [platform, filename] of JVM_LIBRARIES) {
    const matches = inventory.artifacts.filter((item) => record(item) && item.name === `kotlin-native-${platform}`);
    const artifact = matches[0];
    if (matches.length !== 1 || artifact.expired !== false || !Number.isSafeInteger(artifact.id) || artifact.id < 1 ||
        typeof artifact.digest !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(artifact.digest) ||
        !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1 || artifact.size_in_bytes > MAX_NATIVE_BYTES) {
      fail("matching native-build artifacts are missing, expired or invalid");
    }
    const archive = join(scratch, `${platform}.zip`);
    const descriptor = openSync(archive, "wx", 0o600);
    try {
      run("gh", ["api", "--hostname", "github.com", `repos/${repository}/actions/artifacts/${artifact.id}/zip`], "could not download a native-build artifact", {
        stdio: ["ignore", descriptor, "pipe"],
      });
    } finally { closeSync(descriptor); }
    if (`sha256:${(await digest(archive)).sha256}` !== artifact.digest) fail("native-build artifact checksum mismatch");
    const path = `${NATIVE_ROOT}/${platform}/${filename}`;
    const members = run("jar", ["tf", archive], "could not inspect a native-build artifact").split(/\r?\n/u);
    if (members.filter((name) => name === path).length !== 1) fail("native-build artifact is missing its expected library");
    // Extract one fixed member, never arbitrary archive paths or sibling files.
    run("jar", ["xf", archive, path], "could not extract a native-build library", { cwd: resources });
  }
  run(process.execPath, [join(root, "scripts/write_native_manifest.mjs"), join(resources, NATIVE_ROOT),
    join(resources, NATIVE_ROOT, "native-manifest.json")], "could not write the native resource checksum manifest");
  await verifyLocalNativeResources(resources, sourceSha);
  return resources;
}

export async function buildLocalMavenPublications(root, version, sourceSha, destination, scratch, options = {}) {
  const environment = { ...(options.environment ?? process.env), GITHUB_SHA: sourceSha };
  for (const name of ["MAVEN_SIGNING_KEY", "MAVEN_SIGNING_KEY_ID", "MAVEN_SIGNING_PASSWORD",
    "ORG_GRADLE_PROJECT_signingInMemoryKey", "ORG_GRADLE_PROJECT_signingInMemoryKeyPassword"]) delete environment[name];
  const run = options.run ?? runner(root, environment);
  publicationLayout(version, sourceSha);
  for (const path of [root, destination, scratch]) if (!isAbsolute(path)) fail("local Maven build directories must be absolute");
  for (const lane of ["kotlin", "kotlin-android"]) {
    const source = readFileSync(join(root, "packages", lane, "build.gradle.kts"), "utf8");
    const versions = [...source.matchAll(/^version = "([^"]+)"$/gmu)];
    if (versions.length !== 1 || versions[0][1] !== version) fail("JVM and Android versions must match the selected release");
  }
  const assertSource = () => verifyLocalMavenSource(root, sourceSha, run);
  assertSource();
  run("python3", ["-B", "scripts/check_repository_privacy.py", "--index"], "local release inputs failed privacy validation");
  console.error("Preparing desktop native libraries for the selected release commit...");
  const resources = await acquireNativeResources(root, sourceSha, scratch, environment, run);
  const jni = join(scratch, "android-jniLibs");
  const assets = join(scratch, "android-native-assets");
  console.error("Building Android JNI libraries...");
  run("bash", [join(root, "packages/kotlin-android/scripts/build-jni-libs.sh"), jni], "could not build Android JNI libraries", {
    timeout: BUILD_TIMEOUT_MS, stdio: "inherit",
  });
  run(process.execPath, [join(root, "scripts/write_native_manifest.mjs"), jni,
    join(assets, "reallyme-crypto/native-manifest.json")], "could not write the Android native checksum manifest");
  const gradle = (lane, tasks, properties) => run(join(root, "packages", lane, "gradlew"), [
    "--dependency-verification", "strict", "-p", join(root, "packages", lane), ...tasks, ...properties,
  ], "local Gradle publication build failed", { timeout: BUILD_TIMEOUT_MS, stdio: "inherit" });
  console.error("Building and testing the JVM publication...");
  gradle("kotlin", ["test", "publishMavenPublicationToLocalReleaseRepository"], [
    `-Preallyme.crypto.nativeResourcesDir=${resources}`, "-Preallyme.crypto.requireFullNativeResources=true",
  ]);
  console.error("Building and checking the Android publication...");
  gradle("kotlin-android", ["check", "publishAndroidReleasePublicationToLocalReleaseRepository"], [
    `-Preallyme.crypto.androidJniLibsDir=${jni}`, `-Preallyme.crypto.androidNativeAssetsDir=${assets}`,
    "-Preallyme.crypto.requireAndroidJniLibs=true",
  ]);
  assertSource();
  const packages = join(scratch, "publications");
  mkdirSync(packages);
  for (const [lane, kind] of [["kotlin", "jvm"], ["kotlin-android", "android"]]) {
    stageMavenPublication(join(root, "packages", lane, "build/repos/releases"),
      join(packages, `maven-${kind}-${version}-${sourceSha}`), kind, version);
  }
  stageMavenPublications(packages, version, sourceSha, destination);
  console.error("Checking publication privacy before signing...");
  run("python3", ["-B", "scripts/check_release_privacy.py", "--directory", destination], "local Maven publications failed privacy validation", { stdio: "inherit" });
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const [, , option, sourceSha, ...extra] = process.argv;
    if (option !== "--verify-source" || extra.length !== 0) fail("expected --verify-source and a full release source SHA");
    verifyLocalMavenSource(fileURLToPath(new URL("../", import.meta.url)), sourceSha);
  } catch (error) {
    console.error(error instanceof MavenPublicationError ? error.message : "could not verify the local release source");
    process.exitCode = 1;
  }
}
