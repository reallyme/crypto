// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildLocalMavenPublications } from "./build_maven_publications.mjs";
import { MavenPublicationError, publicationLayout } from "./stage_maven_publications.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const JVM_NATIVE_FILES = [
  "linux-x86_64/libcrypto_ffi.so", "linux-aarch64/libcrypto_ffi.so",
  "macos-x86_64/libcrypto_ffi.dylib", "macos-aarch64/libcrypto_ffi.dylib",
  "windows-x86_64/crypto_ffi.dll", "native-manifest.json",
].map((path) => `me/really/crypto/native/${path}`);
const ANDROID_NATIVE_FILES = [
  ...["arm64-v8a", "armeabi-v7a", "x86_64", "x86"].map((abi) => `jni/${abi}/libcrypto_ffi.so`),
  "assets/reallyme-crypto/native-manifest.json",
];

function requireArchiveEntries(archive, expected) {
  const result = spawnSync("jar", ["tf", archive], {
    cwd: repositoryRoot, encoding: "utf8", timeout: 120_000, maxBuffer: 16_777_216,
  });
  if (result.error !== undefined || result.status !== 0) throw new MavenPublicationError("could not inspect a local Maven archive");
  const entries = result.stdout.split(/\r?\n/u);
  if (expected.some((path) => entries.filter((entry) => entry === path).length !== 1)) {
    throw new MavenPublicationError("local Maven archive has a missing or duplicate native entry");
  }
}

async function stage() {
  const [, , version, sourceSha, destination, ...extra] = process.argv;
  publicationLayout(version, sourceSha);
  if (destination === undefined || extra.length !== 0 || !isAbsolute(destination) ||
      !lstatSync(destination).isDirectory() || lstatSync(destination).isSymbolicLink() || readdirSync(destination).length !== 0) {
    throw new MavenPublicationError("expected an empty, absolute staging directory");
  }
  const scratch = mkdtempSync(join(tmpdir(), "crypto-local-maven-"));
  try {
    await buildLocalMavenPublications(repositoryRoot, version, sourceSha, destination, scratch);
    requireArchiveEntries(join(destination, `me/really/crypto/${version}/crypto-${version}.jar`), JVM_NATIVE_FILES);
    requireArchiveEntries(join(destination, `me/really/crypto-android/${version}/crypto-android-${version}.aar`), ANDROID_NATIVE_FILES);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    await stage();
  } catch (error) {
    const message = error instanceof MavenPublicationError ? error.message : "could not stage the local Maven publications";
    console.error(`Maven staging failed: ${message}`);
    process.exitCode = 1;
  }
}
