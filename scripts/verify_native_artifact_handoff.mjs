#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { createReadStream, lstatSync, readdirSync, appendFileSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";

const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_NATIVE_LIBRARY_BYTES = 536_870_912;
const MAX_DIRECTORY_ENTRIES = 64;
const MAX_DIRECTORY_DEPTH = 5;
const NATIVE_EXTENSIONS = new Set([".dll", ".dylib", ".so"]);
const NATIVE_RESOURCE_ROOT = "me/really/crypto/native";

// The output names are deliberately platform-specific. GitHub combines unique
// matrix outputs, which keeps each producer's digest outside the artifact that
// the downstream Maven job downloads and verifies.
const PLATFORMS = Object.freeze([
  Object.freeze({
    id: "linux-x86_64",
    relativePath: `${NATIVE_RESOURCE_ROOT}/linux-x86_64/libcrypto_ffi.so`,
    output: "linux_x86_64_sha256",
    environment: "NATIVE_SHA256_LINUX_X86_64",
  }),
  Object.freeze({
    id: "linux-aarch64",
    relativePath: `${NATIVE_RESOURCE_ROOT}/linux-aarch64/libcrypto_ffi.so`,
    output: "linux_aarch64_sha256",
    environment: "NATIVE_SHA256_LINUX_AARCH64",
  }),
  Object.freeze({
    id: "macos-x86_64",
    relativePath: `${NATIVE_RESOURCE_ROOT}/macos-x86_64/libcrypto_ffi.dylib`,
    output: "macos_x86_64_sha256",
    environment: "NATIVE_SHA256_MACOS_X86_64",
  }),
  Object.freeze({
    id: "macos-aarch64",
    relativePath: `${NATIVE_RESOURCE_ROOT}/macos-aarch64/libcrypto_ffi.dylib`,
    output: "macos_aarch64_sha256",
    environment: "NATIVE_SHA256_MACOS_AARCH64",
  }),
  Object.freeze({
    id: "windows-x86_64",
    relativePath: `${NATIVE_RESOURCE_ROOT}/windows-x86_64/crypto_ffi.dll`,
    output: "windows_x86_64_sha256",
    environment: "NATIVE_SHA256_WINDOWS_X86_64",
  }),
]);

const fail = (reason) => {
  process.stderr.write(`native artifact handoff verification failed: ${reason}\n`);
  process.exit(1);
};

const assertDirectory = (path) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    fail("native resource root is inaccessible");
  }
  if (status.isSymbolicLink() || !status.isDirectory()) {
    fail("native resource root is not a regular directory");
  }
};

const collectArtifactFiles = (root) => {
  const artifactFiles = [];
  let entryCount = 0;

  const walk = (directory, depth) => {
    if (depth > MAX_DIRECTORY_DEPTH) {
      fail("native resource tree exceeds the supported depth");
    }

    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      fail("native resource tree is unreadable");
    }

    for (const entry of entries) {
      entryCount += 1;
      if (entryCount > MAX_DIRECTORY_ENTRIES) {
        fail("native resource tree contains too many entries");
      }

      const path = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) {
        fail("native resource tree contains a symbolic link");
      }
      if (entry.isDirectory()) {
        walk(path, depth + 1);
      } else if (entry.isFile()) {
        artifactFiles.push(relative(root, path).split(sep).join("/"));
      } else if (!entry.isFile()) {
        fail("native resource tree contains an unsupported filesystem entry");
      }
    }
  };

  walk(root, 0);
  return artifactFiles.sort((left, right) => left.localeCompare(right));
};

const digestNativeLibrary = async (path) => {
  if (!NATIVE_EXTENSIONS.has(extname(path))) {
    fail("an expected native library has an unsupported extension");
  }
  let statusBefore;
  try {
    statusBefore = lstatSync(path);
  } catch {
    fail("an expected native library is inaccessible");
  }
  if (
    statusBefore.isSymbolicLink() ||
    !statusBefore.isFile() ||
    statusBefore.size === 0 ||
    statusBefore.size > MAX_NATIVE_LIBRARY_BYTES
  ) {
    fail("an expected native library is not a bounded regular file");
  }

  const hash = createHash("sha256");
  try {
    await new Promise((resolveStream, rejectStream) => {
      const stream = createReadStream(path);
      stream.on("data", (chunk) => hash.update(chunk));
      stream.on("error", rejectStream);
      stream.on("end", resolveStream);
    });
  } catch {
    fail("an expected native library could not be read");
  }

  let statusAfter;
  try {
    statusAfter = lstatSync(path);
  } catch {
    fail("an expected native library changed while it was being hashed");
  }
  if (
    statusAfter.isSymbolicLink() ||
    !statusAfter.isFile() ||
    statusAfter.dev !== statusBefore.dev ||
    statusAfter.ino !== statusBefore.ino ||
    statusAfter.size !== statusBefore.size ||
    statusAfter.mtimeMs !== statusBefore.mtimeMs
  ) {
    fail("an expected native library changed while it was being hashed");
  }

  return hash.digest("hex");
};

const requireExactArtifactFiles = (actual, expected) => {
  // The artifact root becomes a JVM resource root. Reject every unexpected
  // regular file, not only extra native libraries, so unbound classes,
  // manifests, and service-provider files cannot enter the published JAR.
  if (actual.length !== expected.length) {
    fail("native artifact does not contain the exact expected file set");
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index] !== expected[index]) {
      fail("native artifact does not contain the exact expected file set");
    }
  }
};

const [, , operation, rootArgument, platformArgument] = process.argv;
if ((operation !== "record" && operation !== "verify") || rootArgument === undefined) {
  fail("usage: verify_native_artifact_handoff.mjs <record|verify> <artifact-root> [platform]");
}

const root = resolve(rootArgument);
assertDirectory(root);
const actualArtifactFiles = collectArtifactFiles(root);

if (operation === "record") {
  const platform = PLATFORMS.find((candidate) => candidate.id === platformArgument);
  if (platform === undefined) {
    fail("record requires a supported platform identifier");
  }
  requireExactArtifactFiles(actualArtifactFiles, [platform.relativePath]);

  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath === undefined || outputPath.length === 0) {
    fail("GITHUB_OUTPUT is required when recording a producer digest");
  }
  const digest = await digestNativeLibrary(resolve(root, platform.relativePath));
  try {
    appendFileSync(outputPath, `${platform.output}=${digest}\n`, { encoding: "utf8" });
  } catch {
    fail("producer digest could not be written to the job output record");
  }
  process.stdout.write(`Recorded SHA-256 for ${platform.id}\n`);
} else {
  const expectedFiles = PLATFORMS.map((platform) => platform.relativePath).sort((left, right) =>
    left.localeCompare(right),
  );
  requireExactArtifactFiles(actualArtifactFiles, expectedFiles);

  for (const platform of PLATFORMS) {
    const expectedDigest = process.env[platform.environment];
    if (expectedDigest === undefined || !CHECKSUM_PATTERN.test(expectedDigest)) {
      fail(`job output digest for ${platform.id} is missing or malformed`);
    }
    const actualDigest = await digestNativeLibrary(resolve(root, platform.relativePath));
    if (actualDigest !== expectedDigest) {
      fail(`downloaded native library for ${platform.id} does not match its producer job output`);
    }
  }
  process.stdout.write("Downloaded native libraries match all producer job outputs\n");
}
