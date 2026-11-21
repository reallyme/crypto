#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// The upstream core and this repository's policy checker are separate inputs.
// Pinning both makes an unreviewed policy edit fail before the checker runs.
const RELEASE_READINESS_COMMIT = "16aab5287de498e858ff3b85d9e66d7c9f7ebb74";
const RELEASE_READINESS_CORE_SHA256 =
  "56ae3823215f5bca908d2fce3c9304d4ea6bab0334038f37ebe33023dadb8594";
const LOCAL_CHECKER_SHA256 =
  "2f50c5cb5b6ae2589d35a8dc8d466373625b52e33caf83cb44653ac7e77d5d4d";
// The checker imports local policy modules. Pinning only its entry file
// would let an unreviewed dependency change the release decision.
const LOCAL_CHECKER_DEPENDENCIES = [
  ["scripts/generate_protobuf.mjs", "2cc10784a4e7699a0ff271f88014b2da7bab5ca69009c4f97228c72d9ab1d394"],
  ["scripts/check_local_proto_tools.mjs", "d3c542bacd20f41e3cfbff48cd751d07f7af8ae65f7d903d4d57642a71a2db82"],
  ["scripts/install_local_proto_tools.sh", "b7fe4e8b2402599b0b494c7ec178d1b76dfb55f88e8bfc2cfc65e46b542d7288"],
  ["scripts/native_buffa_readiness.mjs", "bdc838ba6bb5a07a36bb060a4cc1524baeaf70205b10f09e7ee8630f8ff128ca"],
  ["scripts/proto_scalar_policy.mjs", "f7b071722aa93a0f75a7fe57f994ae7a12e030ee0bedb1be7058e48543cac377"],
  ["scripts/crypto_operation_route_readiness.mjs", "2b15c4e6778f18cf10b493fb5644e47baf537185b6e4411909ba875b5bd38db4"],
  ["scripts/workflow_gate_policy.mjs", "d5d1a5b4dda702602f28f282e033c0876d445cbd0ebb24c51074fdba9539b761"],
];
const RELEASE_READINESS_CORE_URL =
  `https://raw.githubusercontent.com/reallyme/release-readiness/${RELEASE_READINESS_COMMIT}/core.mjs`;
const VENDORED_CORE_PATH = "scripts/release-readiness/core.mjs";
const LOCAL_CHECKER_PATH = "scripts/check_release_readiness.mjs";
const MAX_CORE_BYTES = 262_144;
const MAX_CHECKER_BYTES = 524_288;
const FETCH_TIMEOUT_MILLISECONDS = 30_000;
const repositoryUrl = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(repositoryUrl);

const fail = (message) => {
  console.error(`pinned release readiness failed: ${message}`);
  process.exit(1);
};

const supportedArguments = new Set([
  "--check-pins", "--refresh-checker-pin", "--verify-upstream", "--print-commit",
  "--generated-freshness", "--release-packages", "--ci-policy",
  "--typescript-source", "--swift-source", "--kotlin-source",
]);
const suppliedArguments = new Set();
for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument) || suppliedArguments.has(argument)) {
    fail("unsupported or duplicate argument");
  }
  suppliedArguments.add(argument);
}
const refreshCheckerPin = suppliedArguments.has("--refresh-checker-pin");
if (suppliedArguments.has("--print-commit")) {
  if (suppliedArguments.size !== 1) fail("commit lookup must be used on its own");
  console.log(RELEASE_READINESS_COMMIT);
  process.exit(0);
}
if (refreshCheckerPin && suppliedArguments.size !== 1) {
  fail("checker pin refresh cannot be combined with checks");
}
// A checksum refresh records reviewed policy; CI must never approve its own
// changed inputs simply to make an integrity check pass.
if (refreshCheckerPin && process.env.CI !== undefined) {
  fail("checker pin refresh is a local review operation and is forbidden in CI");
}
const checkerModes = new Set([
  "--generated-freshness", "--release-packages", "--ci-policy",
  "--typescript-source", "--swift-source", "--kotlin-source",
]);
const checkerArguments = [...suppliedArguments].filter((argument) => checkerModes.has(argument));
if (checkerArguments.length > 1) {
  fail("checker modes are mutually exclusive");
}
if (suppliedArguments.has("--check-pins") && checkerArguments.length !== 0) {
  fail("--check-pins cannot be combined with a full checker mode");
}

const sha256 = (value) => createHash("sha256").update(value).digest();

const readBoundedRegularFile = (path, maximumBytes, label) => {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    fail("this platform cannot enforce no-follow file reads");
  }
  let descriptor;
  try {
    descriptor = openSync(
      new URL(path, repositoryUrl),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const status = fstatSync(descriptor);
    if (!status.isFile()) {
      fail(`${label} must be a regular file`);
    }
    if (status.size === 0 || status.size > maximumBytes) {
      fail(`${label} size is outside the accepted boundary`);
    }

    // Read through the already-validated descriptor. Besides closing the
    // check/use race, the extra byte keeps a concurrent growth attempt inside
    // the same fail-closed size boundary.
    const buffer = Buffer.alloc(status.size + 1);
    let totalLength = 0;
    while (totalLength < buffer.length) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        totalLength,
        buffer.length - totalLength,
        null,
      );
      if (bytesRead === 0) {
        break;
      }
      totalLength += bytesRead;
      if (totalLength > status.size || totalLength > maximumBytes) {
        fail(`${label} size is outside the accepted boundary`);
      }
    }
    if (totalLength === 0 || totalLength !== status.size) {
      fail(`${label} size is outside the accepted boundary`);
    }
    return buffer.subarray(0, totalLength);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
  }
};

const expectedDigest = Buffer.from(RELEASE_READINESS_CORE_SHA256, "hex");
if (expectedDigest.length !== 32) {
  fail("configured core digest is invalid");
}
const expectedCheckerDigest = Buffer.from(LOCAL_CHECKER_SHA256, "hex");
if (expectedCheckerDigest.length !== 32) {
  fail("configured local checker digest is invalid");
}

let localCore;
let localChecker;
try {
  localChecker = readBoundedRegularFile(LOCAL_CHECKER_PATH, MAX_CHECKER_BYTES, "local checker");
  localCore = readBoundedRegularFile(VENDORED_CORE_PATH, MAX_CORE_BYTES, "vendored core");
} catch {
  fail("release readiness inputs are missing or inaccessible");
}
if (!timingSafeEqual(sha256(localCore), expectedDigest)) {
  fail(`vendored core does not match the reviewed upstream pin at ${RELEASE_READINESS_COMMIT}`);
}
for (const [path, digestHex] of LOCAL_CHECKER_DEPENDENCIES) {
  const expected = Buffer.from(digestHex, "hex");
  if (expected.length !== 32) {
    fail(`configured local dependency digest is invalid: ${path}`);
  }
  let source;
  try {
    source = readBoundedRegularFile(path, MAX_CHECKER_BYTES, `local checker dependency ${path}`);
  } catch {
    fail(`local checker dependency is missing or inaccessible: ${path}`);
  }
  if (!timingSafeEqual(sha256(source), expected)) {
    fail(`local checker dependency does not match the reviewed pin: ${path}`);
  }
}

if (refreshCheckerPin) {
  try {
    const source = readBoundedRegularFile(import.meta.url, MAX_CHECKER_BYTES, "runner").toString("utf8");
    const declaration = /const LOCAL_CHECKER_SHA256 =\n  "[0-9a-f]{64}";/gu;
    if ([...source.matchAll(declaration)].length !== 1) {
      fail("local checker pin declaration is missing or ambiguous");
    }
    const updated = source.replace(
      declaration,
      `const LOCAL_CHECKER_SHA256 =\n  "${sha256(localChecker).toString("hex")}";`,
    );
    if (updated !== source) {
      // Only the fixed-width digest changes. Avoid following a substituted
      // symlink or truncating the runner before its content is validated.
      writeFileSync(new URL(import.meta.url), updated, {
        flag: constants.O_WRONLY | constants.O_NOFOLLOW,
      });
    }
  } catch {
    fail("local checker pin could not be refreshed");
  }
  console.log("local checker pin refreshed; review the checker and pin diff together");
  process.exit(0);
}

if (!timingSafeEqual(sha256(localChecker), expectedCheckerDigest)) {
  fail("local checker does not match the reviewed repository policy pin; after reviewing the policy change, run node scripts/run_pinned_release_readiness.mjs --refresh-checker-pin");
}

// Upstream provenance verification is explicit maintenance. Routine CI
// authenticates the identical committed bytes without requiring this service.
if (suppliedArguments.has("--verify-upstream")) {
  let response;
  try {
    response = await fetch(RELEASE_READINESS_CORE_URL, {
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MILLISECONDS),
    });
  } catch {
    fail("pinned upstream core could not be fetched");
  }
  if (!response.ok || response.body === null) {
    fail("pinned upstream core returned an invalid response");
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^[1-9][0-9]*$/u.test(contentLength)) {
      fail("pinned upstream core returned an invalid content length");
    }
    const parsedLength = Number.parseInt(contentLength, 10);
    if (!Number.isSafeInteger(parsedLength) || parsedLength <= 0 || parsedLength > MAX_CORE_BYTES) {
      fail("pinned upstream core length is outside the accepted boundary");
    }
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalLength = 0;
  while (true) {
    let result;
    try {
      result = await reader.read();
    } catch {
      fail("pinned upstream core response could not be read");
    }
    if (result.done) {
      break;
    }
    const chunk = result.value;
    if (!(chunk instanceof Uint8Array) || chunk.length > MAX_CORE_BYTES - totalLength) {
      fail("pinned upstream core exceeds the accepted boundary");
    }
    chunks.push(chunk);
    totalLength += chunk.length;
  }
  if (totalLength === 0) {
    fail("pinned upstream core is empty");
  }
  const upstreamCore = Buffer.concat(chunks, totalLength);
  if (!timingSafeEqual(sha256(upstreamCore), expectedDigest)) {
    fail("pinned upstream core digest does not match the reviewed commit");
  }
}

// Local development and the first CI steps need to detect stale policy pins
// without the cost of running the full release gate.
if (suppliedArguments.has("--check-pins")) {
  process.exit(0);
}

// The reviewed digest authenticates the committed upstream bytes. Downloading
// the identical file again adds an availability dependency without adding an
// integrity guarantee; policy upgrades must update the vendored core and pin.
const checker = spawnSync(process.execPath, [LOCAL_CHECKER_PATH, ...checkerArguments], {
  cwd: repositoryRoot,
  env: process.env,
  stdio: "inherit",
});
if (checker.error !== undefined) {
  fail("local release readiness checker could not be started");
}
if (!Number.isInteger(checker.status)) {
  fail("local release readiness checker ended without a deterministic status");
}
process.exit(checker.status);
