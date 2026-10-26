#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { spawnSync } from "node:child_process";

// The upstream core and this repository's policy checker are separate inputs.
// Pinning both makes an unreviewed policy edit fail before the checker runs.
const RELEASE_READINESS_COMMIT = "5c2da5e5d5795c2c895d0dca0819287ee7101207";
const RELEASE_READINESS_CORE_SHA256 =
  "d3434554901ea5438bb0dd64f4f7214b9050e95cd1e3d579cc2992f4c662e85a";
const LOCAL_CHECKER_SHA256 =
  "9294345c19ba90a56436b46082b988b75318479380854a3b871b7f564318ec28";
// The checker imports both local policy modules. Pinning only its entry file
// would let an unreviewed dependency change the release decision.
const LOCAL_CHECKER_DEPENDENCIES = [
  ["scripts/crypto_operation_route_readiness.mjs", "e82490e194d4712d36ae43b5975fb7449d67ea08260763a83798a60dc33452f2"],
  ["scripts/workflow_gate_policy.mjs", "ee426d45e53608350bce9923ebc78d43ec8dc2c68df1af1305d30a1203d9656b"],
];
const RELEASE_READINESS_CORE_URL =
  `https://raw.githubusercontent.com/reallyme/release-readiness/${RELEASE_READINESS_COMMIT}/core.mjs`;
const VENDORED_CORE_PATH = "scripts/release-readiness/core.mjs";
const LOCAL_CHECKER_PATH = "scripts/check_release_readiness.mjs";
const MAX_CORE_BYTES = 262_144;
const MAX_CHECKER_BYTES = 524_288;
const FETCH_TIMEOUT_MILLISECONDS = 30_000;

const fail = (message) => {
  console.error(`pinned release readiness failed: ${message}`);
  process.exit(1);
};

const sha256 = (value) => createHash("sha256").update(value).digest();

const readBoundedRegularFile = (path, maximumBytes, label) => {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    fail("this platform cannot enforce no-follow file reads");
  }
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
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
if (!timingSafeEqual(sha256(localChecker), expectedCheckerDigest)) {
  fail("local checker does not match the reviewed repository policy pin");
}
if (!timingSafeEqual(sha256(localCore), expectedDigest)) {
  fail("vendored core does not match the reviewed upstream pin");
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

const checker = spawnSync(process.execPath, [LOCAL_CHECKER_PATH, ...process.argv.slice(2)], {
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
