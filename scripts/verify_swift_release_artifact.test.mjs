#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./verify_swift_release_artifact.mjs", import.meta.url));

const writeFixture = (root, { bound = true, sidecarOverride } = {}) => {
  const archive = join(root, "artifact.zip");
  const sidecar = join(root, "artifact.checksum");
  const manifest = join(root, "Package.swift");
  const archiveBytes = Buffer.from("deterministic Swift artifact fixture", "utf8");
  const checksum = createHash("sha256").update(archiveBytes).digest("hex");
  writeFileSync(archive, archiveBytes);
  writeFileSync(sidecar, `${sidecarOverride ?? checksum}\n`);
  writeFileSync(
    manifest,
    `let ffiArtifactChecksum = "${checksum}"
let ffiArtifactVersion = "0.3.0"
let ffiArtifactLocalPathOverride = ""
.binaryTarget(
    name: "ReallyMeCryptoFFI",
    url: "https://github.com/reallyme/crypto/releases/download/${bound ? "v\\(ffiArtifactVersion)" : "v0.3.0"}/ReallyMeCryptoFFI.xcframework.zip",
    checksum: ${bound ? "ffiArtifactChecksum" : `"${checksum}"`}
)
`,
  );
  return { archive, sidecar, manifest };
};

test("Swift release verifier accepts matching archive, sidecar, manifest, and version", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-swift-release-"));
  try {
    const fixture = writeFixture(root);
    assert.doesNotThrow(() => {
      execFileSync(
        process.execPath,
        [script, fixture.archive, fixture.sidecar, fixture.manifest, "0.3.0"],
        { stdio: "pipe" },
      );
    });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("Swift release verifier recomputes bytes and rejects a forged sidecar", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-swift-release-"));
  try {
    const fixture = writeFixture(root, { sidecarOverride: "0".repeat(64) });
    assert.throws(() => {
      execFileSync(
        process.execPath,
        [script, fixture.archive, fixture.sidecar, fixture.manifest, "0.3.0"],
        { stdio: "pipe" },
      );
    });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("Swift release verifier rejects unused manifest binding variables", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-swift-release-"));
  try {
    const fixture = writeFixture(root, { bound: false });
    assert.throws(() => {
      execFileSync(
        process.execPath,
        [script, fixture.archive, fixture.sidecar, fixture.manifest, "0.3.0"],
        { stdio: "pipe" },
      );
    });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
