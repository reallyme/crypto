// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

async function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "readiness-core-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "release-readiness"));
  for (const path of ["load_release_readiness_core.mjs", "read_bounded_file.mjs", "release-readiness/core.mjs"]) {
    copyFileSync(new URL(path, import.meta.url), join(root, path));
  }
  const managed = join(root, "managed.mjs");
  const local = join(root, "release-readiness/core.mjs");
  copyFileSync(local, managed);
  const loader = await import(pathToFileURL(join(root, "load_release_readiness_core.mjs")).href);
  return { ...loader, managed, local };
}

test("local and identical managed cores preserve the reviewed API", async (t) => {
  const f = await fixture(t);
  for (const selected of [undefined, pathToFileURL(f.managed).href]) {
    const core = await f.loadReleaseReadinessCore(selected);
    assert.equal(core.RELEASE_READINESS_VERSION, "0.9.9");
    assert.equal(typeof core.createReleaseReadinessContext, "function");
  }
});

test("changed, oversized, missing and non-file managed cores are rejected before execution", async (t) => {
  const f = await fixture(t);
  for (const bytes of ["globalThis.unreviewedCoreRan = true;", "", "x".repeat(262_145)]) {
    writeFileSync(f.managed, bytes);
    await assert.rejects(f.loadReleaseReadinessCore(pathToFileURL(f.managed).href), f.ReadinessCoreError);
  }
  for (const url of ["https://example.invalid/core.mjs", pathToFileURL(f.managed + ".missing").href,
    pathToFileURL(f.managed).href + "?alternate", pathToFileURL(f.managed).href + "#alternate"]) {
    await assert.rejects(f.loadReleaseReadinessCore(url), f.ReadinessCoreError);
  }
  assert.equal(globalThis.unreviewedCoreRan, undefined);
  writeFileSync(f.local, readFileSync(f.managed));
  await assert.rejects(f.loadReleaseReadinessCore(undefined), f.ReadinessCoreError);
});

test("managed core symlinks are rejected", async (t) => {
  const f = await fixture(t);
  rmSync(f.managed);
  symlinkSync(f.local, f.managed);
  await assert.rejects(f.loadReleaseReadinessCore(pathToFileURL(f.managed).href), f.ReadinessCoreError);
});

test("a path replacement after authentication cannot change the imported code", async (t) => {
  const f = await fixture(t);
  const selected = pathToFileURL(f.managed).href;
  let replaced = false;
  let closes = 0;
  const close = fs.closeSync;
  t.mock.method(fs, "closeSync", (descriptor) => {
    close(descriptor);
    closes += 1;
    if (closes === 2) {
      writeFileSync(f.managed, "globalThis.unreviewedCoreRan = true; export const RELEASE_READINESS_VERSION = 'wrong';");
      replaced = true;
    }
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  const core = await f.loadReleaseReadinessCore(selected);
  assert.ok(replaced);
  assert.equal(core.RELEASE_READINESS_VERSION, "0.9.9");
  assert.equal(globalThis.unreviewedCoreRan, undefined);
});
