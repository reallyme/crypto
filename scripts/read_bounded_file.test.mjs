// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileInputError, hashBoundedFile, readBoundedFile } from "./read_bounded_file.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(join(tmpdir(), "bounded-file-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, path: join(root, "input") };
}

function afterStat(t, action) {
  const original = fs.fstatSync;
  let first = true;
  t.mock.method(fs, "fstatSync", (...args) => {
    const status = original(...args);
    if (first) { first = false; action(); }
    return status;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
}

for (const read of [readBoundedFile, hashBoundedFile]) {
  test(`${read.name} accepts bounded bytes and hashes across chunk boundaries`, (t) => {
    const { path } = fixture(t);
    const bytes = Buffer.alloc(131_073, 0xa5);
    fs.writeFileSync(path, bytes);
    const actual = read(path, bytes.length);
    if (read === readBoundedFile) assert.deepEqual(actual, bytes);
    else assert.deepEqual(actual, { size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  });

  test(`${read.name} rejects missing, empty, oversized, linked and non-file inputs`, (t) => {
    const { root, path } = fixture(t);
    assert.throws(() => read(path, 8), FileInputError);
    assert.throws(() => read(root, 8), FileInputError);
    fs.writeFileSync(path, "");
    assert.throws(() => read(path, 8), FileInputError);
    fs.writeFileSync(path, "123456789");
    assert.throws(() => read(path, 8), FileInputError);
    const link = join(root, "link");
    fs.symlinkSync(path, link);
    assert.throws(() => read(link, 16), FileInputError);
    for (const maximum of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER]) {
      assert.throws(() => read(path, maximum), FileInputError);
    }
  });

  for (const replacement of ["short", "12345678901234567890", "same-size!"]) {
    test(`${read.name} rejects concurrent mutation (${replacement.length} bytes)`, (t) => {
      const { path } = fixture(t);
      fs.writeFileSync(path, "original!!");
      afterStat(t, () => fs.writeFileSync(path, replacement));
      assert.throws(() => read(path, 32), (error) =>
        error instanceof FileInputError && error.code === "changed-during-read");
    });
  }

  test(`${read.name} never reads a replacement inode after validation`, (t) => {
    const { root, path } = fixture(t);
    const original = Buffer.from("original");
    fs.writeFileSync(path, original);
    const replacement = join(root, "replacement");
    fs.writeFileSync(replacement, "malicious");
    afterStat(t, () => fs.renameSync(replacement, path));
    try {
      const actual = read(path, 32);
      if (read === readBoundedFile) assert.deepEqual(actual, original);
      else assert.equal(actual.sha256, createHash("sha256").update(original).digest("hex"));
    } catch (error) {
      assert.ok(error instanceof FileInputError);
    }
  });

  test(`${read.name} rejects FIFOs without blocking`, { skip: process.platform === "win32" }, (t) => {
    const { path } = fixture(t);
    assert.equal(spawnSync("mkfifo", [path]).status, 0);
    assert.throws(() => read(path, 32), FileInputError);
  });
}
