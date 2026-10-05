// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { extractReleaseNotes, ReleaseNotesError } from "./release_notes.mjs";

test("selects only the requested release section", () => {
  const notes = extractReleaseNotes("# Notes\n\n## 0.3.11\n\n- New hash\n\n## 0.3.9\n\n- Prior release\n", "0.3.11");
  assert.equal(notes, "## 0.3.11\n\n- New hash");
});

test("rejects malformed, missing, duplicate, and empty sections", () => {
  const cases = [
    ["## 0.3.11\n\n- New hash\n", "v0.3.11", "InvalidVersion"],
    ["## 0.3.9\n\n- Prior release\n", "0.3.11", "MissingOrDuplicateVersion"],
    ["## 0.3.11\n\n- First\n\n## 0.3.11\n\n- Second\n", "0.3.11", "MissingOrDuplicateVersion"],
    ["## 0.3.11\n\n## 0.3.9\n\n- Prior release\n", "0.3.11", "EmptyReleaseNotes"],
  ];
  for (const [source, version, code] of cases) {
    assert.throws(() => extractReleaseNotes(source, version), (error) => {
      assert.ok(error instanceof ReleaseNotesError);
      assert.equal(error.code, code);
      return true;
    });
  }
});

test("current 0.3.13 notes describe P-256 low-S normalization", () => {
  const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
  const notes = extractReleaseNotes(readFileSync(path, "utf8"), "0.3.13");
  assert.match(notes, /fixed-width 64-byte `r \|\| s`/u);
  assert.match(notes, /Secure Enclave/u);
  assert.match(notes, /Android/u);
});
