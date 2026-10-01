// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { extractReleaseNotes, ReleaseNotesError } from "./release_notes.mjs";

test("selects only the requested release section", () => {
  const notes = extractReleaseNotes("# Notes\n\n## 0.3.10\n\n- New hash\n\n## 0.3.9\n\n- Prior release\n", "0.3.10");
  assert.equal(notes, "## 0.3.10\n\n- New hash");
});

test("rejects malformed, missing, duplicate, and empty sections", () => {
  const cases = [
    ["## 0.3.10\n\n- New hash\n", "v0.3.10", "InvalidVersion"],
    ["## 0.3.9\n\n- Prior release\n", "0.3.10", "MissingOrDuplicateVersion"],
    ["## 0.3.10\n\n- First\n\n## 0.3.10\n\n- Second\n", "0.3.10", "MissingOrDuplicateVersion"],
    ["## 0.3.10\n\n## 0.3.9\n\n- Prior release\n", "0.3.10", "EmptyReleaseNotes"],
  ];
  for (const [source, version, code] of cases) {
    assert.throws(() => extractReleaseNotes(source, version), (error) => {
      assert.ok(error instanceof ReleaseNotesError);
      assert.equal(error.code, code);
      return true;
    });
  }
});

test("current 0.3.10 notes include the announced changes", () => {
  const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
  const notes = extractReleaseNotes(readFileSync(path, "utf8"), "0.3.10");
  assert.match(notes, /Poseidon2/u);
  assert.match(notes, /release-readiness.*0\.6\.6/u);
});
