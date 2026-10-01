#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { extractReleaseNotes, ReleaseNotesError } from "./release_notes.mjs";

const version = process.argv[2];
if (process.argv.length !== 3) {
  console.error("usage: node scripts/extract_release_notes.mjs <version>");
  process.exitCode = 1;
} else {
  try {
    const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
    const source = readFileSync(path, "utf8");
    process.stdout.write(`${extractReleaseNotes(source, version)}\n`);
  } catch (error) {
    const code = error instanceof ReleaseNotesError ? error.code : "ReleaseNotesUnavailable";
    console.error(`release notes extraction failed: ${code}`);
    process.exitCode = 1;
  }
}
