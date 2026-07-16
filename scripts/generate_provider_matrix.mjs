#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const manifestPath = resolve(root, "provider_manifest.json");
// The backend matrix is generated into a marked region of PROVIDER_POLICY.md so
// the human policy and the machine-checked per-algorithm table live in one file.
const outputPath = resolve(root, "PROVIDER_POLICY.md");
const BEGIN_MARKER = "<!-- BEGIN GENERATED PROVIDER MATRIX -->";
const END_MARKER = "<!-- END GENERATED PROVIDER MATRIX -->";

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

const byId = new Map();
for (const algorithm of manifest.algorithms) {
  byId.set(algorithm.id, algorithm);
}

const resolveAlgorithm = (algorithm) => {
  if (algorithm.lanes) {
    return algorithm;
  }
  const source = byId.get(algorithm.sameAs);
  if (!source || !source.lanes) {
    throw new Error(`unresolved sameAs for ${algorithm.id}`);
  }
  return { ...algorithm, lanes: source.lanes };
};

const statusLabel = (status) => {
  switch (status) {
    case "supported":
      return "Supported";
    case "provider_aware":
      return "Provider-aware";
    case "partial":
      return "Partial";
    case "unsupported":
      return "Unsupported";
    default:
      throw new Error(`unknown status ${status}`);
  }
};

const fallbackLabel = (fallback) => {
  switch (fallback) {
    case "typed_provider_failure":
      return "typed provider failure";
    case "typed_unsupported_algorithm":
      return "typed unsupportedAlgorithm";
    case "explicit_provider_required":
      return "explicit provider required";
    default:
      throw new Error(`unknown fallback ${fallback}`);
  }
};

const laneCell = (lane) => {
  const providers = lane.providers.length === 0 ? "none" : lane.providers.join(" + ");
  const rust = lane.usesRust ? "Rust: yes" : "Rust: no";
  return `${statusLabel(lane.status)}<br>${lane.api}<br>Providers: ${providers}<br>${rust}<br>Fallback: ${fallbackLabel(lane.fallback)}`;
};

const tableLines = [
  "| Algorithm | Family | Swift | Kotlin/JVM | Kotlin/Android | TypeScript/WASM |",
  "|---|---|---|---|---|---|",
];

for (const rawAlgorithm of manifest.algorithms) {
  const algorithm = resolveAlgorithm(rawAlgorithm);
  tableLines.push(
    `| \`${algorithm.id}\` | ${algorithm.family} | ${laneCell(algorithm.lanes.swift)} | ${laneCell(algorithm.lanes.kotlin_jvm)} | ${laneCell(algorithm.lanes.kotlin_android)} | ${laneCell(algorithm.lanes.typescript_wasm)} |`,
  );
}

const current = readFileSync(outputPath, "utf8");
const begin = current.indexOf(BEGIN_MARKER);
const end = current.indexOf(END_MARKER);
if (begin === -1 || end === -1 || end < begin) {
  console.error(
    `PROVIDER_POLICY.md is missing the generated matrix markers ${BEGIN_MARKER} / ${END_MARKER}`,
  );
  process.exit(1);
}

const before = current.slice(0, begin + BEGIN_MARKER.length);
const after = current.slice(end);
const rendered = `${before}\n${tableLines.join("\n")}\n${after}`;

if (process.argv.includes("--check")) {
  if (current !== rendered) {
    console.error(
      "PROVIDER_POLICY.md backend matrix is not generated from provider_manifest.json; run `node scripts/generate_provider_matrix.mjs`",
    );
    process.exit(1);
  }
} else {
  writeFileSync(outputPath, rendered, "utf8");
}
