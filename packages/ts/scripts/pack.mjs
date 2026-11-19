#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryDirectory = resolve(packageDirectory, "../..");

export class PackageError extends Error {
  constructor(code) {
    super(code);
    this.name = "PackageError";
    this.code = code;
  }
}

function copyRegularTree(source, destination) {
  const info = lstatSync(source);
  if (info.isDirectory()) {
    mkdirSync(destination);
    for (const name of readdirSync(source).sort()) {
      copyRegularTree(join(source, name), join(destination, name));
    }
  } else if (info.isFile()) {
    copyFileSync(source, destination);
  } else {
    throw new PackageError("NON_REGULAR_BUILD_INPUT");
  }
}

function publicationTarget(value) {
  if (typeof value === "string") {
    return value.startsWith("./dist/") ? `./src/${value.slice("./dist/".length)}` : value;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, target]) => [key, publicationTarget(target)]));
  }
  throw new PackageError("INVALID_EXPORT_TARGET");
}

export function stagePackage(source, destination) {
  const manifest = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest) ||
      manifest.name !== "@reallyme/crypto" || typeof manifest.version !== "string" ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.version) || typeof manifest.main !== "string" || typeof manifest.types !== "string" ||
      manifest.exports === null || typeof manifest.exports !== "object" || Array.isArray(manifest.exports)) {
    throw new PackageError("INVALID_PACKAGE_MANIFEST");
  }
  // Publication uses its own directory. The ignored development build remains
  // local, and the package's public import names remain unchanged.
  const published = { ...manifest, main: publicationTarget(manifest.main), types: publicationTarget(manifest.types),
    exports: publicationTarget(manifest.exports), files: ["src", "LICENSE", "README.md"] };
  delete published.scripts;
  mkdirSync(destination);
  copyRegularTree(join(source, "dist"), join(destination, "src"));
  for (const name of ["LICENSE", "README.md"]) copyRegularTree(join(source, name), join(destination, name));
  writeFileSync(join(destination, "package.json"), `${JSON.stringify(published, null, 2)}\n`);
}

function checkedRun(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, stdio: "inherit" });
  if (result.error !== undefined || result.status !== 0) throw new PackageError("PACKAGE_COMMAND_FAILED");
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--require-staged") {
    throw new PackageError("PUBLICATION_REQUIRES_STAGED_PACKAGE");
  }
  if (args.length !== 1 || !isAbsolute(args[0])) throw new PackageError("ABSOLUTE_OUTPUT_DIRECTORY_REQUIRED");
  const output = args[0];
  const scratch = mkdtempSync(join(tmpdir(), "crypto-npm-publication-"));
  try {
    checkedRun("python3", ["-B", "scripts/check_repository_privacy.py", "--index"], repositoryDirectory);
    const stage = join(scratch, "package");
    stagePackage(packageDirectory, stage);
    checkedRun("python3", ["-B", "scripts/check_release_privacy.py", "--directory", stage,
      "--source-root", "packages/ts"], repositoryDirectory);
    mkdirSync(output, { recursive: true });
    checkedRun("npm", ["pack", "--ignore-scripts", "--pack-destination", output], stage,
      { ...process.env, npm_config_cache: join(scratch, "cache") });
    const manifest = JSON.parse(readFileSync(join(stage, "package.json"), "utf8"));
    if (manifest.name !== "@reallyme/crypto" || !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.version)) {
      throw new PackageError("INVALID_PACKAGE_IDENTITY");
    }
    checkedRun("python3", ["-B", "scripts/check_release_privacy.py", "--archive",
      join(output, `reallyme-crypto-${manifest.version}.tgz`), "--source-root", "packages/ts", "--strip-components", "1"],
    repositoryDirectory);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`npm publication failed [${error instanceof PackageError ? error.code : "PACKAGE_IO_FAILED"}]\n`);
    process.exitCode = 1;
  }
}
