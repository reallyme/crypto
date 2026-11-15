// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { publicationLayout, stageMavenPublication, stageMavenPublications } from "./stage_maven_publications.mjs";

function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "reallyme-maven-bundle-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, "repo");
  const tools = join(root, "tools");
  const output = join(root, "kept bundles");
  mkdirSync(join(repo, "scripts"), { recursive: true });
  mkdirSync(tools);
  mkdirSync(output);
  if (process.platform === "darwin") {
    // Exercise the system Bash used on macOS runners, even with Homebrew Bash installed.
    symlinkSync("/bin/bash", join(tools, "bash"));
  }
  const helper = join(repo, "scripts/maven-central-bundle.local.sh");
  const calls = join(root, "gpg-calls");
  const pom = "<project>sample release</project>\n";
  writeFileSync(helper, readFileSync(new URL("./maven-central-bundle.local.sh", import.meta.url)), { mode: 0o755 });
  const executable = (path, script) => writeFileSync(path, `#!/usr/bin/env bash\nset -euo pipefail\n${script}\n`, { mode: 0o755 });
  executable(join(repo, "scripts/stage-maven-central-bundle.sh"), `
    [[ -z "\${MAVEN_SIGNING_PASSWORD:-}" && -z "\${signing_passphrase:-}" ]] || exit 1
    version="$1"
    test "$2" = "$(git rev-parse HEAD)" || exit 1
    if [[ "$BUNDLE_SCENARIO" == wrong-version ]]; then version=9.0.0; fi
    publication="$3/me/really/example/$version"
    mkdir -p -- "$publication"
    printf '%s\\n' '<project>sample release</project>' >"$publication/example-$version.pom"
    if [[ "$BUNDLE_SCENARIO" == symlink ]]; then
      ln -s /dev/null "$publication/example-$version.jar"
    else
      printf '%s\\n' 'example payload' >"$publication/example-$version.jar"
    fi
  `);
  executable(join(tools, "gpg"), `
    [[ -z "\${MAVEN_SIGNING_PASSWORD:-}" && -z "\${signing_passphrase:-}" ]] || exit 1
    if [[ " $* " == *" --verify "* ]]; then
      printf 'verify\\n' >>"$GPG_CALLS"
      test -s "\${@: -2:1}" || exit 1
      test -f "\${@: -1}" || exit 1
      if [[ "$BUNDLE_SCENARIO" == bad-signature ]]; then exit 1; fi
      exit 0
    fi
    printf 'sign\\n' >>"$GPG_CALLS"
    IFS= read -r passphrase || exit 1
    test "$passphrase" = 'fixture-only' || exit 1
    while [[ "$1" != --output ]]; do shift; done
    printf '%s\\n' 'fixture signature' >"$2"
  `);
  executable(join(tools, "zip"), `
    if [[ "$BUNDLE_SCENARIO" == zip-error ]]; then exit 1; fi
    exec "$REAL_ZIP" "$@"
  `);
  const zip = spawnSync("sh", ["-c", "command -v zip"], { encoding: "utf8" });
  assert.equal(zip.status, 0, zip.stderr);
  const git = (...args) => {
    const result = spawnSync("git", ["-c", "user.name=ReallyMe Test", "-c", "user.email=test@really.me", ...args], {
      cwd: repo, encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  const manifestPath = join(repo, "packages/kotlin/build.gradle.kts");
  mkdirSync(join(repo, "packages/kotlin"), { recursive: true });
  writeFileSync(manifestPath, 'version = "1.2.3"\n');
  git("init", "--quiet");
  git("add", "scripts", "packages");
  git("commit", "--quiet", "-m", "Maven bundle fixture");
  const sha = git("rev-parse", "HEAD");
  writeFileSync(calls, "");
  const run = (version, overrides = {}, source = sha) => spawnSync(helper, version === undefined ? [] : [version, source], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env, PATH: `${tools}${delimiter}${process.env.PATH}`,
      GPG_CALLS: calls, REAL_ZIP: zip.stdout.trim(), BUNDLE_SCENARIO: "",
      MAVEN_SIGNING_KEY_ID: "1234567890ABCDEF", MAVEN_SIGNING_PASSWORD: "fixture-only",
      MAVEN_CENTRAL_OUTPUT_DIR: output, ...overrides,
    },
  });
  return { run, output, calls, pom };
}

test("Maven bundle template verifies each signature and retains every completed ZIP", { skip: process.platform === "win32" }, (t) => {
  const { run, output, calls, pom } = fixture(t);
  const bundle = (version, suffix = "") => {
    const result = run(version);
    assert.equal(result.status, 0, result.stderr);
    const path = join(output, `reallyme-maven-central-${version}${suffix}.zip`);
    assert.equal(result.stdout.trim(), path);
    return path;
  };
  const first = bundle("1.2.3");
  const original = readFileSync(first);
  bundle("1.2.3", "-2");
  bundle("1.2.4");
  assert.deepEqual(readFileSync(first), original);
  assert.deepEqual(readdirSync(output).sort(), [
    "reallyme-maven-central-1.2.3-2.zip", "reallyme-maven-central-1.2.3.zip", "reallyme-maven-central-1.2.4.zip",
  ]);
  assert.equal(readFileSync(calls, "utf8"), "sign\nsign\nverify\nverify\n".repeat(3));
  const entry = "me/really/example/1.2.3/example-1.2.3.pom";
  const extract = (path) => {
    const result = spawnSync("unzip", ["-p", first, path], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  assert.equal(extract(entry), pom);
  assert.equal(extract(`${entry}.asc`), "fixture signature\n");
  assert.equal(extract(`${entry}.sha256`), `${createHash("sha256").update(pom).digest("hex")}\n`);
});

test("Maven bundle template preserves prior archives when staging, signing, or ZIP creation fails", { skip: process.platform === "win32" }, (t) => {
  const { run, output } = fixture(t);
  const original = join(output, "reallyme-maven-central-1.2.3.zip");
  writeFileSync(original, "previous archive");
  for (const [version, env, diagnostic, source] of [
    ["1.2.3", {}, /unchanged tracked files/u, "0".repeat(40)],
    ["1.2.3", { BUNDLE_SCENARIO: "wrong-version" }, /selected version/u],
    ["1.2.3", { BUNDLE_SCENARIO: "symlink" }, /regular files and directories/u],
    ["1.2.3", { BUNDLE_SCENARIO: "bad-signature" }, /signature failed verification/u],
    ["1.2.3", { BUNDLE_SCENARIO: "zip-error" }, /could not create the Maven Central ZIP/u],
  ]) {
    const result = run(version, env, source);
    assert.equal(result.status, 1, env.BUNDLE_SCENARIO ?? "stale source SHA");
    assert.match(result.stderr, diagnostic);
    assert.equal(result.stdout, "");
    assert.deepEqual(readdirSync(output), ["reallyme-maven-central-1.2.3.zip"]);
    assert.equal(readFileSync(original, "utf8"), "previous archive");
  }
});

test("Maven bundle without arguments selects the tracked package version and checkout", { skip: process.platform === "win32" }, (t) => {
  const { run, output } = fixture(t);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readdirSync(output), ["reallyme-maven-central-1.2.3.zip"]);
});

test("Maven staging retains only the reviewed JVM and Android coordinate files", (t) => {
  const root = mkdtempSync(join(tmpdir(), "crypto-maven-staging-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repository = join(root, "repository");
  const packages = join(root, "artifacts");
  const destination = join(root, "bundle");
  const version = "1.2.3";
  const sha = "a".repeat(40);
  const layout = publicationLayout(version, sha);
  for (const { files } of layout) {
    for (const { source } of files) {
      mkdirSync(join(repository, source, ".."), { recursive: true });
      writeFileSync(join(repository, source), source);
    }
  }
  writeFileSync(join(repository, "me/really/crypto/maven-metadata.xml"), "local metadata");
  mkdirSync(packages);
  mkdirSync(destination);
  for (const [index, kind] of ["jvm", "android"].entries()) {
    stageMavenPublication(repository, join(packages, layout[index].name), kind, version);
  }
  stageMavenPublications(packages, version, sha, destination);
  assert.deepEqual(readdirSync(join(destination, "me/really/crypto")), [version]);
  for (const { files } of layout) {
    for (const { source, target } of files) {
      assert.equal(readFileSync(join(destination, target), "utf8"), source);
    }
  }
  const android = layout[1];
  rmSync(join(packages, android.name, android.files[0].source));
  const incomplete = join(root, "incomplete");
  mkdirSync(incomplete);
  assert.throws(() => stageMavenPublications(packages, version, sha, incomplete));
});
