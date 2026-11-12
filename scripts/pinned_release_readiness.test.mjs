// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync,
  unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const runnerPath = "scripts/run_pinned_release_readiness.mjs";
const pinnedInputs = [
  { path: "scripts/check_release_readiness.mjs", maximumBytes: 524_288 },
  { path: "scripts/release-readiness/core.mjs", maximumBytes: 262_144 },
  { path: "scripts/crypto_operation_route_readiness.mjs", maximumBytes: 524_288 },
  { path: "scripts/workflow_gate_policy.mjs", maximumBytes: 524_288 },
];
// Any attempted upstream request must fail the test, even on a connected host.
const forbidNetwork = `data:text/javascript,${encodeURIComponent("globalThis.fetch = () => { process.exit(97); };")}`;

const verifyPins = (root, args = ["--check-pins"], options = {}) => {
  const { preload = forbidNetwork, ...spawnOptions } = options;
  return spawnSync(
    process.execPath,
    ["--import", preload, join(root, runnerPath), ...args],
    { cwd: root, encoding: "utf8", timeout: 10_000, ...spawnOptions },
  );
};

const localEnvironment = () => {
  const environment = { ...process.env };
  delete environment.CI;
  return environment;
};

const fixture = (context) => {
  const root = mkdtempSync(join(tmpdir(), "crypto readiness # "));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  for (const path of [runnerPath, ...pinnedInputs.map((input) => input.path)]) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    copyFileSync(join(repositoryRoot, path), join(root, path));
  }
  return root;
};

const replaceChecker = (root, source) => {
  const target = join(root, "scripts/check_release_readiness.mjs");
  const digest = createHash("sha256").update(source).digest("hex");
  writeFileSync(target, source);
  const runner = join(root, runnerPath);
  writeFileSync(runner, readFileSync(runner, "utf8").replace(
    /const LOCAL_CHECKER_SHA256 =\n  "[a-f0-9]{64}";/u,
    `const LOCAL_CHECKER_SHA256 =\n  "${digest}";`,
  ));
};

const assertRejected = (result) => {
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /^pinned release readiness failed:/u);
};

test("repository policy pins pass without fetching upstream or executing the checker", () => {
  const result = verifyPins(repositoryRoot);
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("pin-only verification never starts the checker", (context) => {
  const root = fixture(context);
  replaceChecker(root, "process.exit(79);\n");
  const result = verifyPins(root);
  assert.equal(result.status, 0, result.stderr);
});

test("full invocations use verified local inputs and preserve checker modes and status", (context) => {
  const root = fixture(context);
  replaceChecker(root, 'process.stdout.write(JSON.stringify(process.argv.slice(2))); process.exit(73);\n');
  for (const args of [[], ["--generated-freshness"], ["--release-packages"]]) {
    const result = verifyPins(root, args);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 73, result.stderr);
    assert.equal(result.stdout, JSON.stringify(args));
    assert.equal(result.stderr, "");
  }
});

test("runner resolves policy and checker working directory from its own repository", (context) => {
  const root = fixture(context);
  replaceChecker(root, "process.stdout.write(process.cwd());\n");
  const result = verifyPins(root, [], { cwd: tmpdir() });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, realpathSync(root));
  writeFileSync(join(root, pinnedInputs[1].path), "modified core\n");
  assertRejected(verifyPins(root, ["--check-pins"], { cwd: repositoryRoot }));
});

test("explicit upstream verification authenticates downloaded bytes and request policy", (context) => {
  const root = fixture(context);
  const source = `
    import { readFileSync } from "node:fs";
    globalThis.fetch = async (url, options) => {
      if (url !== "https://raw.githubusercontent.com/reallyme/release-readiness/18a6d91d99837e80f92e41fe04effb0b043d754e/core.mjs" ||
          options.redirect !== "error" || options.cache !== "no-store" ||
          !(options.signal instanceof AbortSignal)) {
        process.exit(96);
      }
      return new Response(readFileSync(${JSON.stringify(join(root, pinnedInputs[1].path))}));
    };
  `;
  const result = verifyPins(root, ["--check-pins", "--verify-upstream"], {
    preload: `data:text/javascript,${encodeURIComponent(source)}`,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
});

for (const [label, response, failure] of [
  ["unavailable upstream", "Promise.reject(new TypeError())", "could not be fetched"],
  ["unsuccessful response", 'new Response("failure", { status: 503 })', "invalid response"],
  ["missing body", "new Response(null)", "invalid response"],
  ["modified bytes", 'new Response("unreviewed core")', "digest does not match"],
  ["empty body", 'new Response("")', "core is empty"],
  ["oversized body", "new Response(new Uint8Array(262_145))", "exceeds the accepted boundary"],
  ["invalid content length", 'new Response("x", { headers: { "content-length": "-1" } })', "invalid content length"],
  ["oversized content length", 'new Response("x", { headers: { "content-length": "262145" } })', "length is outside the accepted boundary"],
  ["interrupted body", "new Response(new ReadableStream({ start(controller) { controller.error(new TypeError()); } }))", "response could not be read"],
]) {
  test(`explicit upstream verification rejects ${label}`, () => {
    const source = `globalThis.fetch = async () => ${response};`;
    const result = verifyPins(repositoryRoot, ["--check-pins", "--verify-upstream"], {
      preload: `data:text/javascript,${encodeURIComponent(source)}`,
    });
    assertRejected(result);
    assert.ok(result.stderr.includes(failure), result.stderr);
  });
}

test("explicit checker pin refresh is local, reviewable, and idempotent", (context) => {
  const root = fixture(context);
  const runner = join(root, runnerPath);
  const before = readFileSync(runner, "utf8");
  const checker = join(root, pinnedInputs[0].path);
  writeFileSync(checker, `${readFileSync(checker, "utf8")}\n// Reviewed policy change.\n`);
  assertRejected(verifyPins(root));
  const options = { env: localEnvironment() };
  const result = verifyPins(root, ["--refresh-checker-pin"], options);
  assert.equal(result.status, 0, result.stderr);
  const after = readFileSync(runner, "utf8");
  const declaration = /const LOCAL_CHECKER_SHA256 =\n  "[0-9a-f]{64}";/u;
  assert.notEqual(after, before);
  assert.equal(after.replace(declaration, ""), before.replace(declaration, ""));
  assert.equal(verifyPins(root).status, 0);
  assert.equal(verifyPins(root, ["--refresh-checker-pin"], options).status, 0);
  assert.equal(readFileSync(runner, "utf8"), after);
});

test("checker pin refresh is forbidden in CI without changing files", (context) => {
  const root = fixture(context);
  const runner = join(root, runnerPath);
  const before = readFileSync(runner, "utf8");
  for (const value of ["true", "false", ""]) {
    const result = verifyPins(root, ["--refresh-checker-pin"], {
      env: { ...process.env, CI: value },
    });
    assertRejected(result);
    assert.match(result.stderr, /forbidden in CI/u);
    assert.equal(readFileSync(runner, "utf8"), before);
  }
});

for (const { path } of pinnedInputs.slice(1)) {
  test(`checker pin refresh cannot approve a changed ${path}`, (context) => {
    const root = fixture(context);
    writeFileSync(join(root, path), "modified policy\n");
    assertRejected(verifyPins(root, ["--refresh-checker-pin"], { env: localEnvironment() }));
  });
}

for (const { path, maximumBytes } of pinnedInputs) {
  test(`rejects a stale pin for ${path}`, (context) => {
    const root = fixture(context);
    const target = join(root, path);
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// Changed policy.\n`);
    const result = verifyPins(root);
    assertRejected(result);
    assert.match(result.stderr, /does not match/u);
  });

  test(`rejects a missing ${path}`, (context) => {
    const root = fixture(context);
    unlinkSync(join(root, path));
    assertRejected(verifyPins(root));
  });

  for (const bytes of [0, maximumBytes + 1]) {
    test(`rejects ${path} with ${bytes} bytes`, (context) => {
      const root = fixture(context);
      writeFileSync(join(root, path), Buffer.alloc(bytes));
      const result = verifyPins(root);
      assertRejected(result);
      assert.match(result.stderr, /size is outside the accepted boundary/u);
    });
  }

  test(`rejects a directory replacing ${path}`, (context) => {
    const root = fixture(context);
    const target = join(root, path);
    unlinkSync(target);
    mkdirSync(target);
    const result = verifyPins(root);
    assertRejected(result);
    assert.match(result.stderr, /must be a regular file/u);
  });

  test(`rejects a symlink replacing ${path}`, { skip: process.platform === "win32" }, (context) => {
    const root = fixture(context);
    const target = join(root, path);
    copyFileSync(target, `${target}.original`);
    unlinkSync(target);
    symlinkSync(`${target}.original`, target);
    assertRejected(verifyPins(root));
  });

  test(`rejects a FIFO replacing ${path} without blocking`, { skip: process.platform === "win32" }, (context) => {
    const root = fixture(context);
    const target = join(root, path);
    unlinkSync(target);
    const created = spawnSync("mkfifo", [target], { encoding: "utf8", timeout: 5_000 });
    assert.equal(created.error, undefined);
    assert.equal(created.status, 0, created.stderr);
    assertRejected(verifyPins(root));
  });
}

for (const { path } of pinnedInputs) {
  test(`direct checker rejects changed ${path} before importing policy`, (context) => {
    const root = fixture(context);
    const target = join(root, path);
    writeFileSync(target, `${readFileSync(target, "utf8")}\nprocess.exit(94);\n`);
    const result = spawnSync(process.execPath, [join(root, pinnedInputs[0].path)], {
      cwd: root, encoding: "utf8", timeout: 10_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /policy pin verification failed/u);
  });
}

test("pin-only verification cannot be combined with a full release mode", () => {
  for (const mode of ["--generated-freshness", "--release-packages"]) {
    const result = verifyPins(repositoryRoot, ["--check-pins", mode]);
    assertRejected(result);
    assert.match(result.stderr, /cannot be combined with a full checker mode/u);
  }
});

test("runner rejects unknown, duplicate, and conflicting maintenance arguments", () => {
  for (const args of [
    ["--unknown"], ["--check-pins", "--check-pins"],
    ["--generated-freshness", "--generated-freshness"],
    ["--refresh-checker-pin", "--check-pins"],
    ["--refresh-checker-pin", "--verify-upstream"],
    ["--refresh-checker-pin", "--release-packages"],
  ]) {
    assertRejected(verifyPins(repositoryRoot, args));
  }
});

test("CI verifies policy pins before installing build tooling and dependencies", () => {
  for (const [path, laterStep] of [
    [".github/workflows/rust-ci.yml", "      - name: Install Rust toolchain"],
    [".github/workflows/protobuf-ci.yml", "      - name: Install TypeScript package dependencies"],
  ]) {
    const source = readFileSync(join(repositoryRoot, path), "utf8");
    // The Rust workflow has other jobs with their own toolchains. Restrict the
    // comparison to the job that owns the full release-readiness invocation.
    const job = path.endsWith("rust-ci.yml") ? source.slice(source.indexOf("\n  rust:\n")) : source;
    const verificationIndex = job.indexOf("        run: node scripts/run_pinned_release_readiness.mjs --check-pins");
    assert.ok(verificationIndex >= 0, path);
    assert.ok(job.indexOf(laterStep) > verificationIndex, path);
  }
});
