// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { publishingCredentialViolation } from "./workflow_gate_policy.mjs";

for (const [ecosystem, file, environment] of [
  ["crates", "crates-release.yml", "crates-io-release"],
  ["npm", "npm-package-release.yml", "npm-release"],
]) {
  const source = readFileSync(new URL(`../.github/workflows/${file}`, import.meta.url), "utf8");
  test(`${ecosystem} publishing uses its reviewed credential source inside the release environment`, () => {
    assert.equal(publishingCredentialViolation(source, ecosystem), null);
  });
  for (const [name, changed] of [
    ["wrong environment", source.replace(`environment: ${environment}`, "environment: development")],
    ["missing verified source dependency", source.replace("    needs: verify-release-sha", "    needs: []")],
    ["a repository secret", source + "\nenv:\n  TOKEN: ${{ secrets.LEGACY_PUBLISH_TOKEN }}\n"],
    ["a bracket-access secret", source + "\nenv:\n  TOKEN: ${{ secrets['LEGACY_PUBLISH_TOKEN'] }}\n"],
    ["a workflow-level OIDC grant", source.replace("permissions:\n  contents: read", "permissions:\n  contents: read\n  id-token: write")],
    ["a conditional publishing step", source.replace("      - name: Checkout\n", "      - name: Checkout\n        if: false\n")],
  ]) {
    test(`${ecosystem} publishing rejects ${name}`, () => {
      assert.notEqual(publishingCredentialViolation(changed, ecosystem), null);
    });
  }
  const mutations = ecosystem === "crates" ? [
    ["an OIDC authentication action", source.replace("      - name: Publish crates in dependency order", "      - name: Authenticate\n        uses: rust-lang/crates-io-auth-action@v1\n\n      - name: Publish crates in dependency order")],
    ["an unnecessary job OIDC permission", source.replace("    permissions:\n      actions: read\n      contents: read", "    permissions:\n      actions: read\n      contents: read\n      id-token: write")],
    ["a literal credential", source.replace("${{ secrets.CARGO_REGISTRY_TOKEN }}", "literal-token")],
    ["an authentication-action output", source.replace("${{ secrets.CARGO_REGISTRY_TOKEN }}", "${{ steps.crates_auth.outputs.token }}")],
    ["an alternate stored credential", source.replace("secrets.CARGO_REGISTRY_TOKEN", "secrets.LEGACY_PUBLISH_TOKEN")],
    ["a token bound to a preparation step", source.replace("          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n", "").replace("      - name: Checkout\n", "      - name: Checkout\n        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n")],
    ["a token expanded into the shell script", source.replace("        run: |", "        run: |\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}").replace("        env:\n          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}", "        env:")],
    ["a duplicate registry-token binding", source + "\nenv:\n  CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}\n"],
  ] : [
    ["missing OIDC permission", source.replace("      id-token: write", "      id-token: read")],
    ["legacy npm environment authentication", source + "          NODE_AUTH_TOKEN: old-token\n"],
    ["ambient npm user configuration", source.replace("NPM_CONFIG_USERCONFIG: /dev/null", "NPM_CONFIG_USERCONFIG: ~/.npmrc")],
    ["an implicit registry", source.replace(" --registry=https://registry.npmjs.org", "")],
  ];
  for (const [name, changed] of mutations) {
    test(`${ecosystem} publishing rejects ${name}`, () => {
      assert.notEqual(publishingCredentialViolation(changed, ecosystem), null);
    });
  }
}

test("crates publishing fails before invoking Cargo when its token is absent and propagates publish failures", () => {
  const source = readFileSync(new URL("../.github/workflows/crates-release.yml", import.meta.url), "utf8");
  const match = /^      - name: Publish crates in dependency order\n        run: \|\n([\s\S]*?)^        env:/mu.exec(source);
  assert.notEqual(match, null);
  const script = match[1].split("\n").map((line) => line.slice(10)).join("\n");
  const invoke = (environment, status) => spawnSync("bash", ["--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
    `node() { printf '%s\\n' publisher-invoked; return ${status}; }\n${script}`,
  ], { encoding: "utf8", env: { PATH: process.env.PATH, ...environment }, timeout: 10_000 });
  const absent = invoke({}, 0);
  assert.equal(absent.status, 1);
  assert.doesNotMatch(absent.stdout, /publisher-invoked/u);
  const present = invoke({ CARGO_REGISTRY_TOKEN: "fixture-only" }, 0);
  assert.equal(present.status, 0, present.stderr);
  assert.match(present.stdout, /publisher-invoked/u);
  assert.doesNotMatch(present.stdout + present.stderr, /fixture-only/u);
  assert.equal(invoke({ CARGO_REGISTRY_TOKEN: "fixture-only" }, 73).status, 73);
});

test("crypto dependencies preserve their reviewed exact releases", () => {
  for (const path of ["Package.swift", "crates/conformance/platform/swift/Package.swift"]) {
    const manifest = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
    assert.match(manifest, /url: "https:\/\/github.com\/reallyme\/CSecp256k1",\s*exact: "0\.1\.0"/u);
    assert.match(manifest, /url: "https:\/\/github.com\/leif-ibsen\/Digest",\s*exact: "1\.13\.0"/u);
  }
  assert.match(readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8"), /^slh-dsa = "=0\.2\.0-rc\.5"$/mu);
});
