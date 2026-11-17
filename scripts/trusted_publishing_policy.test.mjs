// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { trustedPublishingViolation } from "./workflow_gate_policy.mjs";

for (const [ecosystem, file, environment] of [
  ["crates", "crates-release.yml", "crates-io-release"],
  ["npm", "npm-package-release.yml", "npm-release"],
]) {
  const source = readFileSync(new URL(`../.github/workflows/${file}`, import.meta.url), "utf8");
  test(`${ecosystem} publishing uses environment-bound OIDC without stored secrets`, () => {
    assert.equal(trustedPublishingViolation(source, ecosystem), null);
  });
  for (const [name, changed] of [
    ["missing OIDC permission", source.replace("      id-token: write", "      id-token: read")],
    ["wrong environment", source.replace(`environment: ${environment}`, "environment: development")],
    ["missing verified source dependency", source.replace("    needs: verify-release-sha", "    needs: []")],
    ["a repository secret", source + "\nenv:\n  TOKEN: ${{ secrets.LEGACY_PUBLISH_TOKEN }}\n"],
    ["a bracket-access secret", source + "\nenv:\n  TOKEN: ${{ secrets['LEGACY_PUBLISH_TOKEN'] }}\n"],
    ["a duplicate OIDC grant", source.replace("permissions:\n  contents: read", "permissions:\n  contents: read\n  id-token: write")],
    ["a conditional publishing step", source.replace("      - name: Checkout\n", "      - name: Checkout\n        if: false\n")],
  ]) {
    test(`${ecosystem} trusted publishing rejects ${name}`, () => {
      assert.notEqual(trustedPublishingViolation(changed, ecosystem), null);
    });
  }
  const mutations = ecosystem === "crates" ? [
    ["an unpinned authentication action", source.replace("3268eb413133e2960fa4ae0e963ca76380c54cd9", "v1")],
    ["a literal credential", source.replace("${{ steps.crates_auth.outputs.token }}", "literal-token")],
  ] : [
    ["legacy npm environment authentication", source + "          NODE_AUTH_TOKEN: old-token\n"],
    ["ambient npm user configuration", source.replace("NPM_CONFIG_USERCONFIG: /dev/null", "NPM_CONFIG_USERCONFIG: ~/.npmrc")],
    ["an implicit registry", source.replace(" --registry=https://registry.npmjs.org", "")],
  ];
  for (const [name, changed] of mutations) {
    test(`${ecosystem} trusted publishing rejects ${name}`, () => {
      assert.notEqual(trustedPublishingViolation(changed, ecosystem), null);
    });
  }
}

test("crypto dependencies preserve their reviewed exact releases", () => {
  for (const path of ["Package.swift", "crates/conformance/platform/swift/Package.swift"]) {
    const manifest = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
    assert.match(manifest, /url: "https:\/\/github.com\/reallyme\/CSecp256k1",\s*exact: "0\.1\.0"/u);
    assert.match(manifest, /url: "https:\/\/github.com\/leif-ibsen\/Digest",\s*exact: "1\.13\.0"/u);
  }
  assert.match(readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8"), /^slh-dsa = "=0\.2\.0-rc\.5"$/mu);
});
