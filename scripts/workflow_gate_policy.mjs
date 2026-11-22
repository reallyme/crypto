// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Release attestation trusts the conclusion of these jobs. A skipped or
// tolerated gate can therefore turn an unverified release into a green run.
const CONDITIONAL_GATE = /^\s*(?:if|continue-on-error|"(?:if|continue-on-error)"|'(?:if|continue-on-error)')\s*:/mu;
const MASKED_FAILURE = /(?:\|\|\s*(?:true\b|:(?!\S))|\btrue\s*\|\||;\s*true\b)/u;
const STEP_START = /^\s{6}- name:/gmu;
const RUN_KEY = /^\s{8}run\s*:/mu;

export const LOCKED_DEPENDENCY_AUDIT =
  "cargo +1.100.0 deny --locked --workspace --all-features --config deny.toml check advisories licenses sources";

export const REQUIRED_WORKFLOW_GATES = [
  [".github/workflows/rust-ci.yml", [
    "python3 -B scripts/check_repository_privacy.py --index",
    'node --test --test-concurrency=4 "scripts/**/*.test.mjs" "packages/ts/scripts/*.test.mjs"',
    "actionlint -color",
    "node scripts/check_kmac_zeroization.mjs",
    "node scripts/check_aead_zeroization.mjs",
    "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
    "cargo nextest run --locked --workspace --no-default-features --features native",
    "cargo +1.100.0 test --locked --workspace --all-features",
    LOCKED_DEPENDENCY_AUDIT,
  ]],
  [".github/workflows/release-readiness.yml", [
    "node .release-readiness/scripts/run-consumer-check.mjs",
    "npm --prefix packages/ts run pack:check -- --use-built",
    "node packages/ts/scripts/browser-wasm-test.mjs",
  ]],
  [".github/workflows/dependency-security.yml", [
    "python3 scripts/gradle_runtime_lockfiles.py --check",
    "python3 scripts/verify_gradle_checksum_provenance.py",
  ]],
  [".github/workflows/protobuf-ci.yml", [
    "node scripts/run_pinned_release_readiness.mjs --generated-freshness",
  ]],
  [".github/workflows/swift-package-preflight.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
    "node scripts/run_pinned_release_readiness.mjs --swift-source",
    "run: swift test",
  ]],
  [".github/workflows/crates-package-preflight.yml", [
    "cargo publish --workspace --dry-run --locked",
  ]],
  [".github/workflows/npm-package-preflight.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
    "npm test",
    "npm run pack:check -- --use-built",
  ]],
  [".github/workflows/kotlin-android-package-preflight.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
  ]],
  [".github/workflows/crates-release.yml", [
    "node scripts/publish_crates_in_order.mjs publish",
  ]],
  [".github/workflows/npm-package-release.yml", [
    "sha256sum --check",
    "npm publish \"reallyme-crypto-${RELEASE_VERSION}.tgz\" --provenance --access public",
  ]],
  [".github/workflows/swift-package-release.yml", [
    "node scripts/verify_swift_release_artifact.mjs",
    "gh release create \"v${RELEASE_VERSION}\"",
  ]],
  [".github/workflows/kotlin-android-package-release.yml", [
    "bash scripts/promote_maven_publications.sh",
  ]],
];

export const workflowGateViolation = (source, requiredCommands) => {
  if (CONDITIONAL_GATE.test(source)) {
    return "conditional-gate";
  }

  for (const command of requiredCommands) {
    const commandIndex = source.indexOf(command);
    if (commandIndex < 0) {
      return "missing-required-command";
    }
    const starts = [...source.matchAll(STEP_START)];
    const stepIndex = starts.findLastIndex((match) => match.index <= commandIndex);
    if (stepIndex < 0) {
      return "required-command-outside-step";
    }
    const stepStart = starts[stepIndex].index;
    const stepEnd = starts[stepIndex + 1]?.index ?? source.length;
    const step = source.slice(stepStart, stepEnd);
    if (!RUN_KEY.test(step)) {
      return "required-command-outside-run";
    }
    if (MASKED_FAILURE.test(step)) {
      return "masked-required-command";
    }
  }
  return null;
};

// Release credentials belong to the verified publication step. Crates uses
// the configured registry secret; npm obtains its publishing identity via OIDC.
export const publishingCredentialViolation = (source, ecosystem) => {
  const environments = new Map([["crates", "crates-io-release"], ["npm", "npm-release"]]);
  const environment = environments.get(ecosystem);
  if (environment === undefined) return "unsupported-publishing-ecosystem";
  const lines = source.split("\n").filter((line) => !/^\s*#/u.test(line));
  const start = lines.indexOf("  publish:");
  if (start < 0) return "missing-publish-job";
  const end = lines.findIndex((line, index) => index > start && /^(?:\S| {2}\S)/u.test(line));
  const job = lines.slice(start, end < 0 ? lines.length : end).join("\n");
  if (!job.includes(`    environment: ${environment}\n`) || !job.includes("    needs: verify-release-sha\n")) {
    return "unscoped-publishing-identity";
  }
  if (CONDITIONAL_GATE.test(job)) return "conditional-publishing-step";
  if (ecosystem === "crates") {
    if (/^\s*id-token\s*:/mu.test(source) || source.includes("rust-lang/crates-io-auth-action@")) return "unexpected-crates-oidc";
    const command = "node scripts/publish_crates_in_order.mjs publish";
    const commandIndex = job.indexOf(command);
    if (commandIndex < 0 || job.lastIndexOf(command) !== commandIndex) return "missing-crates-publisher";
    const starts = [...job.matchAll(STEP_START)];
    const index = starts.findLastIndex((match) => match.index <= commandIndex);
    if (index < 0) return "unscoped-crates-token";
    const step = job.slice(starts[index].index, starts[index + 1]?.index ?? job.length);
    const binding = "          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}";
    const stepLines = step.split("\n");
    const envStart = stepLines.indexOf("        env:");
    const envEnd = stepLines.findIndex((line, position) => position > envStart && /^ {0,8}\S/u.test(line));
    const environmentLines = stepLines.slice(envStart + 1, envEnd < 0 ? stepLines.length : envEnd);
    if (envStart < 0 || !environmentLines.includes(binding) ||
        [...source.matchAll(/^\s*CARGO_REGISTRY_TOKEN\s*:/gmu)].length !== 1 ||
        [...source.matchAll(/\bsecrets\s*(?:\.|\[)/giu)].length !== 1) return "unscoped-crates-token";
  } else {
    const oidcGrants = lines.filter((line) => /^\s*id-token:\s*write\s*$/u.test(line));
    if (oidcGrants.length !== 1 || !/^ {6}id-token:\s*write\s*$/mu.test(job)) return "unscoped-oidc-permission";
    if (/\bsecrets\s*(?:\.|\[)/iu.test(source)) return "stored-publishing-secret";
    if (/^\s*(?:NODE_AUTH_TOKEN|NPM_TOKEN|registry-url)\s*:/mu.test(job)) return "legacy-npm-authentication";
    if (!job.includes("NPM_CONFIG_USERCONFIG: /dev/null") || !job.includes("--registry=https://registry.npmjs.org")) {
      return "implicit-npm-authentication";
    }
  }
  return null;
};
