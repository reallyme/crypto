// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Release attestation trusts the conclusion of these jobs. A skipped or
// tolerated gate can therefore turn an unverified release into a green run.
const CONDITIONAL_GATE = /^\s*(?:if|continue-on-error|"(?:if|continue-on-error)"|'(?:if|continue-on-error)')\s*:/mu;
const MASKED_FAILURE = /(?:\|\|\s*(?:true\b|:(?!\S))|\btrue\s*\|\||;\s*true\b)/u;
const STEP_START = /^\s{6}- name:/gmu;
const RUN_KEY = /^\s{8}run\s*:/mu;

export const REQUIRED_WORKFLOW_GATES = [
  [".github/workflows/rust-ci.yml", [
    "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
    "cargo nextest run --locked --workspace --no-default-features --features native",
    "cargo nextest run --locked --workspace --all-features",
    "cargo deny check",
    "node scripts/run_pinned_release_readiness.mjs",
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
  ]],
  [".github/workflows/crates-package-preflight.yml", [
    "cargo publish --workspace --dry-run --locked",
  ]],
  [".github/workflows/npm-package-preflight.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
    "npm test",
  ]],
  [".github/workflows/kotlin-android-package-preflight.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
  ]],
  [".github/workflows/crates-release.yml", [
    "node scripts/verify_release_attestation.mjs",
    "node scripts/publish_crates_in_order.mjs publish",
  ]],
  [".github/workflows/npm-package-release.yml", [
    "node scripts/run_pinned_release_readiness.mjs --release-packages",
    "npm publish \"reallyme-crypto-${RELEASE_VERSION}.tgz\" --provenance --access public",
  ]],
  [".github/workflows/swift-package-release.yml", [
    "node scripts/verify_swift_release_artifact.mjs",
    "node scripts/verify_release_attestation.mjs",
    "gh release create \"v${RELEASE_VERSION}\"",
  ]],
  [".github/workflows/kotlin-android-package-release.yml", [
    "./gradlew --dependency-verification strict publish",
    "packages/kotlin-android/gradlew --dependency-verification strict -p packages/kotlin-android publish",
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
