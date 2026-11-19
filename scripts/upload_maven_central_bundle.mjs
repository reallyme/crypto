#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PORTAL = "https://central.sonatype.com/api/v1/publisher";
const repositoryDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_BUNDLE_BYTES = 536_870_912;
const POLL_INTERVAL_MS = 20_000;
const MAX_POLLS = 180;
const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const DEPLOYMENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

class PortalError extends Error {
  constructor(code) {
    super(code);
    this.name = "PortalError";
    this.code = code;
  }
}

const fail = (code) => {
  throw new PortalError(code);
};

const main = async () => {
  const [, , bundlePath, version] = process.argv;
  const username = process.env.CENTRAL_PORTAL_USERNAME;
  const password = process.env.CENTRAL_PORTAL_PASSWORD;
  if (typeof bundlePath !== "string" || !bundlePath.endsWith(".zip") ||
      typeof version !== "string" || !VERSION_PATTERN.test(version)) {
    fail("invalid-bundle-arguments");
  }
  if (typeof username !== "string" || username.length === 0 ||
      typeof password !== "string" || password.length === 0) {
    fail("missing-portal-credentials");
  }

  let status;
  try {
    status = statSync(bundlePath);
  } catch {
    fail("bundle-unavailable");
  }
  if (!status.isFile() || status.size === 0 || status.size > MAX_BUNDLE_BYTES) {
    fail("bundle-size-invalid");
  }

  // Keep the direct uploader subject to the same policy as CI promotion.
  // Validate before constructing authentication material or sending a request.
  for (const arguments_ of [
    ["-B", "scripts/check_repository_privacy.py", "--index"],
    ["-B", "scripts/check_release_privacy.py", "--archive", resolve(bundlePath)],
  ]) {
    const privacy = spawnSync("python3", arguments_, {
      cwd: repositoryDirectory,
      stdio: "inherit",
    });
    if (privacy.status !== 0) {
      fail("publication-privacy-rejected");
    }
  }

  const authentication = Buffer.from(`${username}:${password}`, "utf8");
  const headers = { Authorization: `Bearer ${authentication.toString("base64")}` };
  authentication.fill(0);

  const uploadUrl = new URL(`${PORTAL}/upload`);
  uploadUrl.searchParams.set("publishingType", "AUTOMATIC");
  uploadUrl.searchParams.set("name", `reallyme-crypto-${version}`);
  const form = new FormData();
  form.set("bundle", new Blob([readFileSync(bundlePath)], { type: "application/octet-stream" }), basename(bundlePath));

  const upload = await fetch(uploadUrl, {
    method: "POST",
    redirect: "error",
    headers,
    body: form,
    signal: AbortSignal.timeout(120_000),
  });
  if (upload.status !== 201) {
    fail(`portal-upload-failed-${upload.status}`);
  }
  const deploymentId = (await upload.text()).trim();
  if (!DEPLOYMENT_ID_PATTERN.test(deploymentId)) {
    fail("portal-deployment-id-invalid");
  }
  console.log(`Central Portal deployment ${deploymentId} uploaded`);

  for (let poll = 0; poll < MAX_POLLS; poll += 1) {
    if (poll !== 0) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    const statusUrl = new URL(`${PORTAL}/status`);
    statusUrl.searchParams.set("id", deploymentId);
    const response = await fetch(statusUrl, {
      method: "POST",
      redirect: "error",
      headers,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      fail(`portal-status-failed-${response.status}`);
    }
    const deployment = await response.json();
    if (deployment === null || typeof deployment !== "object" || Array.isArray(deployment) ||
        deployment.deploymentId !== deploymentId || typeof deployment.deploymentState !== "string") {
      fail("portal-status-invalid");
    }
    if (deployment.deploymentState === "FAILED") {
      fail("portal-deployment-failed");
    }
    if (deployment.deploymentState === "PUBLISHED") {
      const expected = new Set([
        `pkg:maven/me.really/crypto@${version}`,
        `pkg:maven/me.really/crypto-android@${version}`,
      ]);
      if (!Array.isArray(deployment.purls) ||
          ![...expected].every((purl) => deployment.purls.includes(purl))) {
        fail("portal-published-coordinates-mismatch");
      }
      console.log(`Central Portal deployment ${deploymentId} published`);
      process.exit(0);
    }
    if (!["PENDING", "VALIDATING", "VALIDATED", "PUBLISHING"].includes(deployment.deploymentState)) {
      fail("portal-deployment-state-invalid");
    }
  }
  fail("portal-deployment-timeout");
};

try {
  await main();
} catch (error) {
  const code = error instanceof PortalError ? error.code : "portal-unexpected-failure";
  console.error(`Maven Central upload failed: ${code}`);
  process.exitCode = 1;
}
