// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { PortalError, uploadMavenCentralBundle } from "./upload_maven_central_bundle.mjs";

const VERSION = "0.4.6";
const DEPLOYMENT = "12345678-1234-1234-1234-123456789abc";
const environment = { CENTRAL_PORTAL_USERNAME: "fixture-user", CENTRAL_PORTAL_PASSWORD: "fixture-password" };
const published = { deploymentId: DEPLOYMENT, deploymentState: "PUBLISHED",
  purls: [`pkg:maven/me.really/crypto@${VERSION}`, `pkg:maven/me.really/crypto-android@${VERSION}`] };

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "maven-upload-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "bundle.zip");
  const bytes = Buffer.from("validated bundle bytes");
  writeFileSync(path, bytes);
  return { path, bytes };
}

const rejectsCode = (work, code) => assert.rejects(work, (error) => error instanceof PortalError && error.code === code);

test("upload sends the captured privacy-validated bytes even when the caller replaces the file", async (t) => {
  const f = fixture(t);
  const privacyCalls = [];
  let requests = 0;
  const id = await uploadMavenCentralBundle(f.path, VERSION, {
    environment,
    run(command, args, options) {
      assert.equal(command, "python3");
      assert.equal(options.timeout, 120_000);
      privacyCalls.push(args);
      if (args.includes("--archive-stdin")) {
        assert.deepEqual(options.input, f.bytes);
        assert.equal(args.at(-1), ".zip");
        writeFileSync(f.path, "unvalidated replacement");
      }
      return { status: 0 };
    },
    async request(url, options) {
      assert.equal(options.redirect, "error");
      assert.ok(options.signal instanceof AbortSignal);
      requests += 1;
      if (url.pathname.endsWith("/upload")) {
        assert.equal(url.searchParams.get("publishingType"), "AUTOMATIC");
        assert.equal(url.searchParams.get("name"), `reallyme-crypto-${VERSION}`);
        assert.deepEqual(Buffer.from(await options.body.get("bundle").arrayBuffer()), f.bytes);
        return new Response(DEPLOYMENT, { status: 201 });
      }
      assert.equal(url.searchParams.get("id"), DEPLOYMENT);
      return Response.json(published);
    },
  });
  assert.equal(id, DEPLOYMENT);
  assert.equal(requests, 2);
  assert.deepEqual(privacyCalls.map((args) => args[2]), ["--index", "--archive-stdin"]);
});

test("invalid input, credentials, files and privacy failures never send network requests", async (t) => {
  const f = fixture(t);
  const request = async () => { assert.fail("unexpected upload"); };
  const options = { environment, request, run: () => ({ status: 0 }) };
  await rejectsCode(uploadMavenCentralBundle(f.path, "not-a-version", options), "invalid-bundle-arguments");
  await rejectsCode(uploadMavenCentralBundle(f.path, VERSION, { ...options, environment: {} }), "missing-portal-credentials");
  await rejectsCode(uploadMavenCentralBundle(f.path + ".missing.zip", VERSION, options), "bundle-unavailable");
  const link = f.path + ".link.zip";
  symlinkSync(f.path, link);
  await rejectsCode(uploadMavenCentralBundle(link, VERSION, options), "bundle-unavailable");
  writeFileSync(f.path, "");
  await rejectsCode(uploadMavenCentralBundle(f.path, VERSION, options), "bundle-size-invalid");
  writeFileSync(f.path, f.bytes);
  for (const result of [{ status: 1 }, { status: null }, { status: 0, error: { code: "ETIMEDOUT" } }]) {
    await rejectsCode(uploadMavenCentralBundle(f.path, VERSION, { ...options, run: () => result }), "publication-privacy-rejected");
  }
});

for (const [response, code] of [
  [{ deploymentId: "wrong", deploymentState: "PUBLISHED" }, "portal-status-invalid"],
  [{ deploymentId: DEPLOYMENT, deploymentState: "FAILED" }, "portal-deployment-failed"],
  [{ ...published, purls: [] }, "portal-published-coordinates-mismatch"],
  [{ deploymentId: DEPLOYMENT, deploymentState: "UNKNOWN" }, "portal-deployment-state-invalid"],
]) {
  test(`upload rejects ${code}`, async (t) => {
    const f = fixture(t);
    await rejectsCode(uploadMavenCentralBundle(f.path, VERSION, {
      environment, run: () => ({ status: 0 }),
      request: async (url) => url.pathname.endsWith("/upload")
        ? new Response(DEPLOYMENT, { status: 201 }) : Response.json(response),
    }), code);
  });
}

test("pending deployments are polled without a second upload", async (t) => {
  const f = fixture(t);
  let polls = 0;
  const delays = [];
  await uploadMavenCentralBundle(f.path, VERSION, {
    environment, run: () => ({ status: 0 }), sleep: async (duration) => { delays.push(duration); },
    request: async (url) => {
      if (url.pathname.endsWith("/upload")) return new Response(DEPLOYMENT, { status: 201 });
      polls += 1;
      return Response.json(polls === 1 ? { deploymentId: DEPLOYMENT, deploymentState: "VALIDATING" } : published);
    },
  });
  assert.equal(polls, 2);
  assert.deepEqual(delays, [20_000]);
});
