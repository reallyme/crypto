// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  PublishFailureCode,
  PublishRetryError,
  PublishRetryKind,
  publishWithRetries,
} from "./publish_retry_policy.mjs";

const retryAt = "Mon, 20 Jul 2026 04:00:00 GMT";
const now = Date.parse("Mon, 20 Jul 2026 03:59:00 GMT");

function result(status, stderr = "") {
  return { status, stdout: "", stderr };
}

function runSequence(results) {
  let attempts = 0;
  const retries = [];
  publishWithRetries({
    attemptPublish() {
      const next = results[Math.min(attempts, results.length - 1)];
      attempts += 1;
      return next;
    },
    sleep() {},
    onRetry(kind, delayMs, attempt) {
      retries.push({ kind, delayMs, attempt });
    },
    nowMs: () => now,
  });
  return { attempts, retries };
}

test("successful publication returns without retry", () => {
  assert.deepEqual(runSequence([result(0)]), { attempts: 1, retries: [] });
});

test("transient rate limiting retries and then succeeds", () => {
  const observed = runSequence([
    result(1, `too many requests; try again after ${retryAt}`),
    result(0),
  ]);
  assert.equal(observed.attempts, 2);
  assert.deepEqual(observed.retries, [
    { kind: PublishRetryKind.RateLimit, delayMs: 70_000, attempt: 1 },
  ]);
});

test("permanent rate limiting fails terminally", () => {
  let attempts = 0;
  assert.throws(
    () =>
      publishWithRetries({
        attemptPublish() {
          attempts += 1;
          return result(29, `too many requests; try again after ${retryAt}`);
        },
        sleep() {},
        onRetry() {},
        nowMs: () => now,
      }),
    (error) =>
      error instanceof PublishRetryError &&
      error.code === PublishFailureCode.RateLimitExhausted &&
      error.status === 29,
  );
  assert.equal(attempts, 12);
});

test("permanent registry index lag fails terminally", () => {
  let attempts = 0;
  assert.throws(
    () =>
      publishWithRetries({
        attemptPublish() {
          attempts += 1;
          return result(1, "no matching package named `reallyme-crypto-proto` found");
        },
        sleep() {},
        onRetry() {},
      }),
    (error) =>
      error instanceof PublishRetryError &&
      error.code === PublishFailureCode.IndexLagExhausted,
  );
  assert.equal(attempts, 12);
});

test("already-published output is never accepted without artifact identity proof", () => {
  assert.throws(
    () =>
      runSequence([result(1, "crate version already uploaded")]),
    (error) =>
      error instanceof PublishRetryError && error.code === PublishFailureCode.AlreadyPublished,
  );
});

test("unclassified cargo failures fail immediately", () => {
  let attempts = 0;
  assert.throws(
    () =>
      publishWithRetries({
        attemptPublish() {
          attempts += 1;
          return result(7, "publication failed");
        },
        sleep() {},
        onRetry() {},
      }),
    (error) =>
      error instanceof PublishRetryError &&
      error.code === PublishFailureCode.CargoPublishFailed &&
      error.status === 7,
  );
  assert.equal(attempts, 1);
});
