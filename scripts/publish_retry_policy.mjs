// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export const PublishFailureCode = Object.freeze({
  AlreadyPublished: "already-published",
  CargoPublishFailed: "cargo-publish-failed",
  IndexLagExhausted: "index-lag-exhausted",
  RateLimitExhausted: "rate-limit-exhausted",
});

export const PublishRetryKind = Object.freeze({
  IndexLag: "index-lag",
  RateLimit: "rate-limit",
});

export class PublishRetryError extends Error {
  constructor(code, status) {
    super(code);
    this.name = "PublishRetryError";
    this.code = code;
    this.status = Number.isInteger(status) && status > 0 ? status : 1;
  }
}

export function retryAfterMs(output, nowMs = Date.now()) {
  const match = /try again after ([^\n.]+ GMT)/iu.exec(output);
  if (match === null) {
    return null;
  }

  const retryAt = Date.parse(match[1]);
  if (!Number.isFinite(retryAt) || !Number.isFinite(nowMs)) {
    return null;
  }

  return Math.max(retryAt - nowMs + 10_000, 10_000);
}

export function publishWithRetries({
  attemptPublish,
  sleep,
  onRetry,
  maxAttempts = 12,
  nowMs = Date.now,
}) {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const result = attemptPublish();
    const status = Number.isInteger(result.status) ? result.status : 1;
    if (status === 0) {
      return;
    }

    const stdout = typeof result.stdout === "string" ? result.stdout : "";
    const stderr = typeof result.stderr === "string" ? result.stderr : "";
    const combined = `${stdout}\n${stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      throw new PublishRetryError(PublishFailureCode.AlreadyPublished, status);
    }

    const rateLimitDelayMs = retryAfterMs(combined, nowMs());
    if (combined.toLowerCase().includes("too many requests") && rateLimitDelayMs !== null) {
      if (attempt === maxAttempts) {
        throw new PublishRetryError(PublishFailureCode.RateLimitExhausted, status);
      }
      onRetry(PublishRetryKind.RateLimit, rateLimitDelayMs, attempt);
      sleep(rateLimitDelayMs);
      continue;
    }

    if (combined.includes("no matching package named")) {
      if (attempt === maxAttempts) {
        throw new PublishRetryError(PublishFailureCode.IndexLagExhausted, status);
      }
      const delayMs = attempt * 15_000;
      onRetry(PublishRetryKind.IndexLag, delayMs, attempt);
      sleep(delayMs);
      continue;
    }

    throw new PublishRetryError(PublishFailureCode.CargoPublishFailed, status);
  }

  throw new PublishRetryError(PublishFailureCode.CargoPublishFailed, 1);
}
