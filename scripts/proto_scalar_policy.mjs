// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This module has no I/O. Every byte field needs the same clearing-owner
// guarantee, so adding a request must not require another copy of its fields.
const MAX_SCHEMA_CHARACTERS = 1_048_576;
const PUBLIC_STRING_FIELDS = new Set(["CryptoProviderCapability.provider_names"]);

export class ProtobufScalarPolicyError extends Error {
  constructor(code) {
    super("protobuf scalar policy is invalid");
    this.name = "ProtobufScalarPolicyError";
    this.code = code;
  }
}
const fail = (code) => { throw new ProtobufScalarPolicyError(code); };

function maskLiterals(source) {
  const result = [];
  let state = "code";
  let quote = "";
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index];
    const next = source[index + 1];
    if (state === "line") {
      result.push(current === "\n" ? "\n" : " ");
      if (current === "\n") state = "code";
    } else if (state === "block") {
      if (current === "*" && next === "/") {
        result.push("  "); index += 1; state = "code";
      } else result.push(current === "\n" ? "\n" : " ");
    } else if (state === "quote") {
      result.push(current === "\n" ? "\n" : " ");
      if (current === "\\" && next !== undefined) {
        result.push(next === "\n" ? "\n" : " "); index += 1;
      } else if (current === quote) state = "code";
    } else if (current === "/" && next === "/") {
      result.push("  "); index += 1; state = "line";
    } else if (current === "/" && next === "*") {
      result.push("  "); index += 1; state = "block";
    } else if (current === '"' || current === "'") {
      result.push(" "); quote = current; state = "quote";
    } else result.push(current);
  }
  if (state === "quote" || state === "block") fail("unterminated-literal");
  return result.join("");
}

/** Derive strict privacy requirements; generated-owner checks remain independent. */
export function classifyProtoScalars(source) {
  if (typeof source !== "string" || source.length > MAX_SCHEMA_CHARACTERS) fail("schema-size");
  const code = maskLiterals(source);
  const messages = new Set();
  const fields = new Set();
  const result = [];
  const messagePattern = /\bmessage\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{/gu;
  for (const match of code.matchAll(messagePattern)) {
    const message = match[1];
    if (messages.has(message)) fail("duplicate-message");
    messages.add(message);
    const open = code.indexOf("{", match.index);
    let depth = 1;
    let close = open + 1;
    while (close < code.length && depth !== 0) {
      if (code[close] === "{") depth += 1;
      else if (code[close] === "}") depth -= 1;
      close += 1;
    }
    if (depth !== 0) fail("unterminated-message");
    const body = code.slice(open + 1, close - 1);
    // Unsupported schema shapes must fail instead of silently losing ownership
    // edges. The independent upstream policy enforces the same scope.
    if (/\bmessage\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/u.test(body)) fail("nested-message");
    if (/\bmap\s*<[^>]*(?:bytes|string)[^>]*>/u.test(body)) fail("scalar-map");
    const fieldPattern = /(?:^|[;{}])\s*(?:(optional|required|repeated)\s+)?(bytes|string)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\d+(?:\s*\[[^\]]*\])?\s*(?=;)/gu;
    for (const field of body.matchAll(fieldPattern)) {
      const key = message + "." + field[3];
      if (fields.has(key)) fail("duplicate-field");
      fields.add(key);
      result.push({ message, field: field[3], kind: field[2], optional: field[1] === "optional",
        sensitivity: field[2] === "string" && PUBLIC_STRING_FIELDS.has(key) ? "public" : "sensitive" });
    }
  }
  if (messages.size === 0 || result.length === 0) fail("empty-policy");
  return result;
}

/** Extend the pinned shared validator's non-optional JSON staging checks.
 *
 * Its legacy "public" classification suppresses its scalar-shape assertion.
 * Only optional fields proven sensitive by the stricter checks below use that
 * compatibility projection; their actual privacy classification never changes.
 * The shared validator continues checking every non-optional sensitive field,
 * schema coverage, unknown-field cleanup and the other generation invariants.
 */
// Check each cleanup obligation in its own generated implementation. A wipe
// in clear() cannot compensate for a missing Drop wipe, or the reverse.
