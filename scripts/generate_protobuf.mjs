#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { protoGenerationPolicy } from "./proto_generation_policy.mjs";
import { normalizeSdkProtos, redactSdkProtoDebug } from "./redact_sdk_proto_debug.mjs";

export class ProtobufGenerationError extends Error {
  constructor(code) { super("protobuf generation failed"); this.name = "ProtobufGenerationError"; this.code = code; }
}
const fail = (code) => { throw new ProtobufGenerationError(code); };
const HEADER = "// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited\n//\n// SPDX-License-Identifier: MIT OR Apache-2.0\n\n";
const snake = (name) => name.replace(/([A-Z]+)([A-Z][a-z])/gu, "$1_$2").replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();
const FIXTURE_DIRECTORY = "crates/proto/tests/fixtures/guarded";
const FIXTURE_OPTIONS = ["views=true", "lazy_views=true", "json=true", "reflection=true", "zeroize=true",
  "unknown_fields=false", "deny_unknown_json_fields=true", "deny_view_json=.guarded_fixture.Child",
  "borrowed_views_only_in=.guarded_fixture.Child",
  "bytes_type_custom_in=.guarded_fixture=crate::SecretBytes", "string_type_custom_in=.guarded_fixture=crate::SecretString",
  "custom_type_impls=false", "json_policy_type=crate::SecretBytes", "json_policy_type=crate::SecretString",
  ...["Timestamp", "Duration", "Value", "Struct", "ListValue"].map((name) => `extern_path=.google.protobuf.${name}=::buffa_types::sensitive::${name}`)];

/** Native generator configuration is derived from the whole schema, never Rust output. */
export function nativeOptions(document) {
  const policy = protoGenerationPolicy(document);
  return ["views=true", "json=true", "zeroize_in=.reallyme.crypto.v1", "unknown_fields=false", "deny_unknown_json_fields=true",
    "bytes_type_custom_in=.reallyme.crypto.v1=crate::SecretBytes",
    "bytes_type_custom_in=.reallyme.crypto.v1.CryptoKeyPair.secret_key=crate::PrivateBytes",
    "string_type_custom_in=.reallyme.crypto.v1=crate::SecretString",
    "json_policy_type=crate::SecretBytes", "json_policy_type=crate::PrivateBytes", "json_policy_type=crate::SecretString",
    "extern_path=.reallyme.crypto.v1.CryptoErrorReason=crate::error_types::CryptoErrorReason",
    ...[...policy.privateNames].sort().flatMap((name) => [
      `deny_view_json=.${policy.package}.${name}`,
      `borrowed_views_only_in=.${policy.package}.${name}`,
    ])];
}

/** Expose generated bindings and guarded owners through stable package paths. */
export function publicFacade(document) {
  const policy = protoGenerationPolicy(document);
  const lines = [HEADER, "// Generated from canonical descriptors by scripts/generate_protobuf.mjs.", "pub mod reallyme {", "pub mod crypto {", "pub mod v1 {"];
  lines.push("pub use crate::error_types::CryptoErrorReason;");
  for (const { name } of policy.enums) {
    if (name !== "CryptoErrorReason") lines.push(`pub use crate::generated::raw::reallyme::crypto::v1::${name};`);
  }
  for (const { name } of policy.messages) lines.push(`pub use crate::generated::raw::reallyme::crypto::v1::${name};`);
  lines.push("pub mod __buffa {", "pub mod oneof {");
  for (const message of policy.messages.filter((entry) => (entry.oneofDecl ?? []).some((oneof) => !oneof.name.startsWith("_")))) lines.push(`pub use crate::generated::raw::reallyme::crypto::v1::__buffa::oneof::${snake(message.name)};`);
  lines.push("}", "pub mod view {", "pub mod oneof {");
  for (const message of policy.messages.filter((entry) => (entry.oneofDecl ?? []).some((oneof) => !oneof.name.startsWith("_")))) lines.push(`pub use crate::generated::raw::reallyme::crypto::v1::__buffa::view::oneof::${snake(message.name)};`);
  lines.push("}");
  for (const { name } of policy.messages) {
    lines.push(`pub use crate::generated::raw::reallyme::crypto::v1::${name}View;`);
    lines.push(policy.privateNames.has(name)
      ? `pub type ${name}OwnedView = crate::GuardedOwnedView<${name}View<'static>>;`
      : `pub use crate::generated::raw::reallyme::crypto::v1::${name}OwnedView;`);
  }
  lines.push("}", "pub use crate::generated::raw::reallyme::crypto::v1::__buffa::register_types;", "}");
  for (const { name } of policy.messages) lines.push(`pub use self::__buffa::view::{${name}View, ${name}OwnedView};`);
  lines.push("}", "}", "}", "");
  return lines.join("\n");
}

function main() {
  if (process.argv.length > 3 || (process.argv.length === 3 && process.argv[2] !== "--rust-only")) fail("arguments");
  const rustOnly = process.argv[2] === "--rust-only";
  const root = fileURLToPath(new URL("../", import.meta.url));
  const run = (program, args, input) => {
    const result = spawnSync(program, args, { cwd: root, input, encoding: "utf8", maxBuffer: 16_777_216, timeout: 60_000 });
    if (result.status !== 0 || result.error !== undefined) { if (result.stderr) process.stderr.write(result.stderr); fail("command"); }
    return result.stdout;
  };
  for (const executable of ["protoc-gen-reallyme-buffa", "protoc-gen-reallyme-buffa-packaging"]) {
    if (run(executable, ["--version"]).trim() !== `${executable} 0.1.1`) fail("generator-version");
  }
  if (run("buf", ["--version"]).trim() !== "1.75.0") fail("buf-version");
  const document = JSON.parse(run("buf", ["build", "--exclude-source-info", "--as-file-descriptor-set", "-o", "-#format=json"]));
  const policy = protoGenerationPolicy(document);
  const configPath = resolve(root, "buf.gen.yaml");
  const original = readFileSync(configPath, "utf8");
  const options = nativeOptions(document);
  const rustConfig = "  - local: protoc-gen-reallyme-buffa\n    out: crates/proto/src/generated/buffa\n    strategy: all\n    opt:\n" + options.map((option) => `      - ${option}\n`).join("") +
    "  - local: protoc-gen-reallyme-buffa-packaging\n    out: crates/proto/src/generated/buffa\n    strategy: all\n";
  const config = original.replace(/  - local: protoc-gen-(?:reallyme-)?buffa\n[\s\S]*?(?=  # TypeScript)/u, rustConfig);
  if (config === original && !original.includes(rustConfig)) fail("configuration");
  if (config !== original) writeFileSync(configPath, config);
  if (rustOnly) {
    run("buf", ["generate", "--template", JSON.stringify({ version: "v2", inputs: [{ directory: ".", exclude_types: ["reallyme.crypto.contract.v1.**"] }], plugins: [
      { local: "protoc-gen-reallyme-buffa", out: "crates/proto/src/generated/buffa", strategy: "all", opt: options },
      { local: "protoc-gen-reallyme-buffa-packaging", out: "crates/proto/src/generated/buffa", strategy: "all" },
    ] })]);
  } else run("buf", ["generate"]);
  // A separate local schema exercises imported guarded types without adding
  // them to the production descriptor or sending fixtures to hosted plugins.
  run("buf", ["generate", FIXTURE_DIRECTORY, "--template", JSON.stringify({ version: "v2", plugins: [
    { local: "protoc-gen-reallyme-buffa", out: `${FIXTURE_DIRECTORY}/generated`, strategy: "all", opt: FIXTURE_OPTIONS },
    { local: "protoc-gen-reallyme-buffa-packaging", out: `${FIXTURE_DIRECTORY}/generated`, strategy: "all" },
  ] })]);
  const facade = run("rustfmt", ["--edition", "2021", "--emit", "stdout"], publicFacade(document));
  const facadePath = resolve(root, "crates/proto/src/generated/public.rs");
  let before = "";
  try { before = readFileSync(facadePath, "utf8"); } catch (error) { if (error?.code !== "ENOENT") fail("facade-read"); }
  if (before !== facade) writeFileSync(facadePath, facade);
  run("node", ["scripts/generate_error_contract.mjs"]);
  if (!rustOnly) {
    redactSdkProtoDebug(root, policy);
    normalizeSdkProtos(root);
  }
  run("cargo", ["fmt", "--all"]);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    process.stderr.write(`protobuf generation failed: ${error instanceof ProtobufGenerationError ? error.code : "internal"}\n`);
    process.exitCode = 1;
  }
}
