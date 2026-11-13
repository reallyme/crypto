// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ownedPath = "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs";
const strictBranch = `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`;

for (const namespace of ["serde", "::serde"]) {
  test(`protobuf hardening rejects unknown oneof fields from ${namespace} generator output`, () => {
    const root = mkdtempSync(join(tmpdir(), "crypto-proto-hardening-"));
    try {
      for (const path of ["gen", "crates/proto/src/generated", "crates/proto/proto", "packages/ts/src/proto/generated", "scripts/redact_crypto_proto_debug.mjs"]) {
        mkdirSync(dirname(join(root, path)), { recursive: true });
        cpSync(new URL(`../${path}`, import.meta.url), join(root, path), { recursive: true });
      }
      const original = readFileSync(join(root, ownedPath), "utf8");
      const schema = readFileSync(join(root, "crates/proto/proto/reallyme/crypto/v1/crypto.proto"), "utf8");
      const oneofCount = [...schema.matchAll(/\boneof\s+\w+\s*\{/gu)].length;
      assert.equal(original.split(strictBranch).length - 1, oneofCount);
      // Undo just the oneof rejection to model both supported raw-generator
      // spellings. All existing secret-field hardening must survive the pass.
      const rawBranch = strictBranch.replace(
        'return Err(serde::de::Error::custom("unknown field"));',
        `map.next_value::<${namespace}::de::IgnoredAny>()?;`,
      );
      writeFileSync(join(root, ownedPath), original.replaceAll(strictBranch, rawBranch));
      const script = join(root, "scripts/redact_crypto_proto_debug.mjs");
      const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(join(root, ownedPath), "utf8"), original);
      const stablePaths = [ownedPath,
        "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
        "gen/swift/reallyme/crypto/v1/crypto.pb.swift"];
      const past = new Date("2000-01-01T00:00:00Z");
      for (const path of stablePaths) utimesSync(join(root, path), past, past);
      const timestamps = stablePaths.map((path) => statSync(join(root, path)).mtimeMs);
      const repeated = spawnSync(process.execPath, [script, "--check-idempotent"], { encoding: "utf8" });
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.deepEqual(stablePaths.map((path) => statSync(join(root, path)).mtimeMs), timestamps,
        "idempotent verification must preserve incremental-build timestamps");

      // A partially changed template must fail closed instead of silently
      // leaving an unknown-field acceptance route in the generated decoder.
      writeFileSync(join(root, ownedPath), original.replace(strictBranch, rawBranch));
      const partial = spawnSync(process.execPath, [script], { encoding: "utf8" });
      assert.notEqual(partial.status, 0);
      assert.match(partial.stderr, new RegExp(`expected ${oneofCount} oneof unknown-field branches, found 1`, "u"));
      if (namespace === "serde") {
        // A generated owner must not retain a plain optional buffer in its
        // temporary JSON wire shape when a later field can reject decoding.
        const optionalWire = /(salt|kid):\s*::core::option::Option<\s*::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>\s*,?\s*>,/u;
        const corrupt = original.replace(optionalWire,
          "$1: ::core::option::Option<::buffa::alloc::vec::Vec<u8>>,");
        assert.notEqual(corrupt, original, "fixture must contain guarded optional bytes");
        writeFileSync(join(root, ownedPath), corrupt);
        const incomplete = spawnSync(process.execPath, [script], { encoding: "utf8" });
        assert.notEqual(incomplete.status, 0);
        assert.match(incomplete.stderr, /incomplete optional byte ownership hardening/u);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

function generatedBody(source, marker) {
  const start = source.indexOf(marker);
  assert.ok(start >= 0, `missing generated declaration ${marker}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  assert.fail("unterminated generated declaration");
}

test("optional byte fields retain native types while all generated mutation paths clear ownership", () => {
  const source = readFileSync(new URL(`../${ownedPath}`, import.meta.url), "utf8");
  const compact = (value) => value.replace(/\s+/gu, "").replace(/,>/gu, ">").replace(/,\)/gu, ")");
  for (const [name, field] of [["CryptoHkdfDeriveInputs", "salt"], ["CryptoHkdfExtractSha384Request", "salt"],
    ["CryptoHkdfDomainKey32Request", "salt"], ["CryptoJwkOptions", "kid"], ["PublicEcJwk", "kid"],
    ["PublicOkpJwk", "kid"], ["PublicAkpJwk", "kid"]]) {
    const body = compact(generatedBody(source, `pub struct ${name} {`));
    assert.ok(body.includes(`pub${field}:::core::option::Option<::buffa::alloc::vec::Vec<u8>>,`));
    const deserialize = compact(generatedBody(source, `impl<'de> ::serde::Deserialize<'de> for ${name} {`));
    assert.ok(deserialize.includes(`${field}:::core::option::Option<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>>,`));
    assert.ok(deserialize.includes(`${field}:wire.${field}.as_mut().map(|bytes|::core::mem::take(&mut**bytes))`));
    const drop = compact(generatedBody(source, `impl ::core::ops::Drop for ${name} {`));
    const message = compact(generatedBody(source, `impl ::buffa::Message for ${name} {`));
    const wipe = `::zeroize::Zeroize::zeroize(&mutself.${field});`;
    assert.ok(drop.includes(wipe));
    assert.ok(message.includes(wipe));
    assert.ok(message.includes(`crate::merge_sensitive::merge_bytes(self.${field}.get_or_insert_with(::buffa::alloc::vec::Vec::new),buf)?;`));
    assert.ok(source.includes(`impl ::zeroize::ZeroizeOnDrop for ${name} {}`));
  }
  const setter = compact(generatedBody(source, "pub fn with_salt("));
  assert.ok(setter.includes("letmutvalue=::zeroize::Zeroizing::new(value.into());"));
  assert.ok(setter.indexOf("Zeroize::zeroize") < setter.indexOf("self.salt=Some"));
});

test("transitive byte wrappers clear retained unknowns without a moving restriction", () => {
  const source = readFileSync(new URL(`../${ownedPath}`, import.meta.url), "utf8");
  const schema = readFileSync(new URL("../crates/proto/proto/reallyme/crypto/v1/crypto.proto", import.meta.url), "utf8");
  const names = new Set([...schema.matchAll(/\bmessage\s+(\w+)\s*\{/gu)].map((match) => match[1]));
  for (const name of ["PublicJwk", "PublicJwks", "PublicJwkDocument", "CryptoEcdsaInput",
    "CryptoEcdsaKeyDescriptor", "CryptoEd448KeyDescriptor", "CryptoPrimeGroupScalarDescriptor"]) {
    if (!names.has(name)) continue;
    const body = generatedBody(source, `pub struct ${name} {`);
    assert.match(body, /pub __buffa_unknown_fields: __ReallyMeZeroizingUnknownFields/u);
    assert.ok(source.includes(`impl ::zeroize::ZeroizeOnDrop for ${name} {}`));
    assert.ok(!source.includes(`impl ::core::ops::Drop for ${name} {`));
  }
  for (const name of ["CryptoRsaPssParams", "CryptoNativeKeyCapabilities", "CryptoEcdsaSignOptions",
    "CryptoEd448SupportRequest", "CryptoNativeVerificationResult", "CryptoNativeKeyGenerateRequest",
    "CryptoNativePublicKeyRequest"]) {
    if (!names.has(name)) continue;
    assert.ok(source.includes(`impl ::zeroize::ZeroizeOnDrop for ${name} {}`));
    assert.ok(source.includes(`impl<'de> ::serde::Deserialize<'de> for ${name} {`));
  }
});

test("unknown-group partial decoding keeps a clearing owner and upstream accounting", () => {
  const source = readFileSync(new URL(`../${ownedPath}`, import.meta.url), "utf8");
  const helper = generatedBody(source, "fn __reallyme_decode_unknown_field(");
  assert.match(helper, /return ::buffa::encoding::decode_unknown_field\(tag, buf, ctx\);/u);
  assert.match(helper, /ctx\.register_unknown_field\(\)\?;/u);
  assert.match(helper, /let ctx = ctx\.descend\(\)\?;/u);
  assert.match(helper, /let mut nested = __ReallyMeZeroizingUnknownFields::default\(\);/u);
  assert.match(helper, /nested\.push\(__reallyme_decode_unknown_field\(tag, buf, ctx\)\?\);/u);
  assert.match(helper, /UnknownFieldData::Group\(::core::mem::take\(&mut nested\.0\)\)/u);
  assert.doesNotMatch(helper, /UnknownFields::new/u);
  assert.match(source, /\.push\(__reallyme_decode_unknown_field\(tag, buf, ctx\)\?\)/u);
});

test("JSON byte decoding guards output and owned text before errors can discard them", () => {
  const generated = readFileSync(new URL(`../${ownedPath}`, import.meta.url), "utf8");
  assert.match(generated, /crate::deserialize_sensitive::deserialize_optional_bytes\(deserializer\)/u);
  assert.match(generated, /crate::deserialize_sensitive::deserialize_bytes\(deserializer\)/u);
  const source = readFileSync(new URL("../crates/proto/src/deserialize_sensitive.rs", import.meta.url), "utf8");
  assert.ok(source.indexOf("let mut output = Zeroizing::new(Vec::new())") <
    source.indexOf("let length = decode_into(value, output.as_mut_slice())"));
  assert.match(source, /\.checked_add\(usize::from\(has_partial\)\)/u);
  assert.match(source, /\.checked_mul\(DECODED_QUANTUM_BYTES\)/u);
  assert.match(source, /let value = Zeroizing::new\(value\);/u);
  assert.match(source, /let _value = Zeroizing::new\(value\);/u);
  assert.match(source, /with_decode_allow_trailing_bits\(true\)/u);
  assert.match(source, /DecodePaddingMode::Indifferent/u);
  assert.doesNotMatch(source, /NATIVE_TYPE|MAX_[A-Z_]*LENGTH|unwrap\(|expect\(|panic!|format!/u);
});

test("CI policy and generation modes do not launch repository tests", () => {
  // Trace the actual checker through the test-routing boundary. Child commands
  // are intercepted; only the tracked-file inventory may execute. Stop before
  // any package metadata, SDK, generation or other toolchain commands run.
  const preload = `
    import childProcess from "node:child_process";
    import { syncBuiltinESMExports } from "node:module";
    const original = childProcess.spawnSync;
    const calls = [];
    childProcess.spawnSync = (command, args, options) => {
      if (command === "git" && args.length === 2 && args[0] === "ls-files" && args[1] === "-z") {
        return original(command, args, options);
      }
      calls.push(args);
      if (args[0] === "scripts/publish_crates_in_order.mjs") {
        process.stdout.write(JSON.stringify(calls));
        process.exit(73);
      }
      return { status: 0, stdout: "", stderr: "" };
    };
    syncBuiltinESMExports();
  `;
  const checker = fileURLToPath(new URL("./check_release_readiness.mjs", import.meta.url));
  const root = fileURLToPath(new URL("../", import.meta.url));
  for (const mode of [undefined, "--release-packages", "--ci-policy", "--generated-freshness",
    "--typescript-source", "--swift-source", "--kotlin-source"]) {
    const result = spawnSync(process.execPath, ["--import",
      `data:text/javascript,${encodeURIComponent(preload)}`, checker, ...(mode === undefined ? [] : [mode])],
    { cwd: root, encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, mode);
    assert.equal(result.status, 73, result.stderr);
    const calls = JSON.parse(result.stdout);
    assert.equal(calls.filter((args) => args[0] === "--test").length,
      mode === undefined || mode === "--release-packages" ? 1 : 0, mode);
  }
});

function supplementalMetadataFixture(callback) {
  const root = mkdtempSync(join(tmpdir(), "crypto-metadata-hardening-"));
  try {
    for (const path of ["gen", "crates/proto/src/generated", "crates/proto/proto",
      "packages/ts/src/proto/generated", "scripts/redact_crypto_proto_debug.mjs"]) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      cpSync(new URL(`../${path}`, import.meta.url), join(root, path), { recursive: true });
    }
    const script = join(root, "scripts/redact_crypto_proto_debug.mjs");
    callback(root, script);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function supplementalMetadataRecords() {
  // Discover these output records from the same authoritative schemas. A new
  // numeric record must inherit the coverage without another message-name list.
  const directory = new URL("../crates/proto/proto/reallyme/crypto/v1/", import.meta.url);
  return readdirSync(directory).filter((name) => name.endsWith(".proto") && name !== "crypto.proto")
    .sort().flatMap((name) => {
      const schema = readFileSync(new URL(name, directory), "utf8");
      const basename = name.slice(0, -".proto".length);
      return [...schema.matchAll(/^message\s+(\w+)\s*\{/gmu)]
        .map((match) => ({ name: match[1], basename }));
    });
}

test("numeric metadata outside the main schema keeps guarded ownership and public moves", () => {
  const records = supplementalMetadataRecords();
  assert.ok(records.length > 0);
  for (const { name, basename } of records) {
    const stem = `../crates/proto/src/generated/buffa/reallyme.crypto.v1.${basename}`;
    const source = readFileSync(new URL(`${stem}.rs`, import.meta.url), "utf8");
    assert.match(generatedBody(source, `pub struct ${name} {`),
      /pub __buffa_unknown_fields: __ReallyMeZeroizingUnknownFields/u);
    assert.ok(source.includes(`impl ::zeroize::ZeroizeOnDrop for ${name} {}`));
    assert.ok(!source.includes(`impl ::core::ops::Drop for ${name} {`));
    const message = generatedBody(source, `impl ::buffa::Message for ${name} {`);
    assert.equal(message.split(".push(__reallyme_decode_unknown_field(tag, buf, ctx)?);").length - 1, 1);
    assert.equal(message.split("__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);").length - 1, 1);
    assert.doesNotMatch(message, /::buffa::encoding::decode_unknown_field|self\.__buffa_unknown_fields\.clear\(\)/u);
    assert.match(generatedBody(source, `impl ::core::fmt::Debug for ${name} {`), /formatter\.write_str/u);
    const view = readFileSync(new URL(`${stem}.__view.rs`, import.meta.url), "utf8");
    assert.ok(view.includes(`#[derive(Clone, Default)]\npub struct ${name}View<'a> {`));
    assert.ok(view.includes(`#[derive(Clone)]\npub struct ${name}OwnedView(`));
    assert.ok(view.includes(`formatter.write_str("${name}View(<redacted>)")`));
    assert.ok(view.includes(`formatter.write_str("${name}OwnedView(<redacted>)")`));
    assert.match(view, new RegExp(`impl<'__a> ::serde::Serialize\\s+for ${name}View<'__a>`, "u"));
    assert.match(view, new RegExp(`impl ::serde::Serialize\\s+for ${name}OwnedView`, "u"));
  }
});

test("numeric metadata regeneration is stable and preserves compiler timestamps", () => {
  supplementalMetadataFixture((root, script) => {
    const paths = [...new Set(supplementalMetadataRecords().flatMap(({ basename }) => [
      `crates/proto/src/generated/buffa/reallyme.crypto.v1.${basename}.rs`,
      `crates/proto/src/generated/buffa/reallyme.crypto.v1.${basename}.__view.rs`,
    ]))];
    const past = new Date("2000-01-01T00:00:00Z");
    for (const path of paths) utimesSync(join(root, path), past, past);
    const timestamps = paths.map((path) => statSync(join(root, path)).mtimeMs);
    const result = spawnSync(process.execPath, [script, "--check-idempotent"], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(paths.map((path) => statSync(join(root, path)).mtimeMs), timestamps);
  });
});

for (const obligation of ["merge", "clear"]) {
  test(`numeric metadata fails closed when one record loses its ${obligation} guard`, () => {
    supplementalMetadataFixture((root, script) => {
      const { name, basename } = supplementalMetadataRecords()[0];
      const path = join(root, `crates/proto/src/generated/buffa/reallyme.crypto.v1.${basename}.rs`);
      const source = readFileSync(path, "utf8");
      const body = generatedBody(source, `impl ::buffa::Message for ${name} {`);
      const original = obligation === "merge"
        ? ".push(__reallyme_decode_unknown_field(tag, buf, ctx)?);"
        : "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);";
      const corrupt = obligation === "merge"
        ? ".push(unreviewed_unknown_decoder(tag, buf, ctx)?);"
        : "unreviewed_unknown_clear(&mut self.__buffa_unknown_fields);";
      const changedBody = body.replace(original, corrupt);
      assert.notEqual(changedBody, body, "fixture must change the selected record");
      writeFileSync(path, source.replace(body, changedBody));
      const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /incomplete supplemental metadata unknown-field hardening/u);
    });
  });
}

test("supplemental numeric discovery rejects unguarded byte-bearing schema additions", () => {
  supplementalMetadataFixture((root, script) => {
    const path = join(root, "crates/proto/proto/reallyme/crypto/v1/native_options.proto");
    writeFileSync(path, `${readFileSync(path, "utf8")}\nmessage FutureByteRecord {\n  bytes payload = 1;\n}\n`);
    const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /supplemental metadata requires a numeric-only schema owner/u);
  });
});
