#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

const rustGeneratedPath = join(
  root,
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
);
const rustGeneratedViewPath = join(
  root,
  "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
);

const protoPath = join(
  root,
  "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
);
const protoSource = readFileSync(protoPath, "utf8");
const supportedArguments = new Set(["--check-idempotent"]);
const suppliedArguments = new Set();
const byteFieldNames = new Set();
const byteBearingMessageNames = [];
const messageBodies = new Map();
const sensitiveStringFieldNames = new Set(["authentication_prompt"]);
// Ignore comments and quoted values before following schema ownership edges.
// Empty one-line messages and nested oneofs must retain their real braces.
function schemaCode(source) {
  const masked = [];
  let state = "code";
  let quote = "";
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (state === "line") {
      masked.push(char === "\n" ? "\n" : " ");
      if (char === "\n") state = "code";
    } else if (state === "block") {
      if (char === "*" && next === "/") {
        masked.push("  "); index += 1; state = "code";
      } else masked.push(char === "\n" ? "\n" : " ");
    } else if (state === "quote") {
      masked.push(char === "\n" ? "\n" : " ");
      if (char === "\\" && next !== undefined) {
        masked.push(next === "\n" ? "\n" : " "); index += 1;
      } else if (char === quote) state = "code";
    } else if (char === "/" && next === "/") {
      masked.push("  "); index += 1; state = "line";
    } else if (char === "/" && next === "*") {
      masked.push("  "); index += 1; state = "block";
    } else if (char === '"' || char === "'") {
      masked.push(" "); quote = char; state = "quote";
    } else masked.push(char);
  }
  if (state === "block" || state === "quote") fail("unterminated schema literal");
  return masked.join("");
}
const protoCode = schemaCode(protoSource);
const messagePattern = /\bmessage\s+(\w+)\s*\{/gu;
const oneofCount = [...protoCode.matchAll(/\boneof\s+\w+\s*\{/gu)].length;
for (const match of protoCode.matchAll(messagePattern)) {
  const messageName = match[1];
  const open = protoCode.indexOf("{", match.index);
  const close = findMatchingBrace(protoCode, open);
  const body = protoCode.slice(open + 1, close);
  if (messageBodies.has(messageName)) fail("ambiguous schema message name");
  messageBodies.set(messageName, body);
  const fields = [...body.matchAll(/\bbytes\s+(\w+)\s*=/gu)];
  if (fields.length === 0) continue;
  byteBearingMessageNames.push(messageName);
  for (const field of fields) byteFieldNames.add(field[1]);
}
const messageNames = [...messageBodies.keys()];
// Supplemental schemas contain descriptive numeric records, never secret byte
// DTOs or executable requests. Discover their records from the schema itself so
// unknown-field ownership cannot depend on a second list of message names.
const supplementalSchemas = readdirSync(dirname(protoPath), { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".proto") && entry.name !== "crypto.proto")
  .map((entry) => {
    const code = schemaCode(readFileSync(join(dirname(protoPath), entry.name), "utf8"));
    const messages = [...code.matchAll(messagePattern)].map((match) => {
      const open = code.indexOf("{", match.index);
      const close = findMatchingBrace(code, open);
      return { name: match[1], body: code.slice(open + 1, close) };
    });
    return { basename: entry.name.slice(0, -".proto".length), code, messages };
  })
  .sort((left, right) => left.basename.localeCompare(right.basename));
const supplementalMessageNames = supplementalSchemas.flatMap((schema) =>
  schema.messages.map((message) => message.name));
const allMessageNames = [...messageNames, ...supplementalMessageNames];
if (new Set(allMessageNames).size !== allMessageNames.length) {
  fail("ambiguous supplemental metadata message name");
}
const numericMetadataTypes = new Set([
  "bool", "double", "fixed32", "fixed64", "float", "int32", "int64",
  "sfixed32", "sfixed64", "sint32", "sint64", "uint32", "uint64",
  ...supplementalMessageNames,
  ...[protoCode, ...supplementalSchemas.map((schema) => schema.code)]
    .flatMap((code) => [...code.matchAll(/\benum\s+(\w+)\s*\{/gu)].map((match) => match[1])),
]);
for (const schema of supplementalSchemas) {
  for (const { body } of schema.messages) {
    // Byte/string DTOs belong to crypto.proto, where all mutation and JSON wire
    // paths have their own guards. Do not silently apply numeric-only handling
    // when a future supplemental record acquires a different owner model.
    const fields = [...body.matchAll(
      /^\s*(?:(?:optional|required|repeated)\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+[A-Za-z_][A-Za-z0-9_]*\s*=/gmu,
    )];
    if (/\b(?:oneof|map|message)\b/u.test(body) || fields.length === 0 ||
        fields.some((field) => !numericMetadataTypes.has(field[1].split(".").at(-1)))) {
      fail("supplemental metadata requires a numeric-only schema owner");
    }
  }
}
const supplementalMetadataSchemas = supplementalSchemas.filter((schema) => schema.messages.length > 0)
  .map((schema) => ({ ...schema,
    rustPath: join(root, `crates/proto/src/generated/buffa/reallyme.crypto.v1.${schema.basename}.rs`),
    viewPath: join(root, `crates/proto/src/generated/buffa/reallyme.crypto.v1.${schema.basename}.__view.rs`),
    swiftPath: join(root, `gen/swift/reallyme/crypto/v1/${schema.basename}.pb.swift`),
  }));

const scalarMetadataMessageNames = new Set([
  "ProviderDecision",
  "ProviderDecisionRequest",
  "ProviderDecisionResult",
  "CryptoKeyAlgorithmIdentifier",
  "CryptoEcdsaCurveIdentifier",
  "CryptoPrimeGroupIdentifier",
  "CryptoHkdfSuiteIdentifier",
  "CryptoPbkdf2PrfIdentifier",
  "CryptoArgon2idProfileIdentifier",
  "CryptoRsaHashIdentifier",
  "CryptoRsaPublicKeyDerEncodingIdentifier",
]);
// Standalone contracts may be introduced independently of executable requests.
// Register their scalar/empty owners only when present in this schema revision.
for (const name of [
  "CryptoRandomBytesRequest",
  "CryptoConstantTimeCompareResult",
  "CryptoConstantTimeRequireEqualResult",
  "CryptoHpkeP256BaseRecipientGenerateRequest",
  "CryptoRsaPssParams",
  "CryptoNativeKeyCapabilities",
  "CryptoEcdsaSignOptions",
  "CryptoEd448SupportRequest",
  "CryptoNativeVerificationResult",
  "CryptoNativeKeyGenerateRequest",
  "CryptoNativePublicKeyRequest",
  "HpkeSuiteIdentifier",
  "CryptoHpkePskReceiverSetupResult",
  "CryptoHpkeP256BaseCapabilities",
  "CryptoHpkeComponentCapability",
  "CryptoP256CompressedPublicKeyRequest",
  "CryptoGenerateMultikeyKeypairRequest",
  "CryptoVerificationMethodMultikeyResult",
  "CryptoArgon2PlatformResolveRequest",
  "CryptoArgon2BudgetFitRequest",
  "CryptoArgon2MobileUnlockRequest",
  "CryptoMaterialPolicyQueryRequest",
  "CryptoRandomFillPolicyQueryRequest",
]) {
  if (messageBodies.has(name)) scalarMetadataMessageNames.add(name);
}
const sensitiveMessageNames = new Set([
  ...byteBearingMessageNames,
  ...scalarMetadataMessageNames,
]);
for (const [messageName, body] of messageBodies) {
  for (const fieldName of sensitiveStringFieldNames) {
    if (new RegExp(`\\bstring\\s+${fieldName}\\s*=`, "u").test(body)) {
      sensitiveMessageNames.add(messageName);
    }
  }
}

// Debug renderers in SwiftProtobuf and protobuf-javalite recursively traverse
// nested messages. Marking only direct byte owners therefore still exposes a
// private key or plaintext when its operation wrapper is logged. Compute the
// transitive sensitive-owner closure from the schema so new wrapper messages
// inherit redaction without another hand-maintained exception.
let addedSensitiveOwner = true;
while (addedSensitiveOwner) {
  addedSensitiveOwner = false;
  for (const [messageName, body] of messageBodies) {
    if (sensitiveMessageNames.has(messageName)) {
      continue;
    }
    const fieldTypes = [
      ...body.matchAll(
        /^\s*(?:(?:optional|required|repeated)\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s+[A-Za-z_][A-Za-z0-9_]*\s*=/gmu,
      ),
    ].map((field) => field[1].split(".").at(-1));
    if (fieldTypes.some((fieldType) => sensitiveMessageNames.has(fieldType))) {
      sensitiveMessageNames.add(messageName);
      addedSensitiveOwner = true;
    }
  }
}
const redactedMessageNames = messageNames.filter((messageName) =>
  sensitiveMessageNames.has(messageName),
);
const unknownFieldDropOwnerNames = new Set([
  ...byteBearingMessageNames,
  // Key metadata has no secret fields, but rejected unknown fields can still
  // retain caller-owned bytes and must be cleared with the decoded owner.
  ...scalarMetadataMessageNames,
]);
// Wrappers retain child owners and receive guarded unknown storage instead of
// a struct Drop, so generated oneof/default field transfers remain legal.
const wrappedUnknownFieldOwnerNames = new Set(redactedMessageNames.filter(
  (name) => !unknownFieldDropOwnerNames.has(name),
));

function fail(message) {
  console.error(`generated crypto proto hardening failed: ${message}`);
  process.exit(1);
}

for (const argument of process.argv.slice(2)) {
  if (!supportedArguments.has(argument)) {
    fail(`unsupported argument ${argument}`);
  }
  if (suppliedArguments.has(argument)) {
    fail(`argument ${argument} was specified more than once`);
  }
  suppliedArguments.add(argument);
}
const checkIdempotent = suppliedArguments.has("--check-idempotent");

function writeGeneratedIfChanged(path, source) {
  // Validation must not invalidate compiler caches for byte-identical input.
  // Regenerated files still receive every hardening transformation below.
  if (readFileSync(path, "utf8") !== source) {
    writeFileSync(path, source);
  }
}

function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  fail(`missing matching brace after byte offset ${openIndex}`);
}

const sensitiveViewSerializationError =
  "serialization of sensitive protobuf views is disabled";

function disableViewSerialization(
  source,
  typeName,
  implPattern,
  canonicalImplHeader,
  docMarker,
) {
  const implMatch = source.match(implPattern);
  const implIndex = implMatch?.index ?? -1;
  if (implIndex < 0 || implMatch === null) {
    fail(`${rustGeneratedViewPath} is missing Serialize for ${typeName}`);
  }

  const openBraceIndex = source.indexOf(
    "{",
    implIndex + implMatch[0].length - 1,
  );
  if (openBraceIndex < 0) {
    fail(`${rustGeneratedViewPath} has an incomplete Serialize impl for ${typeName}`);
  }
  const closeBraceIndex = findMatchingBrace(source, openBraceIndex);
  const existingImpl = source.slice(implIndex, closeBraceIndex + 1);
  if (existingImpl.includes(sensitiveViewSerializationError)) {
    return source;
  }

  let replacementStart = implIndex;
  let documentation = "";
  if (docMarker !== null) {
    const docIndex = source.lastIndexOf(docMarker, implIndex);
    if (
      docIndex < 0 ||
      !source.slice(docIndex, implIndex).includes("Use the owned message type")
    ) {
      fail(`${rustGeneratedViewPath} is missing Serialize documentation for ${typeName}`);
    }
    replacementStart = docIndex;
    documentation = `/// Serialization is disabled because this generated view can contain\n/// sensitive or privacy-bearing bytes. Use only a policy-approved owned\n/// message at an explicit ProtoJSON boundary.\n`;
  }

  const hardenedImpl = `${documentation}${canonicalImplHeader}\n    fn serialize<__S: ::serde::Serializer>(\n        &self,\n        _serializer: __S,\n    ) -> ::core::result::Result<__S::Ok, __S::Error> {\n        ::core::result::Result::Err(<__S::Error as ::serde::ser::Error>::custom(\n            "${sensitiveViewSerializationError}",\n        ))\n    }\n}`;
  return `${source.slice(0, replacementStart)}${hardenedImpl}${source.slice(closeBraceIndex + 1)}`;
}

function extractSerdeValue(attrs, key) {
  const match = attrs.match(new RegExp(`${key} = "([^"]+)"`, "u"));
  return match?.[1] ?? null;
}

function extractSerdeAliases(attrs) {
  return [...attrs.matchAll(/alias = "([^"]+)"/gu)].map((match) => match[1]);
}

function parseStructFields(body) {
  const fields = [];
  const lines = body.split("\n");
  let serdeAttr = "";
  let collectingSerde = false;
  let serdeLines = [];
  let pendingField = null;

  function finishPendingField() {
    if (pendingField === null) {
      return;
    }
    const type = pendingField.typeLines
      .map((line) => line.trim())
      .join("\n                ")
      .replace(/,$/u, "");
    fields.push({
      name: pendingField.name,
      type,
      jsonName: extractSerdeValue(pendingField.serdeAttr, "rename") ?? pendingField.name,
      aliases: extractSerdeAliases(pendingField.serdeAttr),
    });
    pendingField = null;
  }

  function updateTypeDepth(field, line) {
    for (const char of line) {
      if (char === "<") {
        field.angleDepth += 1;
      } else if (char === ">") {
        field.angleDepth -= 1;
      }
    }
    if (field.angleDepth < 0) {
      fail(`invalid generated type nesting on ${field.name}`);
    }
  }

  function isFieldComplete(field, line) {
    return field.angleDepth === 0 && line.trim().endsWith(",");
  }

  for (const line of lines) {
    const trimmed = line.trim();
    if (pendingField !== null) {
      pendingField.typeLines.push(trimmed);
      updateTypeDepth(pendingField, trimmed);
      if (isFieldComplete(pendingField, trimmed)) {
        finishPendingField();
      }
      continue;
    }

    if (trimmed.startsWith("#[serde(")) {
      collectingSerde = true;
      serdeLines = [trimmed];
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join(" ");
      }
      continue;
    }

    if (collectingSerde) {
      serdeLines.push(trimmed);
      if (trimmed.endsWith(")]")) {
        collectingSerde = false;
        serdeAttr = serdeLines.join(" ");
      }
      continue;
    }

    const field = line.match(/^\s+pub\s+(\w+):\s+(.+)$/u);
    if (!field) {
      continue;
    }
    const [, name, firstTypeLine] = field;
    pendingField = {
      name,
      typeLines: [firstTypeLine],
      serdeAttr,
      angleDepth: 0,
    };
    updateTypeDepth(pendingField, firstTypeLine);
    serdeAttr = "";
    if (isFieldComplete(pendingField, firstTypeLine)) {
      finishPendingField();
    }
  }

  if (pendingField !== null) {
    fail(`unterminated generated field ${pendingField.name}`);
  }

  return fields;
}

const bytesType = "::buffa::alloc::vec::Vec<u8>";
const optionalBytesType = `::core::option::Option<${bytesType}>`;
const compactType = (field) => field.type.replace(/\s+/gu, "").replace(/,>/gu, ">");
const isRequiredByteField = (field) => compactType(field) === bytesType;
const isOptionalByteField = (field) => compactType(field) === optionalBytesType;
const isByteField = (field) => isRequiredByteField(field) || isOptionalByteField(field);

function serdeAttrForWireField(field) {
  const parts = [`rename = "${field.jsonName}"`];
  for (const alias of field.aliases) {
    parts.push(`alias = "${alias}"`);
  }

  if (isOptionalByteField(field)) {
    parts.push('deserialize_with = "deserialize_optional_zeroizing_bytes"');
  } else if (isRequiredByteField(field)) {
    parts.push('deserialize_with = "deserialize_zeroizing_bytes"');
  } else if (field.type.startsWith("::buffa::EnumValue<")) {
    parts.push('with = "::buffa::json_helpers::proto_enum"');
  } else if (compactType(field) === "::core::option::Option<u32>") {
    parts.push('with = "::buffa::json_helpers::opt_uint32"');
  } else if (field.type === "u32") {
    parts.push('with = "::buffa::json_helpers::uint32"');
  } else if (field.type === "u64") {
    parts.push('with = "::buffa::json_helpers::uint64"');
  } else if (isSensitiveStringField(field)) {
    parts.push('deserialize_with = "deserialize_zeroizing_string"');
  } else if (field.type === "::buffa::alloc::string::String") {
    parts.push('with = "::buffa::json_helpers::proto_string"');
  } else if (field.type === "bool") {
    // ProtoJSON null means the scalar default, including inside custom Wire
    // owners. A bare bool deserializer would reject a previously valid null.
    parts.push('with = "::buffa::json_helpers::proto_bool"');
  } else if (field.type.startsWith("::buffa::MessageField<")) {
    // MessageField preserves the generated optional-message representation.
  } else {
    fail(`unsupported field type ${field.type} on ${field.name}`);
  }

  return `            #[serde(${parts.join(", ")})]`;
}

function isSensitiveStringField(field) {
  return (
    field.type === "::buffa::alloc::string::String" &&
    sensitiveStringFieldNames.has(field.name)
  );
}

function wireType(field) {
  if (isOptionalByteField(field)) {
    return "::core::option::Option<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>>";
  }
  if (isRequiredByteField(field)) {
    return "::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>";
  }
  if (isSensitiveStringField(field)) {
    return "::zeroize::Zeroizing<::buffa::alloc::string::String>";
  }
  return field.type;
}

function assignmentForField(field) {
  if (isOptionalByteField(field)) {
    return `            ${field.name}: wire.${field.name}.as_mut().map(|bytes| ::core::mem::take(&mut **bytes)),`;
  }
  if (isRequiredByteField(field) || isSensitiveStringField(field)) {
    return `            ${field.name}: ::core::mem::take(&mut *wire.${field.name}),`;
  }
  return `            ${field.name}: wire.${field.name},`;
}

function implementationBody(source, marker) {
  const start = source.indexOf(marker);
  if (start < 0) fail("missing generated owner implementation");
  const open = source.indexOf("{", start);
  return source.slice(open + 1, findMatchingBrace(source, open));
}

function hardenOptionalByteSetters(source, field) {
  const marker = `pub fn with_${field.name}(`;
  let offset = 0;
  while (true) {
    const start = source.indexOf(marker, offset);
    if (start < 0) return source;
    const open = source.indexOf("{", start);
    const close = findMatchingBrace(source, open);
    const original = source.slice(open + 1, close);
    const wipe = `::zeroize::Zeroize::zeroize(&mut self.${field.name});`;
    const compact = original.replace(/\s+/gu, "");
    const take = `self.${field.name} = Some(::core::mem::take(&mut *value));`;
    if (compact.includes(take.replace(/\s+/gu, ""))) {
      if (!compact.includes(wipe.replace(/\s+/gu, "")) ||
          !compact.includes("::zeroize::Zeroizing::new(value.into())")) fail("incomplete optional byte setter hardening");
      offset = close + 1;
      continue;
    }
    if (compact !== `self.${field.name}=Some(value.into());self`) fail("unexpected optional byte setter");
    const replacement = `
        let mut value = ::zeroize::Zeroizing::new(value.into());
        ${wipe}
        ${take}
        self
    `;
    source = source.slice(0, open + 1) + replacement + source.slice(close);
    offset = open + 1 + replacement.length + 1;
  }
}

function validateOptionalByteOwner(source, messageName, fields) {
  const optional = fields.filter(isOptionalByteField);
  if (optional.length === 0) return;
  const compact = (value) => value.replace(/\s+/gu, "").replace(/,\)/gu, ")").replace(/,>/gu, ">");
  const deserialize = compact(implementationBody(source, `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`));
  const drop = compact(implementationBody(source, `impl ::core::ops::Drop for ${messageName} {`));
  const message = compact(implementationBody(source, `impl ::buffa::Message for ${messageName} {`));
  for (const field of optional) {
    const wipe = `::zeroize::Zeroize::zeroize(&mutself.${field.name});`;
    if (!deserialize.includes(`${field.name}:${wireType(field)},`) ||
        !deserialize.includes(`${field.name}:wire.${field.name}.as_mut().map(|bytes|::core::mem::take(&mut**bytes))`) ||
        !deserialize.includes("deserialize_optional_zeroizing_bytes") ||
        !drop.includes(wipe) || !message.includes(wipe) ||
        !message.includes(`crate::merge_sensitive::merge_bytes(self.${field.name}.get_or_insert_with(::buffa::alloc::vec::Vec::new),buf)?;`)) {
      fail("incomplete optional byte ownership hardening");
    }
  }
}

function hardenByteDeserializeHelpers(source, messageName) {
  const marker = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`;
  const start = source.indexOf(marker);
  if (start < 0) fail("missing generated byte deserializer");
  const open = source.indexOf("{", start);
  const close = findMatchingBrace(source, open);
  let body = source.slice(open + 1, close);
  body = body.replace(
    /::buffa::json_helpers::bytes::deserialize\(deserializer\)(?:\s*\.map\(::zeroize::Zeroizing::new\))?/gu,
    "crate::deserialize_sensitive::deserialize_bytes(deserializer)",
  );
  body = body.replaceAll(
    "::buffa::json_helpers::opt_bytes::deserialize(deserializer)",
    "crate::deserialize_sensitive::deserialize_optional_bytes(deserializer)",
  );
  if (/::buffa::json_helpers::(?:opt_)?bytes::deserialize/gu.test(body)) {
    fail("incomplete protected JSON byte decoding");
  }
  return source.slice(0, open + 1) + body + source.slice(close);
}

function deserializeImpl(messageName, fields) {
  const declared = fields.filter((field) => field.name !== "__buffa_unknown_fields");
  const wireFields = declared.map((field) => `${serdeAttrForWireField(field)}
            ${field.name}: ${wireType(field)},`).join("\n");
  const assignments = declared.map(assignmentForField).join("\n");
  const helpers = [];
  if (declared.some(isRequiredByteField)) helpers.push(`        fn deserialize_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            crate::deserialize_sensitive::deserialize_bytes(deserializer)
        }
`);
  if (declared.some(isOptionalByteField)) helpers.push(`        fn deserialize_optional_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::core::option::Option<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            // Null remains absent, while an empty string remains Some(empty).
            crate::deserialize_sensitive::deserialize_optional_bytes(deserializer)
        }
`);
  if (declared.some(isSensitiveStringField)) helpers.push(`        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_string::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }
`);
  const mutable = declared.some((field) => isByteField(field) || isSensitiveStringField(field));
  const binding = declared.length === 0 ? "_wire" : mutable ? "mut wire" : "wire";
  return `impl<'de> ::serde::Deserialize<'de> for ${messageName} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
${helpers.join("\n")}
        #[derive(Default, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
${wireFields}
        }

        let ${binding} = Wire::deserialize(deserializer)?;
        Ok(Self {
${assignments}
            __buffa_unknown_fields: Default::default(),
        })
    }
}
`;
}

function dropImpl(messageName, fields) {
  const zeroizeLines = fields
    .filter(
      (field) =>
        isByteField(field) ||
        isSensitiveStringField(field),
    )
    .map((field) => `        ::zeroize::Zeroize::zeroize(&mut self.${field.name});`)
    .join("\n");
  const zeroizePrefix = zeroizeLines.length === 0 ? "" : `${zeroizeLines}\n`;

  return `impl ::core::ops::Drop for ${messageName} {
    fn drop(&mut self) {
${zeroizePrefix}        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);
    }
}
`;
}

function hardenSensitiveOwnerDrop(source, messageName) {
  const drop = dropImpl(messageName, []);
  if (source.includes(drop)) {
    return source;
  }
  if (source.includes(`impl ::core::ops::Drop for ${messageName} {`)) {
    fail(`${messageName} contains an unexpected partial Drop hardening`);
  }
  const implMarker = `impl ${messageName} {`;
  const implIndex = source.indexOf(implMarker);
  if (implIndex < 0) {
    fail(`${rustGeneratedPath} is missing inherent impl for ${messageName}`);
  }
  return `${source.slice(0, implIndex)}${drop}${source.slice(implIndex)}`;
}

function hardenScalarMetadataDeserialize(source, messageName) {
  const deserializeMarker = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`;
  if (source.includes(deserializeMarker)) {
    const start = source.indexOf(deserializeMarker);
    const open = source.indexOf("{", start);
    const end = findMatchingBrace(source, open) + 1;
    const implementation = source.slice(start, end).replace(
      "let mut wire = Wire::deserialize(deserializer)?;",
      "let wire = Wire::deserialize(deserializer)?;",
    );
    return source.slice(0, start) + implementation + source.slice(end);
  }
  const structMarker = `pub struct ${messageName} {`;
  const structStart = source.indexOf(structMarker);
  if (structStart < 0) {
    fail(`missing scalar metadata owner ${messageName}`);
  }
  const structOpen = source.indexOf("{", structStart);
  const structEnd = findMatchingBrace(source, structOpen);
  const fields = parseStructFields(source.slice(structOpen + 1, structEnd));
  const headerStart = Math.max(0, structStart - 512);
  const header = source.slice(headerStart, structStart);
  const rawDerive = "#[derive(::serde::Serialize, ::serde::Deserialize)]";
  const deriveOffset = header.lastIndexOf(rawDerive);
  if (deriveOffset < 0) {
    fail(`unexpected scalar metadata serde derive on ${messageName}`);
  }
  const deriveIndex = headerStart + deriveOffset;
  source = source.slice(0, deriveIndex) + "#[derive(::serde::Serialize)]" +
    source.slice(deriveIndex + rawDerive.length);
  const implMarker = `impl ${messageName} {`;
  const implIndex = source.indexOf(implMarker, deriveIndex);
  if (implIndex < 0) {
    fail(`missing scalar metadata implementation ${messageName}`);
  }
  // Serde's struct-level default otherwise moves skipped unknown storage out
  // of a Drop owner. Decode through an independent wire shape instead.
  const implementation = deserializeImpl(messageName, fields).replace(
    "let mut wire = Wire::deserialize(deserializer)?;",
    "let wire = Wire::deserialize(deserializer)?;",
  );
  return source.slice(0, implIndex) + implementation +
    source.slice(implIndex);
}

function hardenUnknownFieldStorage(source, messageName) {
  const structMarker = `pub struct ${messageName} {`;
  const structStart = source.indexOf(structMarker);
  if (structStart < 0) {
    fail(`${rustGeneratedPath} is missing generated message ${messageName}`);
  }
  const structOpen = source.indexOf("{", structStart);
  const structEnd = findMatchingBrace(source, structOpen);
  const rawField = "pub __buffa_unknown_fields: ::buffa::UnknownFields,";
  const hardenedField =
    "pub __buffa_unknown_fields: __ReallyMeZeroizingUnknownFields,";
  const body = source.slice(structOpen + 1, structEnd);
  if (body.includes(hardenedField)) {
    return source;
  }
  if (!body.includes(rawField)) {
    fail(`${messageName} is missing generated unknown-field storage`);
  }
  const fieldIndex = source.indexOf(rawField, structOpen);
  return `${source.slice(0, fieldIndex)}${hardenedField}${source.slice(
    fieldIndex + rawField.length,
  )}`;
}

function hardenExistingSensitiveStringDeserialize(source, messageName) {
  const deserializeMarker = `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`;
  const deserializeStart = source.indexOf(deserializeMarker);
  if (deserializeStart < 0) {
    fail(`${rustGeneratedPath} is missing serde Deserialize impl for ${messageName}`);
  }
  const deserializeOpen = source.indexOf("{", deserializeStart);
  const deserializeEnd = findMatchingBrace(source, deserializeOpen);
  let deserializeImplSource = source.slice(deserializeStart, deserializeEnd + 1);
  const stringHelper = `        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_string::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }
`;
  if (!deserializeImplSource.includes("fn deserialize_zeroizing_string")) {
    const bytesHelperEnd = `        }

        #[derive(Default, ::serde::Deserialize)]`;
    deserializeImplSource = deserializeImplSource.replace(
      bytesHelperEnd,
      `        }

${stringHelper}
        #[derive(Default, ::serde::Deserialize)]`,
    );
  }
  deserializeImplSource = deserializeImplSource.replaceAll(
    `            #[serde(rename = "authenticationPrompt", alias = "authentication_prompt", with = "::buffa::json_helpers::proto_string")]
            authentication_prompt: ::buffa::alloc::string::String,`,
    `            #[serde(rename = "authenticationPrompt", alias = "authentication_prompt", deserialize_with = "deserialize_zeroizing_string")]
            authentication_prompt: ::zeroize::Zeroizing<::buffa::alloc::string::String>,`,
  );
  deserializeImplSource = deserializeImplSource.replaceAll(
    "            authentication_prompt: wire.authentication_prompt,",
    "            authentication_prompt: ::core::mem::take(&mut *wire.authentication_prompt),",
  );
  return `${source.slice(0, deserializeStart)}${deserializeImplSource}${source.slice(
    deserializeEnd + 1,
  )}`;
}

function hardenOwnedRust() {
  let source = readFileSync(rustGeneratedPath, "utf8");
  const generatedHeader = `// @generated by buffa-codegen. DO NOT EDIT.
// source: reallyme/crypto/v1/crypto.proto
`;
  const unknownFieldZeroizeHelpers = `
fn __reallyme_zeroize_unknown_fields(fields: &mut ::buffa::UnknownFields) {
    for mut field in ::core::mem::take(fields) {
        __reallyme_zeroize_unknown_field_data(&mut field.data);
    }
}

fn __reallyme_zeroize_unknown_field_data(data: &mut ::buffa::UnknownFieldData) {
    match data {
        ::buffa::UnknownFieldData::LengthDelimited(bytes) => {
            ::zeroize::Zeroize::zeroize(bytes);
        }
        ::buffa::UnknownFieldData::Group(fields) => {
            __reallyme_zeroize_unknown_fields(fields);
        }
        ::buffa::UnknownFieldData::Varint(_)
        | ::buffa::UnknownFieldData::Fixed64(_)
        | ::buffa::UnknownFieldData::Fixed32(_) => {}
    }
}

#[doc(hidden)]
#[derive(Clone, Default, PartialEq)]
pub struct __ReallyMeZeroizingUnknownFields(::buffa::UnknownFields);

// Unknown length-delimited fields can carry future secret-bearing schema
// values. Keep diagnostics useful without exposing those retained bytes.
impl ::core::fmt::Debug for __ReallyMeZeroizingUnknownFields {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("__ReallyMeZeroizingUnknownFields(<redacted>)")
    }
}

impl ::core::convert::From<::buffa::UnknownFields> for __ReallyMeZeroizingUnknownFields {
    fn from(fields: ::buffa::UnknownFields) -> Self {
        Self(fields)
    }
}

impl ::core::ops::Deref for __ReallyMeZeroizingUnknownFields {
    type Target = ::buffa::UnknownFields;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ::core::ops::DerefMut for __ReallyMeZeroizingUnknownFields {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ::core::ops::Drop for __ReallyMeZeroizingUnknownFields {
    fn drop(&mut self) {
        __reallyme_zeroize_unknown_fields(&mut self.0);
    }
}
`;
  const rejectSecretJsonHelper = `
fn __reallyme_reject_secret_json<S: ::serde::Serializer>(
    _secret: &::buffa::alloc::vec::Vec<u8>,
    _serializer: S,
) -> ::core::result::Result<S::Ok, S::Error> {
    ::core::result::Result::Err(<S::Error as ::serde::ser::Error>::custom(
        "ProtoJSON serialization of secret key material is disabled",
    ))
}
`;
  const guardedUnknownGroupHelper = `
// Keep partially decoded groups in a clearing owner until the closing tag is
// validated. Non-group decoding retains the upstream wire and budget logic.
fn __reallyme_decode_unknown_field(
    tag: ::buffa::encoding::Tag,
    buf: &mut impl ::buffa::bytes::Buf,
    ctx: ::buffa::DecodeContext<'_>,
) -> ::core::result::Result<::buffa::UnknownField, ::buffa::DecodeError> {
    if tag.wire_type() != ::buffa::encoding::WireType::StartGroup {
        return ::buffa::encoding::decode_unknown_field(tag, buf, ctx);
    }
    ctx.register_unknown_field()?;
    let ctx = ctx.descend()?;
    let number = tag.field_number();
    let mut nested = __ReallyMeZeroizingUnknownFields::default();
    loop {
        let tag = ::buffa::encoding::Tag::decode(buf)?;
        if tag.wire_type() == ::buffa::encoding::WireType::EndGroup {
            if tag.field_number() != number {
                return Err(::buffa::DecodeError::InvalidEndGroup(tag.field_number()));
            }
            break;
        }
        nested.push(__reallyme_decode_unknown_field(tag, buf, ctx)?);
    }
    Ok(::buffa::UnknownField {
        number,
        data: ::buffa::UnknownFieldData::Group(::core::mem::take(&mut nested.0)),
    })
}
`;
  if (!source.includes(generatedHeader)) {
    fail(`${rustGeneratedPath} is missing the generated header`);
  }
  if (!source.includes("__reallyme_zeroize_unknown_fields")) {
    source = source.replace(
      generatedHeader,
      `${generatedHeader}${unknownFieldZeroizeHelpers}`,
    );
  }
  if (!source.includes("__reallyme_reject_secret_json")) {
    source = source.replace(
      generatedHeader,
      `${generatedHeader}${rejectSecretJsonHelper}`,
    );
  }
  if (!source.includes("fn __reallyme_decode_unknown_field(")) {
    source = source.replace(generatedHeader, `${generatedHeader}${guardedUnknownGroupHelper}`);
  }
  source = source.replaceAll(
    "::buffa::encoding::decode_unknown_field(tag, buf, ctx)?",
    "__reallyme_decode_unknown_field(tag, buf, ctx)?",
  );
  for (const messageName of byteBearingMessageNames) {
    const structMarker = `pub struct ${messageName} {`;
    const structStart = source.indexOf(structMarker);
    if (structStart < 0) {
      fail(`${rustGeneratedPath} is missing generated message ${messageName}`);
    }
    const structOpen = source.indexOf("{", structStart);
    const structEnd = findMatchingBrace(source, structOpen);
    const body = source.slice(structOpen + 1, structEnd);
    const fields = parseStructFields(body);
    const sensitiveFields = fields.filter(
      (field) =>
        isByteField(field) ||
        isSensitiveStringField(field),
    );

    if (sensitiveFields.length === 0) {
      fail(`${rustGeneratedPath} message ${messageName} has no generated byte fields`);
    }

    const serdeDeriveForms = [
      {
        raw: "#[derive(::serde::Serialize, ::serde::Deserialize)]",
        hardened: "#[derive(::serde::Serialize)]",
      },
      {
        // rustfmt merges adjacent derive attributes in generated files. The
        // hardening pass must remain idempotent after that required formatter
        // step without accidentally restoring derived deserialization.
        raw: "#[derive(Clone, PartialEq, Default, ::serde::Serialize, ::serde::Deserialize)]",
        hardened: "#[derive(Clone, PartialEq, Default, ::serde::Serialize)]",
      },
    ];
    const structHeaderStart = Math.max(0, structStart - 512);
    const structHeader = source.slice(structHeaderStart, structStart);
    const rawSerdeForm = serdeDeriveForms
      .map((form) => ({ form, index: structHeader.lastIndexOf(form.raw) }))
      .filter(({ index }) => index >= 0)
      .sort((left, right) => right.index - left.index)[0] ?? null;
    const hasDrop = source.includes(`impl ::core::ops::Drop for ${messageName} {`);
    const hasDeserialize = source.includes(
      `impl<'de> ::serde::Deserialize<'de> for ${messageName} {`,
    );
    const hasHardenedSerde = serdeDeriveForms.some((form) =>
      structHeader.includes(form.hardened),
    );
    const alreadyHardened = hasHardenedSerde && hasDrop && hasDeserialize;
    if (!alreadyHardened && (hasDrop || hasDeserialize)) {
      fail(`${messageName} is only partially hardened`);
    }
    if (!alreadyHardened) {
      if (rawSerdeForm === null) {
        fail(`${messageName} is missing generated serde Deserialize derive`);
      }
      const absoluteSerdeIndex = structHeaderStart + rawSerdeForm.index;
      source =
        source.slice(0, absoluteSerdeIndex) +
        rawSerdeForm.form.hardened +
        source.slice(absoluteSerdeIndex + rawSerdeForm.form.raw.length);
    }

    for (const field of sensitiveFields) {
      source = source.replaceAll(
        `.field("${field.name}", &self.${field.name})`,
        `.field("${field.name}", &"<redacted>")`,
      );
      source = source.replaceAll(
        `        self.${field.name}.clear();`,
        `        ::zeroize::Zeroize::zeroize(&mut self.${field.name});`,
      );
      const mergeFunction = isSensitiveStringField(field) ? "merge_string" : "merge_bytes";
      source = source.replaceAll(
        `::buffa::types::${mergeFunction}(&mut self.${field.name}, buf)?;`,
        `crate::merge_sensitive::${mergeFunction}(&mut self.${field.name}, buf)?;`,
      );
      if (isOptionalByteField(field)) {
        // Clear and setters can discard an initialized optional allocation.
        // Zeroize its owner before the generated None/Some replacement.
        for (const absent of ["::core::option::Option::None", "None"]) {
          source = source.replaceAll(
            `        self.${field.name} = ${absent};`,
            `        ::zeroize::Zeroize::zeroize(&mut self.${field.name});`,
          );
        }
        const optionalMerge = new RegExp(
          `::buffa::types::merge_bytes(?=\\(\\s*self\\.${field.name}\\.get_or_insert_with\\(::buffa::alloc::vec::Vec::new\\))`,
          "gu",
        );
        source = source.replace(optionalMerge, "crate::merge_sensitive::merge_bytes");
        source = hardenOptionalByteSetters(source, field);
      }
    }

    const implMarker = `impl ${messageName} {`;
    const implIndex = source.indexOf(implMarker, structEnd);
    if (implIndex < 0) {
      fail(`${rustGeneratedPath} is missing inherent impl for ${messageName}`);
    }
    if (!alreadyHardened) {
      const inserted = `${dropImpl(messageName, fields)}${deserializeImpl(messageName, fields)}`;
      source = `${source.slice(0, implIndex)}${inserted}${source.slice(implIndex)}`;
    }
    source = hardenByteDeserializeHelpers(source, messageName);
    validateOptionalByteOwner(source, messageName, fields);
  }

  const keyPairMarker = "pub struct CryptoKeyPair {";
  const keyPairIndex = source.indexOf(keyPairMarker);
  if (keyPairIndex < 0) {
    fail("generated CryptoKeyPair is missing");
  }
  const keyPairHeaderStart = Math.max(0, keyPairIndex - 256);
  let keyPairHeader = source.slice(keyPairHeaderStart, keyPairIndex);
  if (keyPairHeader.includes("#[derive(Clone, PartialEq, Default)]")) {
    keyPairHeader = keyPairHeader.replace(
      "#[derive(Clone, PartialEq, Default)]",
      "#[derive(Clone, Default)]",
    );
    source = source.slice(0, keyPairHeaderStart) + keyPairHeader + source.slice(keyPairIndex);
  } else if (!keyPairHeader.includes("#[derive(Clone, Default)]")) {
    fail("CryptoKeyPair has an unexpected derive form");
  }
  const keyPairBodyStart = source.indexOf(keyPairMarker);
  const secretComment = "    /// Secret-bearing exportable private key material.";
  const secretStart = source.indexOf(secretComment, keyPairBodyStart);
  const secretEnd = source.indexOf("    pub secret_key:", secretStart);
  if (secretStart < 0 || secretEnd < 0) {
    fail("CryptoKeyPair secret field is missing");
  }
  const secretFieldHeader = source.slice(secretStart, secretEnd);
  const rawSecretSerializer = 'with = "::buffa::json_helpers::bytes",';
  const hardenedSecretSerializer = 'serialize_with = "__reallyme_reject_secret_json",';
  if (secretFieldHeader.includes(rawSecretSerializer)) {
    source = source.slice(0, secretStart) +
      secretFieldHeader.replace(rawSecretSerializer, hardenedSecretSerializer) +
      source.slice(secretEnd);
  } else if (!secretFieldHeader.includes(hardenedSecretSerializer)) {
    fail("CryptoKeyPair secret field has an unexpected serializer");
  }

  const keyPairEqMarker = "impl ::core::cmp::PartialEq for CryptoKeyPair {";
  if (!source.includes(keyPairEqMarker)) {
    const debugMarker = "impl ::core::fmt::Debug for CryptoKeyPair {";
    if (!source.includes(debugMarker)) {
      fail("CryptoKeyPair debug implementation is missing");
    }
    const constantTimeEquality = `${keyPairEqMarker}
    fn eq(&self, other: &Self) -> bool {
        // The key length is public for its algorithm. Compare the secret bytes
        // in constant time even when other envelope fields differ.
        let secret_equal = ::subtle::ConstantTimeEq::ct_eq(
            self.secret_key.as_slice(),
            other.secret_key.as_slice(),
        );
        bool::from(secret_equal)
            & (self.algorithm == other.algorithm)
            & (self.public_key == other.public_key)
            & (self.__buffa_unknown_fields == other.__buffa_unknown_fields)
    }
}
`;
    source = source.replace(debugMarker, `${constantTimeEquality}${debugMarker}`);
  }

  // The operation wrappers transitively own private keys, plaintext, and
  // derived material without declaring byte fields themselves. Their child
  // drops wipe declared fields; these owners must also wipe retained unknown
  // fields. Direct byte owners are hardened by the loop above.
  for (const messageName of unknownFieldDropOwnerNames) {
    if (!source.includes(`impl ::core::ops::Drop for ${messageName} {`)) {
      source = hardenSensitiveOwnerDrop(source, messageName);
    }
  }
  for (const messageName of scalarMetadataMessageNames) {
    source = hardenScalarMetadataDeserialize(source, messageName);
    const cleanupMarker = `impl ::zeroize::ZeroizeOnDrop for ${messageName} {}`;
    if (!source.includes(cleanupMarker)) {
      source = source.replace(
        `impl ${messageName} {`,
        `${cleanupMarker}\nimpl ${messageName} {`,
      );
    }
  }
  for (const messageName of wrappedUnknownFieldOwnerNames) {
    source = hardenUnknownFieldStorage(source, messageName);
  }
  // Every marked owner clears its own fields or delegates to guarded child
  // owners and guarded unknown storage. The marker never adds Clone to native
  // private-key owners; generated transport DTO copies retain their own wipes.
  for (const messageName of redactedMessageNames) {
    const cleanupMarker = `impl ::zeroize::ZeroizeOnDrop for ${messageName} {}`;
    if (!source.includes(cleanupMarker)) {
      source = source.replace(
        `impl ${messageName} {`, `${cleanupMarker}\nimpl ${messageName} {`,
      );
    }
  }
  source = hardenExistingSensitiveStringDeserialize(
    source,
    "CryptoPlatformSignatureSignRequest",
  );

  // Buffa's proto-JSON enum visitors interpolate untrusted numeric values into
  // serde errors. Fixed messages avoid reflecting boundary input into logs and
  // keep these rejection paths free of formatting allocations.
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("enum value {v} out of i32 range"),
                        )`,
    `::serde::de::Error::custom("enum value out of i32 range")`,
  );
  source = source.replaceAll(
    `::serde::de::Error::custom(
                            ::buffa::alloc::format!("unknown enum value {v32}"),
                        )`,
    `::serde::de::Error::custom("unknown enum value")`,
  );
  if (source.includes("::buffa::alloc::format!(")) {
    fail(`${rustGeneratedPath} still contains formatted proto-JSON errors`);
  }
  source = source.replaceAll(
    "        self.__buffa_unknown_fields.clear();",
    "        __reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);",
  );
  source = source.replaceAll(
    "#[serde(default)]",
    "#[serde(default, deny_unknown_fields)]",
  );
  const ignoredUnknownField = `                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }`;
  // Buffa 0.9.2 qualifies serde from the crate root. Accept that spelling
  // alongside older generated input while retaining the exact branch count.
  const qualifiedIgnoredUnknownField = ignoredUnknownField.replace(
    "::<serde::", "::<::serde::",
  );
  const ignoredUnknownFieldCount =
    source.split(ignoredUnknownField).length - 1 +
    source.split(qualifiedIgnoredUnknownField).length - 1;
  const strictUnknownField = `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`;
  const strictUnknownFieldCount = source.split(strictUnknownField).length - 1;
  if (
    ignoredUnknownFieldCount !== oneofCount &&
    !(ignoredUnknownFieldCount === 0 && strictUnknownFieldCount === oneofCount)
  ) {
    fail(
      `${rustGeneratedPath} expected ${oneofCount} oneof unknown-field branches, found ${ignoredUnknownFieldCount}`,
    );
  }
  source = source.replaceAll(ignoredUnknownField, strictUnknownField);
  source = source.replaceAll(qualifiedIgnoredUnknownField, strictUnknownField);

  writeGeneratedIfChanged(rustGeneratedPath, source);
}

function redactDebugImplementation(source, typeName, displayName = typeName) {
  const marker = `impl ::core::fmt::Debug for ${typeName} {`;
  const start = source.indexOf(marker);
  if (start < 0) fail("missing supplemental metadata Debug implementation");
  const open = source.indexOf("{", start);
  const end = findMatchingBrace(source, open) + 1;
  return source.slice(0, start) + `impl ::core::fmt::Debug for ${typeName} {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${displayName}(<redacted>)")
    }
}` + source.slice(end);
}

function hardenSupplementalMetadataRust(schema) {
  let source = readFileSync(schema.rustPath, "utf8");
  for (const { name } of schema.messages) {
    source = hardenUnknownFieldStorage(source, name);
    const marker = `impl ::zeroize::ZeroizeOnDrop for ${name} {}`;
    const inherent = `impl ${name} {`;
    if (!source.includes(marker)) {
      if (!source.includes(inherent)) fail("missing supplemental metadata implementation");
      source = source.replace(inherent, `${marker}\n${inherent}`);
    }
    if (source.includes(`impl ::core::ops::Drop for ${name} {`)) {
      fail("supplemental metadata must preserve public field moves");
    }
    const messageMarker = `impl ::buffa::Message for ${name} {`;
    const start = source.indexOf(messageMarker);
    if (start < 0) fail("missing supplemental metadata Message implementation");
    const open = source.indexOf("{", start);
    const end = findMatchingBrace(source, open) + 1;
    let implementation = source.slice(start, end);
    const rawDecode = ".push(::buffa::encoding::decode_unknown_field(tag, buf, ctx)?);";
    const guardedDecode = ".push(__reallyme_decode_unknown_field(tag, buf, ctx)?);";
    const rawClear = "self.__buffa_unknown_fields.clear();";
    const guardedClear = "__reallyme_zeroize_unknown_fields(&mut self.__buffa_unknown_fields);";
    const occurrences = (value) => implementation.split(value).length - 1;
    // Check each generated record independently. A marker or another record's
    // safe implementation cannot satisfy the missing merge/clear obligation.
    if (occurrences(rawDecode) + occurrences(guardedDecode) !== 1 ||
        occurrences(rawClear) + occurrences(guardedClear) !== 1) {
      fail("incomplete supplemental metadata unknown-field hardening");
    }
    implementation = implementation.replace(rawDecode, guardedDecode).replace(rawClear, guardedClear);
    source = source.slice(0, start) + implementation + source.slice(end);
    source = redactDebugImplementation(source, name);
  }
  // All package files are included into the same module. Reuse the private
  // guarded group decoder and clearing owner defined in crypto.rs, rather than
  // duplicating them or widening their visibility across module boundaries.
  writeGeneratedIfChanged(schema.rustPath, source);
}

function hardenSupplementalMetadataView(schema) {
  let source = readFileSync(schema.viewPath, "utf8");
  for (const { name } of schema.messages) {
    const viewName = `${name}View`;
    const rawView = `#[derive(Clone, Debug, Default)]\npub struct ${viewName}<'a> {`;
    const guardedView = `#[derive(Clone, Default)]\npub struct ${viewName}<'a> {`;
    if (source.includes(rawView)) source = source.replace(rawView, guardedView);
    else if (!source.includes(guardedView)) fail("missing supplemental metadata view");
    const viewDebug = `impl ::core::fmt::Debug for ${viewName}<'_> {`;
    if (!source.includes(viewDebug)) {
      const viewMessage = new RegExp(`impl<'a> ::buffa::MessageView<'a>\\s+for ${viewName}<'a> \\{`, "u");
      if (!viewMessage.test(source)) fail("missing supplemental metadata MessageView");
      source = source.replace(viewMessage, (marker) => `${viewDebug}
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${viewName}(<redacted>)")
    }
}
${marker}`);
    }
    const ownedName = `${name}OwnedView`;
    const rawOwned = `#[derive(Clone, Debug)]\npub struct ${ownedName}(`;
    const guardedOwned = `#[derive(Clone)]\npub struct ${ownedName}(`;
    if (source.includes(rawOwned)) source = source.replace(rawOwned, guardedOwned);
    else if (!source.includes(guardedOwned)) fail("missing supplemental metadata owned view");
    const ownedDebug = `impl ::core::fmt::Debug for ${ownedName} {`;
    if (!source.includes(ownedDebug)) {
      const inherent = `impl ${ownedName} {`;
      if (!source.includes(inherent)) fail("missing supplemental metadata owned view implementation");
      source = source.replace(inherent, `${ownedDebug}
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${ownedName}(<redacted>)")
    }
}
${inherent}`);
    }
    source = redactDebugImplementation(source, `${viewName}<'_>`, viewName);
    source = redactDebugImplementation(source, ownedName);
    // These views expose public numeric metadata. Keep their existing Clone
    // and protobuf JSON implementations; only debug rendering is redacted.
  }
  writeGeneratedIfChanged(schema.viewPath, source);
}

function hardenViewRust() {
  let source = readFileSync(rustGeneratedViewPath, "utf8");

  for (const messageName of redactedMessageNames) {
    const viewName = `${messageName}View`;
    const deriveAndStruct = `#[derive(Clone, Debug, Default)]
pub struct ${viewName}<'a> {`;
    const hardenedDeriveAndStruct = `#[derive(Clone, Default)]
pub struct ${viewName}<'a> {`;
    if (source.includes(deriveAndStruct)) {
      source = source.replace(deriveAndStruct, hardenedDeriveAndStruct);
    } else if (!source.includes(hardenedDeriveAndStruct)) {
      fail(`${rustGeneratedViewPath} is missing ${viewName}`);
    }

    const messageViewPattern = new RegExp(
      `impl<'a> ::buffa::MessageView<'a>\\s+for ${viewName}<'a> \\{`,
      "u",
    );
    const redactedViewDebug = `impl ::core::fmt::Debug for ${viewName}<'_> {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${viewName}(<redacted>)")
    }
}
`;
    if (!messageViewPattern.test(source)) {
      fail(`${rustGeneratedViewPath} is missing MessageView for ${viewName}`);
    }
    if (!source.includes(`formatter.write_str("${viewName}(<redacted>)")`)) {
      source = source.replace(
        messageViewPattern,
        (messageViewImpl) => `${redactedViewDebug}${messageViewImpl}`,
      );
    }

    source = disableViewSerialization(
      source,
      viewName,
      new RegExp(
        `impl<'__a> ::serde::Serialize\\s+for ${viewName}<'__a> \\{`,
        "u",
      ),
      `impl<'__a> ::serde::Serialize for ${viewName}<'__a> {`,
      "/// Serializes this view as protobuf JSON.",
    );

    const ownedViewName = `${messageName}OwnedView`;
    const ownedDeriveAndStruct = `#[derive(Clone, Debug)]
pub struct ${ownedViewName}(`;
    const previouslyHardenedOwnedDeriveAndStruct = `#[derive(Clone)]
pub struct ${ownedViewName}(`;
    const hardenedOwnedDeriveAndStruct = `pub struct ${ownedViewName}(`;
    if (source.includes(ownedDeriveAndStruct)) {
      source = source.replace(ownedDeriveAndStruct, hardenedOwnedDeriveAndStruct);
    } else if (source.includes(previouslyHardenedOwnedDeriveAndStruct)) {
      source = source.replace(
        previouslyHardenedOwnedDeriveAndStruct,
        hardenedOwnedDeriveAndStruct,
      );
    } else if (!source.includes(hardenedOwnedDeriveAndStruct)) {
      fail(`${rustGeneratedViewPath} is missing ${ownedViewName}`);
    }

    const ownedImpl = `impl ${ownedViewName} {`;
    const redactedOwnedDebug = `impl ::core::fmt::Debug for ${ownedViewName} {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("${ownedViewName}(<redacted>)")
    }
}
`;
    if (!source.includes(ownedImpl)) {
      fail(`${rustGeneratedViewPath} is missing inherent impl for ${ownedViewName}`);
    }
    if (!source.includes(`formatter.write_str("${ownedViewName}(<redacted>)")`)) {
      source = source.replace(ownedImpl, `${redactedOwnedDebug}${ownedImpl}`);
    }
    source = disableViewSerialization(
      source,
      ownedViewName,
      new RegExp(
        `impl ::serde::Serialize\\s+for ${ownedViewName} \\{`,
        "u",
      ),
      `impl ::serde::Serialize for ${ownedViewName} {`,
      null,
    );
  }

  writeGeneratedIfChanged(rustGeneratedViewPath, source);
}

const swiftPath = join(
  root,
  "gen/swift/reallyme/crypto/v1/crypto.pb.swift",
);
// Normalize the generated package uniformly so new schema files do not need
// a second list of Java/Kotlin filenames just to keep regeneration stable.
const normalizedGeneratedPaths = [
  ["gen/java/me/really/crypto/v1", ".java"],
  ["gen/kotlin/me/really/crypto/v1", ".kt"],
  ["gen/es/reallyme/crypto/v1", ".js"],
  ["gen/es/reallyme/crypto/v1", ".ts"],
  ["packages/ts/src/proto/generated/reallyme/crypto/v1", ".ts"],
  ["gen/swift/reallyme/crypto/v1", ".swift"],
].flatMap(([directory, extension]) =>
  readdirSync(join(root, directory), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(extension))
    .map((entry) => join(root, directory, entry.name))
    .sort(),
);
const generatedPaths = [
  rustGeneratedPath,
  rustGeneratedViewPath,
  ...supplementalMetadataSchemas.flatMap((schema) => [schema.rustPath, schema.viewPath]),
  swiftPath,
  ...redactedMessageNames.map((messageName) =>
    join(root, `gen/java/me/really/crypto/v1/${messageName}.java`),
  ),
  ...normalizedGeneratedPaths,
];
const idempotencyBefore = checkIdempotent
  ? new Map(generatedPaths.map((path) => [path, readFileSync(path)]))
  : null;

hardenOwnedRust();
hardenViewRust();
for (const schema of supplementalMetadataSchemas) {
  hardenSupplementalMetadataRust(schema);
  hardenSupplementalMetadataView(schema);
}

for (const schema of [
  { swiftPath, messages: redactedMessageNames.map((name) => ({ name })) },
  ...supplementalMetadataSchemas,
]) {
  let swiftSource = readFileSync(schema.swiftPath, "utf8");
  for (const { name: messageName } of schema.messages) {
    const swiftName = `ReallyMeProto${messageName}`;
    const declaration = `public nonisolated struct ${swiftName}: Sendable {`;
    const replacement = `${declaration}
  // Security post-processing: protobuf bytes can contain secrets or PII.
  public var debugDescription: String { "${swiftName}(<redacted>)" }`;
    if (!swiftSource.includes(`${swiftName}(<redacted>)`)) {
      swiftSource = swiftSource.replace(declaration, replacement);
    }
  }
  writeGeneratedIfChanged(schema.swiftPath, swiftSource);
}

for (const messageName of [...redactedMessageNames, ...supplementalMessageNames]) {
  const javaPath = join(
    root,
    `gen/java/me/really/crypto/v1/${messageName}.java`,
  );
  let javaSource = readFileSync(javaPath, "utf8");
  if (javaSource.includes(`${messageName}{<redacted>}`)) {
    continue;
  }
  const declaration = new RegExp(`public\\s+final\\s+class\\s+${messageName}\\s+extends`, "u");
  const declarationMatch = declaration.exec(javaSource);
  const declarationStart = declarationMatch?.index ?? -1;
  const bodyStart = javaSource.indexOf("{", declarationStart);
  if (declarationStart < 0 || bodyStart < 0) {
    fail(`unable to locate generated Java message ${messageName}`);
  }
  const redaction = `
  // Security post-processing: protobuf bytes can contain secrets or PII.
  @java.lang.Override
  public java.lang.String toString() {
    return "${messageName}{<redacted>}";
  }
`;
  javaSource = `${javaSource.slice(0, bodyStart + 1)}${redaction}${javaSource.slice(bodyStart + 1)}`;
  writeGeneratedIfChanged(javaPath, javaSource);
}

function normalizeGeneratedTextFile(path) {
  const source = readFileSync(path, "utf8");
  const normalized = source.replace(/[ \t]+$/gmu, "").replace(/\n+$/u, "\n");
  if (normalized !== source) {
    writeFileSync(path, normalized);
  }
}

// Protoc emits trailing whitespace for some message and enum shapes. Keep
// normalization deterministic across the complete generated package.
for (const path of normalizedGeneratedPaths) {
  normalizeGeneratedTextFile(path);
}

if (idempotencyBefore !== null) {
  for (const [path, before] of idempotencyBefore) {
    if (!before.equals(readFileSync(path))) {
      fail("generated Crypto protobuf hardening is not idempotent");
    }
  }
}
