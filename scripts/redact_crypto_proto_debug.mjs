#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
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
const messagePattern = /message\s+(\w+)\s*\{([\s\S]*?)\n\}/gu;
const oneofCount = [...protoSource.matchAll(/\boneof\s+\w+\s*\{/gu)].length;
for (const match of protoSource.matchAll(messagePattern)) {
  const [, messageName, body] = match;
  messageBodies.set(messageName, body);
  const fields = [...body.matchAll(/\bbytes\s+(\w+)\s*=/gu)];
  if (fields.length === 0) {
    continue;
  }
  byteBearingMessageNames.push(messageName);
  for (const field of fields) {
    byteFieldNames.add(field[1]);
  }
}
const messageNames = [...messageBodies.keys()];
const sensitiveMessageNames = new Set(byteBearingMessageNames);
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
const unknownFieldDropOwnerNames = new Set(byteBearingMessageNames);
const wrappedUnknownFieldOwnerNames = new Set([
  "CryptoOperationRequest",
  "CryptoOperationResponse",
  "CryptoOperationResult",
]);

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

function serdeAttrForWireField(field) {
  const parts = [`rename = "${field.jsonName}"`];
  for (const alias of field.aliases) {
    parts.push(`alias = "${alias}"`);
  }

  if (field.type === "::buffa::alloc::vec::Vec<u8>") {
    parts.push('deserialize_with = "deserialize_zeroizing_bytes"');
  } else if (field.type.startsWith("::buffa::EnumValue<")) {
    parts.push('with = "::buffa::json_helpers::proto_enum"');
  } else if (field.type === "u32") {
    parts.push('with = "::buffa::json_helpers::uint32"');
  } else if (isSensitiveStringField(field)) {
    parts.push('deserialize_with = "deserialize_zeroizing_string"');
  } else if (field.type === "::buffa::alloc::string::String") {
    parts.push('with = "::buffa::json_helpers::proto_string"');
  } else if (
    field.type.startsWith("::buffa::MessageField<") ||
    field.type === "bool"
  ) {
    // Buffa's generated serde for these field shapes relies on the default
    // field representation. The surrounding Wire struct is #[serde(default)].
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
  if (field.type === "::buffa::alloc::vec::Vec<u8>") {
    return "::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>";
  }
  if (isSensitiveStringField(field)) {
    return "::zeroize::Zeroizing<::buffa::alloc::string::String>";
  }
  return field.type;
}

function assignmentForField(field) {
  if (field.type === "::buffa::alloc::vec::Vec<u8>" || isSensitiveStringField(field)) {
    return `            ${field.name}: ::core::mem::take(&mut *wire.${field.name}),`;
  }
  return `            ${field.name}: wire.${field.name},`;
}

function deserializeImpl(messageName, fields) {
  const wireFields = fields
    .filter((field) => field.name !== "__buffa_unknown_fields")
    .map(
      (field) => `${serdeAttrForWireField(field)}
            ${field.name}: ${wireType(field)},`,
    )
    .join("\n");
  const assignments = fields
    .filter((field) => field.name !== "__buffa_unknown_fields")
    .map(assignmentForField)
    .join("\n");

  return `impl<'de> ::serde::Deserialize<'de> for ${messageName} {
    fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        fn deserialize_zeroizing_bytes<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::vec::Vec<u8>>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::bytes::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

        fn deserialize_zeroizing_string<'de, D>(
            deserializer: D,
        ) -> ::core::result::Result<::zeroize::Zeroizing<::buffa::alloc::string::String>, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            ::buffa::json_helpers::proto_string::deserialize(deserializer)
                .map(::zeroize::Zeroizing::new)
        }

        #[derive(Default, ::serde::Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Wire {
${wireFields}
        }

        let mut wire = Wire::deserialize(deserializer)?;
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
        field.type === "::buffa::alloc::vec::Vec<u8>" ||
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
  if (!source.includes(generatedHeader)) {
    fail(`${rustGeneratedPath} is missing the generated header`);
  }
  if (!source.includes("__reallyme_zeroize_unknown_fields")) {
    source = source.replace(
      generatedHeader,
      `${generatedHeader}${unknownFieldZeroizeHelpers}`,
    );
  }
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
        field.type === "::buffa::alloc::vec::Vec<u8>" ||
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
  for (const messageName of wrappedUnknownFieldOwnerNames) {
    source = hardenUnknownFieldStorage(source, messageName);
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
  const ignoredUnknownFieldCount =
    source.split(ignoredUnknownField).length - 1;
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

  writeFileSync(rustGeneratedPath, source);
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

  writeFileSync(rustGeneratedViewPath, source);
}

const swiftPath = join(
  root,
  "gen/swift/reallyme/crypto/v1/crypto.pb.swift",
);
const normalizedGeneratedPaths = [
  "gen/java/me/really/crypto/v1/CryptoHpkeDeriveKeyPairRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkeGenerateKeyPairRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkePskOpenRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkePskSealRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkeReceiverExportRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkeReceiverExportResult.java",
  "gen/java/me/really/crypto/v1/CryptoHpkeSenderExportRequest.java",
  "gen/java/me/really/crypto/v1/CryptoHpkeSenderExportResult.java",
  "gen/java/me/really/crypto/v1/CryptoKmac256DeriveRequest.java",
  "gen/java/me/really/crypto/v1/CryptoKmac256DeriveResult.java",
  "gen/java/me/really/crypto/v1/CryptoKemDeriveKeyPairRequest.java",
  "gen/java/me/really/crypto/v1/CryptoOperationRequest.java",
  "gen/java/me/really/crypto/v1/HpkeAeadId.java",
  "gen/java/me/really/crypto/v1/HpkeKdfId.java",
  "gen/java/me/really/crypto/v1/HpkeKemId.java",
  "gen/java/me/really/crypto/v1/HpkeSuiteIdentifier.java",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeDeriveKeyPairRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeGenerateKeyPairRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkePskOpenRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkePskSealRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeReceiverExportRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeReceiverExportResultKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeSenderExportRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoHpkeSenderExportResultKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoKmac256DeriveRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoKmac256DeriveResultKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoKemDeriveKeyPairRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/CryptoOperationRequestKt.kt",
  "gen/kotlin/me/really/crypto/v1/HpkeSuiteIdentifierKt.kt",
].map((relativePath) => join(root, relativePath));
const generatedPaths = [
  rustGeneratedPath,
  rustGeneratedViewPath,
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

let swiftSource = readFileSync(swiftPath, "utf8");
for (const messageName of redactedMessageNames) {
  const swiftName = `ReallyMeProto${messageName}`;
  const declaration = `public nonisolated struct ${swiftName}: Sendable {`;
  const replacement = `${declaration}
  // Security post-processing: protobuf bytes can contain secrets or PII.
  public var debugDescription: String { "${swiftName}(<redacted>)" }`;
  if (!swiftSource.includes(`${swiftName}(<redacted>)`)) {
    swiftSource = swiftSource.replace(declaration, replacement);
  }
}
writeFileSync(swiftPath, swiftSource);

for (const messageName of redactedMessageNames) {
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
  writeFileSync(javaPath, javaSource);
}

function normalizeGeneratedTextFile(path) {
  const source = readFileSync(path, "utf8");
  const normalized = source.replace(/[ \t]+$/gmu, "").replace(/\n+$/u, "\n");
  if (normalized !== source) {
    writeFileSync(path, normalized);
  }
}

// Protoc emits unstable trailing whitespace for these message shapes. Keep the
// list explicit so clean regeneration is deterministic without rewriting the
// entire managed-runtime output tree during a release-only hardening change.
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
