// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const PACKAGE = "reallyme.crypto.v1";
// These public scalar/empty contracts already prohibited view JSON and redacted
// diagnostics. Retain that policy alongside the schema-derived byte closure.
const PRIVATE_SCALAR_OWNERS = new Set([
  "ProviderDecision", "ProviderDecisionRequest", "ProviderDecisionResult",
  "CryptoKeyAlgorithmIdentifier", "CryptoEcdsaCurveIdentifier", "CryptoPrimeGroupIdentifier",
  "CryptoHkdfSuiteIdentifier", "CryptoPbkdf2PrfIdentifier", "CryptoArgon2idProfileIdentifier",
  "CryptoRsaHashIdentifier", "CryptoRsaPublicKeyDerEncodingIdentifier", "CryptoRandomBytesRequest",
  "CryptoConstantTimeCompareResult", "CryptoConstantTimeRequireEqualResult",
  "CryptoHpkeP256BaseRecipientGenerateRequest", "CryptoRsaPssParams", "CryptoNativeKeyCapabilities",
  "CryptoEcdsaSignOptions", "CryptoEd448SupportRequest", "CryptoNativeVerificationResult",
  "CryptoNativeKeyGenerateRequest", "CryptoNativePublicKeyRequest", "HpkeSuiteIdentifier",
  "CryptoHpkePskReceiverSetupResult", "CryptoHpkeP256BaseCapabilities", "CryptoHpkeComponentCapability",
  "CryptoP256CompressedPublicKeyRequest", "CryptoGenerateMultikeyKeypairRequest",
  "CryptoVerificationMethodMultikeyResult", "CryptoArgon2PlatformResolveRequest",
  "CryptoArgon2BudgetFitRequest", "CryptoArgon2MobileUnlockRequest", "CryptoMaterialPolicyQueryRequest",
  "CryptoRandomFillPolicyQueryRequest", "CryptoKeyAgreementGenerateKeyPairRequest",
]);

export class ProtoGenerationPolicyError extends Error {
  constructor(code) { super("protobuf generation policy is invalid"); this.name = "ProtoGenerationPolicyError"; this.code = code; }
}
const fail = (code) => { throw new ProtoGenerationPolicyError(code); };

/** Discover ownership closure from descriptors, independently of generated Rust. */
export function protoGenerationPolicy(document) {
  if (document === null || typeof document !== "object" || !Array.isArray(document.file) || document.file.length > 128) fail("descriptor");
  const files = document.file.filter((file) => file.package === PACKAGE);
  if (files.length === 0) fail("package");
  const messages = [];
  const privateNames = new Set();
  const sdkNames = new Set();
  for (const file of files) {
    for (const message of file.messageType ?? []) {
      if (typeof message.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(message.name) ||
          (message.nestedType?.length ?? 0) !== 0) fail("message");
      messages.push({ ...message, file: file.name });
      if (file.name !== "reallyme/crypto/v1/crypto.proto") sdkNames.add(message.name);
      if (PRIVATE_SCALAR_OWNERS.has(message.name) || (message.field ?? []).some((field) =>
        field.type === "TYPE_BYTES" || (field.type === "TYPE_STRING" && `${message.name}.${field.name}` !== "CryptoProviderCapability.provider_names"))) privateNames.add(message.name);
    }
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const message of messages) {
      if (!privateNames.has(message.name) && (message.field ?? []).some((field) =>
        field.type === "TYPE_MESSAGE" && privateNames.has(field.typeName?.split(".").at(-1)))) {
        privateNames.add(message.name); changed = true;
      }
    }
  }
  for (const name of privateNames) sdkNames.add(name);
  return { package: PACKAGE, messages, privateNames, sdkNames };
}
