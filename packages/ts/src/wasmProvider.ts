// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { ReallyMeCryptoError } from "./errors.js";
import type { ReallyMeCryptoErrorCode } from "./errors.js";

type GenerateKeypairFn = () => unknown;
type GenerateKeypairFromSeedFn = (seed: Uint8Array) => unknown;
type Argon2idFn = (kdfVersion: number, secret: Uint8Array, salt: Uint8Array) => unknown;
type AeadFn = (
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  text: Uint8Array,
) => unknown;
type KeyWrapFn = (wrappingKey: Uint8Array, keyMaterial: Uint8Array) => unknown;
type BytesToStringFn = (bytes: Uint8Array) => unknown;
type BytesToObjectFn = (bytes: Uint8Array) => unknown;
type StringToBytesFn = (text: string) => unknown;
type StringToObjectFn = (text: string) => unknown;
type StringBytesToStringFn = (text: string, bytes: Uint8Array) => unknown;
type SignatureSignFn = (secretKey: Uint8Array, message: Uint8Array) => unknown;
type SignatureVerifyFn = (
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) => unknown;
type RsaPkcs1v15VerifyFn = (
  publicKeyDer: Uint8Array,
  publicKeyEncoding: number,
  hashSuite: number,
  message: Uint8Array,
  signature: Uint8Array,
) => unknown;
type RsaPssVerifyFn = (
  publicKeyDer: Uint8Array,
  publicKeyEncoding: number,
  messageHashSuite: number,
  mgf1HashSuite: number,
  saltLength: number,
  message: Uint8Array,
  signature: Uint8Array,
) => unknown;
type HpkeOpenFn = (
  suite: number,
  recipientSecretKey: Uint8Array,
  encapsulatedKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
) => unknown;
type HpkeSealFn = (
  suite: number,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
) => unknown;
type HpkeSealDerandFn = (
  suite: number,
  recipientPublicKey: Uint8Array,
  encapsulationRandomness: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
) => unknown;
type DeriveKeypairFn = (secretKey: Uint8Array) => unknown;
type SlhDsaDeriveKeypairFn = (
  skSeed: Uint8Array,
  skPrf: Uint8Array,
  pkSeed: Uint8Array,
) => unknown;
type EncapsulateFn = (publicKey: Uint8Array) => unknown;
type EncapsulateDerandFn = (publicKey: Uint8Array, seed: Uint8Array) => unknown;
type DecapsulateFn = (ciphertext: Uint8Array, secretKey: Uint8Array) => unknown;
type WasmArgument = Uint8Array | number | string;
type WasmCallable = (...args: ReadonlyArray<WasmArgument>) => unknown;

export type ReallyMeWasmProvider = Readonly<{
  aes128GcmSeal: AeadFn;
  aes128GcmOpen: AeadFn;
  aes192GcmSeal: AeadFn;
  aes192GcmOpen: AeadFn;
  aes256GcmSeal: AeadFn;
  aes256GcmOpen: AeadFn;
  aes256GcmSivSeal: AeadFn;
  aes256GcmSivOpen: AeadFn;
  chacha20Poly1305Seal: AeadFn;
  chacha20Poly1305Open: AeadFn;
  xchacha20Poly1305Seal: AeadFn;
  xchacha20Poly1305Open: AeadFn;
  aes256KwWrapKey: KeyWrapFn;
  aes256KwUnwrapKey: KeyWrapFn;
  argon2idDeriveKey: Argon2idFn;
  base64urlEncode: BytesToStringFn;
  base64urlDecode: StringToBytesFn;
  multibaseBase64urlEncode: BytesToStringFn;
  multibaseBase58btcEncode: BytesToStringFn;
  multibaseDecode: StringToBytesFn;
  multicodecPrefixForName: StringToObjectFn;
  multicodecLookupPrefix: BytesToObjectFn;
  multikeyEncode: StringBytesToStringFn;
  multikeyParse: StringToObjectFn;
  dagCborComputeCid: BytesToStringFn;
  dagCborVerifyCid: StringBytesToStringFn;
  hpkeSealBase: HpkeSealFn;
  hpkeSealBaseDerand: HpkeSealDerandFn;
  hpkeOpenBase: HpkeOpenFn;
  mlDsa44GenerateKeypair: GenerateKeypairFn;
  mlDsa44DeriveKeypair: GenerateKeypairFromSeedFn;
  mlDsa44Sign: SignatureSignFn;
  mlDsa44Verify: SignatureVerifyFn;
  mlDsa65GenerateKeypair: GenerateKeypairFn;
  mlDsa65DeriveKeypair: GenerateKeypairFromSeedFn;
  mlDsa65Sign: SignatureSignFn;
  mlDsa65Verify: SignatureVerifyFn;
  mlDsa87GenerateKeypair: GenerateKeypairFn;
  mlDsa87DeriveKeypair: GenerateKeypairFromSeedFn;
  mlDsa87Sign: SignatureSignFn;
  mlDsa87Verify: SignatureVerifyFn;
  mlKem512GenerateKeypair: GenerateKeypairFn;
  mlKem512DeriveKeypair: GenerateKeypairFromSeedFn;
  mlKem512Encapsulate: EncapsulateFn;
  mlKem512EncapsulateDerand: EncapsulateDerandFn;
  mlKem512Decapsulate: DecapsulateFn;
  mlKem768GenerateKeypair: GenerateKeypairFn;
  mlKem768DeriveKeypair: GenerateKeypairFromSeedFn;
  mlKem768Encapsulate: EncapsulateFn;
  mlKem768EncapsulateDerand: EncapsulateDerandFn;
  mlKem768Decapsulate: DecapsulateFn;
  mlKem1024GenerateKeypair: GenerateKeypairFn;
  mlKem1024DeriveKeypair: GenerateKeypairFromSeedFn;
  mlKem1024Encapsulate: EncapsulateFn;
  mlKem1024EncapsulateDerand: EncapsulateDerandFn;
  mlKem1024Decapsulate: DecapsulateFn;
  slhDsaSha2128sGenerateKeypair: GenerateKeypairFn;
  slhDsaSha2128sDeriveKeypair: SlhDsaDeriveKeypairFn;
  slhDsaSha2128sSign: SignatureSignFn;
  slhDsaSha2128sVerify: SignatureVerifyFn;
  rsaVerifyPkcs1v15: RsaPkcs1v15VerifyFn;
  rsaVerifyPss: RsaPssVerifyFn;
  xWing768GenerateKeypair: GenerateKeypairFn;
  xWing768DeriveKeypair: DeriveKeypairFn;
  xWing768Encapsulate: EncapsulateFn;
  xWing768EncapsulateDerand: EncapsulateDerandFn;
  xWing768Decapsulate: DecapsulateFn;
  xWing1024GenerateKeypair: GenerateKeypairFn;
  xWing1024DeriveKeypair: DeriveKeypairFn;
  xWing1024Encapsulate: EncapsulateFn;
  xWing1024EncapsulateDerand: EncapsulateDerandFn;
  xWing1024Decapsulate: DecapsulateFn;
}>;

let installedProvider: ReallyMeWasmProvider | undefined;

const requireObject = (module: unknown): object => {
  if (typeof module !== "object" || module === null) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return module;
};

const requireFunction = (module: object, name: string): WasmCallable => {
  const candidate: unknown = Reflect.get(module, name);
  if (typeof candidate !== "function") {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return (...args: ReadonlyArray<WasmArgument>): unknown => {
    try {
      return candidate(...args);
    } catch (error: unknown) {
      throw new ReallyMeCryptoError(wasmErrorCode(error));
    }
  };
};

const wasmErrorCode = (error: unknown): ReallyMeCryptoErrorCode => {
  switch (error) {
    case "invalid-input":
      return "invalid-input";
    case "invalid-signature":
      return "invalid-signature";
    case "unsupported-algorithm":
      return "unsupported-algorithm";
    case "provider-failure":
    default:
      return "provider-failure";
  }
};

const function0 = (module: object, name: string): GenerateKeypairFn => {
  const callable = requireFunction(module, name);
  return (): unknown => callable();
};

const function1 = (module: object, name: string): DeriveKeypairFn => {
  const callable = requireFunction(module, name);
  return (first: Uint8Array): unknown => callable(first);
};

const function2 = (module: object, name: string): EncapsulateDerandFn => {
  const callable = requireFunction(module, name);
  return (first: Uint8Array, second: Uint8Array): unknown => callable(first, second);
};

const stringFunction1 = (module: object, name: string): StringToBytesFn => {
  const callable = requireFunction(module, name);
  return (text: string): unknown => callable(text);
};

const bytesFunction1 = (module: object, name: string): BytesToStringFn => {
  const callable = requireFunction(module, name);
  return (bytes: Uint8Array): unknown => callable(bytes);
};

const stringBytesFunction2 = (module: object, name: string): StringBytesToStringFn => {
  const callable = requireFunction(module, name);
  return (text: string, bytes: Uint8Array): unknown => callable(text, bytes);
};

const function3 = (module: object, name: string): SignatureVerifyFn => {
  const callable = requireFunction(module, name);
  return (first: Uint8Array, second: Uint8Array, third: Uint8Array): unknown =>
    callable(first, second, third);
};

const deriveSlhDsaFunction3 = (
  module: object,
  name: string,
): SlhDsaDeriveKeypairFn => {
  const callable = requireFunction(module, name);
  return (skSeed: Uint8Array, skPrf: Uint8Array, pkSeed: Uint8Array): unknown =>
    callable(skSeed, skPrf, pkSeed);
};

const function4 = (module: object, name: string): AeadFn => {
  const callable = requireFunction(module, name);
  return (
    first: Uint8Array,
    second: Uint8Array,
    third: Uint8Array,
    fourth: Uint8Array,
  ): unknown => callable(first, second, third, fourth);
};

const argon2idFunction = (module: object, name: string): Argon2idFn => {
  const callable = requireFunction(module, name);
  return (kdfVersion: number, secret: Uint8Array, salt: Uint8Array): unknown =>
    callable(kdfVersion, secret, salt);
};

const hpkeSealFunction = (module: object, name: string): HpkeSealFn => {
  const callable = requireFunction(module, name);
  return (
    suite: number,
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): unknown => callable(suite, recipientPublicKey, info, aad, plaintext);
};

const hpkeSealDerandFunction = (module: object, name: string): HpkeSealDerandFn => {
  const callable = requireFunction(module, name);
  return (
    suite: number,
    recipientPublicKey: Uint8Array,
    encapsulationRandomness: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): unknown =>
    callable(suite, recipientPublicKey, encapsulationRandomness, info, aad, plaintext);
};

const hpkeOpenFunction = (module: object, name: string): HpkeOpenFn => {
  const callable = requireFunction(module, name);
  return (
    suite: number,
    recipientSecretKey: Uint8Array,
    encapsulatedKey: Uint8Array,
    info: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
  ): unknown => callable(suite, recipientSecretKey, encapsulatedKey, info, aad, ciphertext);
};

const rsaPkcs1v15VerifyFunction = (
  module: object,
  name: string,
): RsaPkcs1v15VerifyFn => {
  const callable = requireFunction(module, name);
  return (
    publicKeyDer: Uint8Array,
    publicKeyEncoding: number,
    hashSuite: number,
    message: Uint8Array,
    signature: Uint8Array,
  ): unknown => callable(publicKeyDer, publicKeyEncoding, hashSuite, message, signature);
};

const rsaPssVerifyFunction = (module: object, name: string): RsaPssVerifyFn => {
  const callable = requireFunction(module, name);
  return (
    publicKeyDer: Uint8Array,
    publicKeyEncoding: number,
    messageHashSuite: number,
    mgf1HashSuite: number,
    saltLength: number,
    message: Uint8Array,
    signature: Uint8Array,
  ): unknown =>
    callable(
      publicKeyDer,
      publicKeyEncoding,
      messageHashSuite,
      mgf1HashSuite,
      saltLength,
      message,
      signature,
    );
};

export const installReallyMeWasmProvider = (module: unknown): void => {
  const providerModule = requireObject(module);
  installedProvider = {
    aes128GcmSeal: function4(providerModule, "aes128GcmSeal"),
    aes128GcmOpen: function4(providerModule, "aes128GcmOpen"),
    aes192GcmSeal: function4(providerModule, "aes192GcmSeal"),
    aes192GcmOpen: function4(providerModule, "aes192GcmOpen"),
    aes256GcmSeal: function4(providerModule, "aes256GcmSeal"),
    aes256GcmOpen: function4(providerModule, "aes256GcmOpen"),
    aes256GcmSivSeal: function4(providerModule, "aes256GcmSivSeal"),
    aes256GcmSivOpen: function4(providerModule, "aes256GcmSivOpen"),
    chacha20Poly1305Seal: function4(providerModule, "chacha20Poly1305Seal"),
    chacha20Poly1305Open: function4(providerModule, "chacha20Poly1305Open"),
    xchacha20Poly1305Seal: function4(providerModule, "xchacha20Poly1305Seal"),
    xchacha20Poly1305Open: function4(providerModule, "xchacha20Poly1305Open"),
    aes256KwWrapKey: function2(providerModule, "aes256KwWrapKey"),
    aes256KwUnwrapKey: function2(providerModule, "aes256KwUnwrapKey"),
    argon2idDeriveKey: argon2idFunction(providerModule, "argon2idDeriveKey"),
    base64urlEncode: bytesFunction1(providerModule, "base64urlEncode"),
    base64urlDecode: stringFunction1(providerModule, "base64urlDecode"),
    multibaseBase64urlEncode: bytesFunction1(
      providerModule,
      "multibaseBase64urlEncode",
    ),
    multibaseBase58btcEncode: bytesFunction1(
      providerModule,
      "multibaseBase58btcEncode",
    ),
    multibaseDecode: stringFunction1(providerModule, "multibaseDecode"),
    multicodecPrefixForName: stringFunction1(
      providerModule,
      "multicodecPrefixForName",
    ),
    multicodecLookupPrefix: bytesFunction1(providerModule, "multicodecLookupPrefix"),
    multikeyEncode: stringBytesFunction2(providerModule, "multikeyEncode"),
    multikeyParse: stringFunction1(providerModule, "multikeyParse"),
    dagCborComputeCid: bytesFunction1(providerModule, "dagCborComputeCid"),
    dagCborVerifyCid: stringBytesFunction2(providerModule, "dagCborVerifyCid"),
    hpkeSealBase: hpkeSealFunction(providerModule, "hpkeSealBase"),
    hpkeSealBaseDerand: hpkeSealDerandFunction(providerModule, "hpkeSealBaseDerand"),
    hpkeOpenBase: hpkeOpenFunction(providerModule, "hpkeOpenBase"),
    mlDsa44GenerateKeypair: function0(providerModule, "mlDsa44GenerateKeypair"),
    mlDsa44DeriveKeypair: function1(providerModule, "mlDsa44DeriveKeypair"),
    mlDsa44Sign: function2(providerModule, "mlDsa44Sign"),
    mlDsa44Verify: function3(providerModule, "mlDsa44Verify"),
    mlDsa65GenerateKeypair: function0(providerModule, "mlDsa65GenerateKeypair"),
    mlDsa65DeriveKeypair: function1(providerModule, "mlDsa65DeriveKeypair"),
    mlDsa65Sign: function2(providerModule, "mlDsa65Sign"),
    mlDsa65Verify: function3(providerModule, "mlDsa65Verify"),
    mlDsa87GenerateKeypair: function0(providerModule, "mlDsa87GenerateKeypair"),
    mlDsa87DeriveKeypair: function1(providerModule, "mlDsa87DeriveKeypair"),
    mlDsa87Sign: function2(providerModule, "mlDsa87Sign"),
    mlDsa87Verify: function3(providerModule, "mlDsa87Verify"),
    mlKem512GenerateKeypair: function0(providerModule, "mlKem512GenerateKeypair"),
    mlKem512DeriveKeypair: function1(providerModule, "mlKem512DeriveKeypair"),
    mlKem512Encapsulate: function1(providerModule, "mlKem512Encapsulate"),
    mlKem512EncapsulateDerand: function2(providerModule, "mlKem512EncapsulateDerand"),
    mlKem512Decapsulate: function2(providerModule, "mlKem512Decapsulate"),
    mlKem768GenerateKeypair: function0(providerModule, "mlKem768GenerateKeypair"),
    mlKem768DeriveKeypair: function1(providerModule, "mlKem768DeriveKeypair"),
    mlKem768Encapsulate: function1(providerModule, "mlKem768Encapsulate"),
    mlKem768EncapsulateDerand: function2(providerModule, "mlKem768EncapsulateDerand"),
    mlKem768Decapsulate: function2(providerModule, "mlKem768Decapsulate"),
    mlKem1024GenerateKeypair: function0(providerModule, "mlKem1024GenerateKeypair"),
    mlKem1024DeriveKeypair: function1(providerModule, "mlKem1024DeriveKeypair"),
    mlKem1024Encapsulate: function1(providerModule, "mlKem1024Encapsulate"),
    mlKem1024EncapsulateDerand: function2(providerModule, "mlKem1024EncapsulateDerand"),
    mlKem1024Decapsulate: function2(providerModule, "mlKem1024Decapsulate"),
    slhDsaSha2128sGenerateKeypair: function0(
      providerModule,
      "slhDsaSha2128sGenerateKeypair",
    ),
    slhDsaSha2128sDeriveKeypair: deriveSlhDsaFunction3(
      providerModule,
      "slhDsaSha2128sDeriveKeypair",
    ),
    slhDsaSha2128sSign: function2(providerModule, "slhDsaSha2128sSign"),
    slhDsaSha2128sVerify: function3(providerModule, "slhDsaSha2128sVerify"),
    rsaVerifyPkcs1v15: rsaPkcs1v15VerifyFunction(
      providerModule,
      "rsaVerifyPkcs1v15",
    ),
    rsaVerifyPss: rsaPssVerifyFunction(providerModule, "rsaVerifyPss"),
    xWing768GenerateKeypair: function0(providerModule, "xWing768GenerateKeypair"),
    xWing768DeriveKeypair: function1(providerModule, "xWing768DeriveKeypair"),
    xWing768Encapsulate: function1(providerModule, "xWing768Encapsulate"),
    xWing768EncapsulateDerand: function2(providerModule, "xWing768EncapsulateDerand"),
    xWing768Decapsulate: function2(providerModule, "xWing768Decapsulate"),
    xWing1024GenerateKeypair: function0(providerModule, "xWing1024GenerateKeypair"),
    xWing1024DeriveKeypair: function1(providerModule, "xWing1024DeriveKeypair"),
    xWing1024Encapsulate: function1(providerModule, "xWing1024Encapsulate"),
    xWing1024EncapsulateDerand: function2(providerModule, "xWing1024EncapsulateDerand"),
    xWing1024Decapsulate: function2(providerModule, "xWing1024Decapsulate"),
  };
};

export const requireReallyMeWasmProvider = (): ReallyMeWasmProvider => {
  if (installedProvider === undefined) {
    throw new ReallyMeCryptoError("provider-failure");
  }
  return installedProvider;
};
