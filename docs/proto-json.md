<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Proto-JSON Examples

ReallyMe Crypto supports a restricted, strict proto-JSON route for generated
operation messages. The executable adapter allows only `hash`,
`signatureGenerateKeyPair`, `signatureVerify`, `rsaVerify`,
`kemGenerateKeyPair`, `kemEncapsulate`, `hpkeGenerateKeyPair`, and
`hpkeSenderExport`. These request shapes contain no caller-provided private or
symmetric key material, password, shared secret, or PSK. Hash and verification
inputs can still contain confidential or privacy-bearing application data and
must not be logged.

These examples are JSON encodings of the operation request/response messages in
`reallyme.crypto.v1`. They are not casual JSON facades. Algorithms use protobuf
enum names and `bytes` fields use base64. Examples for secret-bearing operations
below document the generated schema only; the executable JSON adapter rejects
those selectors before deserializing their values. Submit those requests as
binary protobuf.

`CryptoOperationRequest` is the only executable JSON request shape. Each
example therefore includes the generated ProtoJSON name of its selected
`oneof` branch. `process_operation_response_json` decodes that message and
dispatches permitted selectors through the same implementation as binary
protobuf. It returns binary `CryptoOperationResponse` bytes; it does not create
a second JSON result API. A secret-bearing selector returns provider-owned
`CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND` in that binary response.

## Hash

Request:

```json
{
  "hash": {
    "algorithm": {
      "hash": "HASH_ALGORITHM_SHA2_256"
    },
    "input": "YWJj"
  }
}
```

Result:

```json
{
  "algorithm": {
    "hash": "HASH_ALGORITHM_SHA2_256"
  },
  "digest": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
}
```

## AEAD

AEAD requests carry secret-bearing keys and may carry secret or PII-bearing
plaintext. The following shapes are schema illustrations and are not accepted
by the executable JSON adapter.

Seal request:

```json
{
  "aeadSeal": {
    "algorithm": {
      "aead": "AEAD_ALGORITHM_AES_256_GCM"
    },
    "key": "ERERERERERERERERERERERERERERERERERERERERERE=",
    "nonce": "IiIiIiIiIiIiIiIi",
    "aad": "Ym91bmRhcnkgYWFk",
    "plaintext": "dHJhbnNwb3J0IHBsYWludGV4dA=="
  }
}
```

Open request:

```json
{
  "aeadOpen": {
    "algorithm": {
      "aead": "AEAD_ALGORITHM_AES_256_GCM"
    },
    "key": "ERERERERERERERERERERERERERERERERERERERERERE=",
    "nonce": "IiIiIiIiIiIiIiIi",
    "aad": "Ym91bmRhcnkgYWFk",
    "ciphertextWithTag": "BASE64_CIPHERTEXT_AND_TAG"
  }
}
```

## MAC

MAC keys are secret-bearing.

Authenticate request:

```json
{
  "macAuthenticate": {
    "algorithm": {
      "mac": "MAC_ALGORITHM_HMAC_SHA256"
    },
    "key": "ERERERERERERERERERERERERERERERERERERERERERE=",
    "message": "bWFjIG1lc3NhZ2U="
  }
}
```

Verify request:

```json
{
  "macVerify": {
    "algorithm": {
      "mac": "MAC_ALGORITHM_HMAC_SHA256"
    },
    "tag": "BASE64_TAG",
    "key": "ERERERERERERERERERERERERERERERERERERERERERE=",
    "message": "bWFjIG1lc3NhZ2U="
  }
}
```

## Signatures

Signing and key-derivation requests carry secret-bearing key material.
Ed25519 signing uses 32-byte seed material in `secretKey`; 64-byte expanded
`seed || publicKey` input is rejected as typed invalid-key input.

Generate key pair request:

```json
{
  "signatureGenerateKeyPair": {
    "algorithm": {
      "signature": "SIGNATURE_ALGORITHM_ED25519"
    }
  }
}
```

Sign request:

```json
{
  "signatureSign": {
    "algorithm": {
      "signature": "SIGNATURE_ALGORITHM_ED25519"
    },
    "message": "c2lnbmF0dXJlIG1lc3NhZ2U=",
    "secretKey": "BASE64_SECRET_KEY"
  }
}
```

Verify request:

```json
{
  "signatureVerify": {
    "algorithm": {
      "signature": "SIGNATURE_ALGORITHM_ED25519"
    },
    "signature": "BASE64_SIGNATURE",
    "message": "c2lnbmF0dXJlIG1lc3NhZ2U=",
    "publicKey": "BASE64_PUBLIC_KEY"
  }
}
```

BIP-340 Schnorr sign request:

```json
{
  "bip340SchnorrSign": {
    "message32": "BASE64_32_BYTE_MESSAGE",
    "secretKey": "BASE64_32_BYTE_SECRET_KEY",
    "auxRand32": "BASE64_32_BYTE_AUX_RAND"
  }
}
```

RSA verify request:

```json
{
  "rsaVerify": {
    "algorithm": {
      "signature": "SIGNATURE_ALGORITHM_RSA_PSS_SHA256_MGF1_SHA256"
    },
    "signature": "BASE64_SIGNATURE",
    "message": "BASE64_MESSAGE",
    "publicKeyDer": "BASE64_RSA_PUBLIC_KEY_DER",
    "publicKeyEncoding": "RSA_PUBLIC_KEY_DER_ENCODING_PKCS1"
  }
}
```

## KEM

Decapsulation results and requests carry secret-bearing material.

Generate key pair request:

```json
{
  "kemGenerateKeyPair": {
    "algorithm": {
      "kem": "KEM_ALGORITHM_ML_KEM_768"
    }
  }
}
```

Encapsulate request:

```json
{
  "kemEncapsulate": {
    "algorithm": {
      "kem": "KEM_ALGORITHM_ML_KEM_768"
    },
    "publicKey": "BASE64_PUBLIC_KEY"
  }
}
```

Decapsulate request:

```json
{
  "kemDecapsulate": {
    "algorithm": {
      "kem": "KEM_ALGORITHM_ML_KEM_768"
    },
    "ciphertext": "BASE64_CIPHERTEXT",
    "secretKey": "BASE64_SECRET_KEY"
  }
}
```

## KDF And HKDF

KDF inputs and outputs are secret-bearing.

Generic KDF schema illustration. The binary operation branch accepts
PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-512 from 100,000 through 10,000,000
iterations; the executable JSON adapter rejects this secret-bearing selector.
Argon2id remains on its dedicated versioned-profile APIs.

```json
{
  "kdfDeriveKey": {
    "algorithm": {
      "kdf": "KDF_ALGORITHM_PBKDF2_HMAC_SHA256"
    },
    "password": "BASE64_PASSWORD_OR_INPUT_SECRET",
    "salt": "BASE64_SALT",
    "iterations": 100000,
    "outputLength": 32
  }
}
```

HKDF request:

```json
{
  "hkdfDerive": {
    "algorithm": {
      "kdf": "KDF_ALGORITHM_HKDF_SHA256"
    },
    "inputKeyMaterial": "BASE64_INPUT_KEY_MATERIAL",
    "salt": "BASE64_SALT",
    "info": "BASE64_CONTEXT_INFO",
    "outputLength": 32
  }
}
```

KMAC256 request:

```json
{
  "kmac256Derive": {
    "algorithm": {
      "kdf": "KDF_ALGORITHM_KMAC_256"
    },
    "key": "BASE64_KEY_DERIVATION_KEY",
    "context": "BASE64_PROTOCOL_CONTEXT",
    "customization": "BASE64_CUSTOMIZATION_STRING",
    "outputLength": 32
  }
}
```

## Key Wrap

Wrapping keys and unwrapped keys are secret-bearing.

Wrap request:

```json
{
  "keyWrap": {
    "algorithm": {
      "keyWrap": "KEY_WRAP_ALGORITHM_AES_256_KW"
    },
    "wrappingKey": "BASE64_KEY_ENCRYPTION_KEY",
    "keyToWrap": "BASE64_KEY_TO_WRAP"
  }
}
```

Unwrap request:

```json
{
  "keyUnwrap": {
    "algorithm": {
      "keyWrap": "KEY_WRAP_ALGORITHM_AES_256_KW"
    },
    "wrappingKey": "BASE64_KEY_ENCRYPTION_KEY",
    "wrappedKey": "BASE64_WRAPPED_KEY"
  }
}
```

## HPKE

HPKE open requests and plaintext fields can carry secret-bearing data.

Seal request:

```json
{
  "hpkeSeal": {
    "algorithm": {
      "hpkeSuite": {
        "kem": "HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256",
        "kdf": "HPKE_KDF_ID_HKDF_SHA256",
        "aead": "HPKE_AEAD_ID_CHACHA20_POLY1305"
      }
    },
    "recipientPublicKey": "BASE64_PUBLIC_KEY",
    "info": "BASE64_INFO",
    "aad": "BASE64_AAD",
    "plaintext": "BASE64_PLAINTEXT"
  }
}
```

Open request:

```json
{
  "hpkeOpen": {
    "algorithm": {
      "hpkeSuite": {
        "kem": "HPKE_KEM_ID_DHKEM_X25519_HKDF_SHA256",
        "kdf": "HPKE_KDF_ID_HKDF_SHA256",
        "aead": "HPKE_AEAD_ID_CHACHA20_POLY1305"
      }
    },
    "recipientSecretKey": "BASE64_SECRET_KEY",
    "encapsulatedKey": "BASE64_ENCAPSULATED_KEY",
    "info": "BASE64_INFO",
    "aad": "BASE64_AAD",
    "ciphertext": "BASE64_CIPHERTEXT"
  }
}
```

## Errors And Responses

Structured errors keep the owning branch explicit.

```json
{
  "primitive": {
    "reason": "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_SIGNATURE"
  }
}
```

For fixtures and diagnostics, a binary `CryptoOperationResponse` may be
explicitly rendered as generated ProtoJSON. Successful data remains in its
typed result branch; it is never wrapped in opaque payload bytes:

```json
{
  "result": {
    "hash": {
      "digest": "BASE64_DIGEST"
    }
  }
}
```

An operation failure instead selects the response's `error` branch and carries
the structured error shown above. The executable JSON adapter always returns
the response as binary protobuf bytes.
