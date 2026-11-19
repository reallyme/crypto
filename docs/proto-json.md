# ProtoJSON requests

`process_operation_response_json` accepts the generated ProtoJSON form of
`CryptoOperationRequest` and returns binary `CryptoOperationResponse` bytes.
Decode the response with the generated protobuf bindings.

The executable JSON route permits only these selectors:

- `hash`
- `signatureGenerateKeyPair`, `signatureVerify`, `rsaVerify`
- `kemGenerateKeyPair`, `kemEncapsulate`
- `hpkeGenerateKeyPair`, `hpkeSenderExport`

Other selectors return `CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_BACKEND`.
Use binary protobuf for private keys, passwords, plaintext, MAC keys, PSKs,
shared secrets, signing, decryption and key derivation. Hash and verification
inputs may also be confidential: do not log request or response payloads.

JSON uses generated enum names and standard base64 for `bytes` fields. Unknown
fields, extra operation branches and invalid enum values are rejected. Consult
[crypto.proto](../crates/proto/proto/reallyme/crypto/v1/crypto.proto) for the
complete field definitions and [protobuf.md](protobuf.md) for transport limits.

## Hash

This request hashes the UTF-8 bytes of `abc`:

```json
{
  "hash": {
    "algorithm": { "hash": "HASH_ALGORITHM_SHA2_256" },
    "input": "YWJj"
  }
}
```

Its binary response has the following ProtoJSON representation when explicitly
rendered for inspection:

```json
{
  "result": {
    "hash": {
      "algorithm": { "hash": "HASH_ALGORITHM_SHA2_256" },
      "digest": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    }
  }
}
```

## Generate a key pair

```json
{
  "signatureGenerateKeyPair": {
    "algorithm": { "signature": "SIGNATURE_ALGORITHM_ED25519" }
  }
}
```

The input has no private material, but the binary result contains a secret key.
Keep it out of logs and clear caller-owned buffers after use.

## Verify a signature

Replace the `BASE64_*` placeholders with standard base64 of the actual bytes:

```json
{
  "signatureVerify": {
    "algorithm": { "signature": "SIGNATURE_ALGORITHM_ED25519" },
    "publicKey": "BASE64_PUBLIC_KEY",
    "message": "YWJj",
    "signature": "BASE64_SIGNATURE"
  }
}
```

## Errors

An unsupported algorithm selects `CryptoOperationResponse.error`:

```json
{
  "error": {
    "provider": {
      "reason": "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM"
    }
  }
}
```

The executable adapter returns this envelope as binary protobuf, not JSON.
