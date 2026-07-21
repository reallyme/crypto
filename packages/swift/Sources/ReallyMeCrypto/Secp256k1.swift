// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import CSecp256k1
import Foundation

/// secp256k1 ECDSA backed by Bitcoin Core libsecp256k1 via the
/// reallyme/CSecp256k1 binary package.
///
/// The API follows the workspace secp256k1 contract exactly, so signatures
/// interoperate byte-for-byte with the Rust, TypeScript, and Kotlin lanes:
///
/// - Secret keys are 32 bytes; public keys are 33-byte compressed SEC1.
/// - `sign` hashes the full message internally with SHA-256 (callers pass the
///   message, not a digest), derives the nonce deterministically (RFC 6979),
///   and emits the 64-byte compact `r ‖ s` form normalized to low-S
///   (BIP 0062).
/// - `verify` accepts only the 64-byte compact form and fails closed with a
///   typed error for malformed inputs or signatures that do not verify.
public enum ReallyMeSecp256k1 {
    public static let secretKeyLength = 32
    public static let compressedPublicKeyLength = 33
    public static let signatureLength = 64

    /// Generates a random keypair. The secret key is sampled from the
    /// platform CSPRNG and rejection-sampled until libsecp256k1 accepts it as
    /// a valid scalar.
    public static func generateKeyPair() throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let ctx = try makeContext(flags: UInt32(SECP256K1_CONTEXT_SIGN), randomize: true)
        defer { secp256k1_context_destroy(ctx) }

        return try generateKeyPair(
            fillRandom: { candidate in
                SecRandomCopyBytes(kSecRandomDefault, candidate.count, &candidate) == errSecSuccess
            },
            acceptsSecret: { candidate in
                secp256k1_ec_seckey_verify(ctx, candidate) == 1
            },
            derivePublicKey: { candidate in
                try derivePublicKey(secretKey: candidate)
            }
        )
    }

    /// Rejection-sampling core with injectable boundaries for cleanup tests.
    ///
    /// The production entrypoint supplies the platform CSPRNG and randomized
    /// libsecp256k1 context. Keeping cleanup in this shared core makes a later
    /// provider failure unable to bypass wiping an accepted secret candidate.
    static func generateKeyPair(
        fillRandom: (inout [UInt8]) -> Bool,
        acceptsSecret: ([UInt8]) -> Bool,
        derivePublicKey: ([UInt8]) throws -> [UInt8],
        didClear: (([UInt8]) -> Void)? = nil
    ) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var secretKey = [UInt8](repeating: 0, count: secretKeyLength)
        for _ in 0..<1024 {
            guard fillRandom(&secretKey) else {
                clearSecretCandidate(&secretKey, didClear: didClear)
                throw ReallyMeCryptoError.providerFailure
            }
            if acceptsSecret(secretKey) {
                do {
                    return (publicKey: try derivePublicKey(secretKey), secretKey: secretKey)
                } catch {
                    clearSecretCandidate(&secretKey, didClear: didClear)
                    throw error
                }
            }
        }
        clearSecretCandidate(&secretKey, didClear: didClear)
        throw ReallyMeCryptoError.providerFailure
    }

    private static func clearSecretCandidate(
        _ secretKey: inout [UInt8],
        didClear: (([UInt8]) -> Void)?
    ) {
        ReallyMeCryptoMemory.bestEffortClear(&secretKey)
        didClear?(secretKey)
    }

    /// Derives a secp256k1 ECDSA keypair from a 32-byte secret scalar.
    public static func deriveKeyPair(secretKey: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        (
            publicKey: try derivePublicKey(secretKey: secretKey),
            secretKey: secretKey
        )
    }

    /// Derives the 33-byte compressed SEC1 public key for a 32-byte secret.
    public static func derivePublicKey(secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == secretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let ctx = try makeContext(flags: UInt32(SECP256K1_CONTEXT_SIGN), randomize: true)
        defer { secp256k1_context_destroy(ctx) }
        guard secp256k1_ec_seckey_verify(ctx, secretKey) == 1 else {
            throw ReallyMeCryptoError.invalidInput
        }

        var publicKey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_create(ctx, &publicKey, secretKey) == 1 else {
            throw ReallyMeCryptoError.providerFailure
        }

        var output = [UInt8](repeating: 0, count: compressedPublicKeyLength)
        var outputLength = compressedPublicKeyLength
        let serialized = withUnsafePointer(to: &publicKey) { publicKeyPointer in
            secp256k1_ec_pubkey_serialize(
                ctx, &output, &outputLength, publicKeyPointer, UInt32(SECP256K1_EC_COMPRESSED)
            )
        }
        guard serialized == 1, outputLength == compressedPublicKeyLength else {
            throw ReallyMeCryptoError.providerFailure
        }
        return output
    }

    /// Decompresses a 33-byte compressed SEC1 public key to 65-byte
    /// uncompressed SEC1 form for envelope formats such as JWK.
    public static func decompressPublicKey(publicKey: [UInt8]) throws -> [UInt8] {
        guard publicKey.count == compressedPublicKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let ctx = try makeContext(flags: UInt32(SECP256K1_CONTEXT_VERIFY), randomize: false)
        defer { secp256k1_context_destroy(ctx) }

        var parsedKey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(ctx, &parsedKey, publicKey, publicKey.count) == 1 else {
            throw ReallyMeCryptoError.invalidInput
        }

        var output = [UInt8](repeating: 0, count: 65)
        var outputLength = output.count
        let serialized = withUnsafePointer(to: &parsedKey) { publicKeyPointer in
            secp256k1_ec_pubkey_serialize(
                ctx, &output, &outputLength, publicKeyPointer, UInt32(SECP256K1_EC_UNCOMPRESSED)
            )
        }
        guard serialized == 1, outputLength == output.count else {
            throw ReallyMeCryptoError.providerFailure
        }
        return output
    }

    /// Signs `message` with deterministic (RFC 6979) ECDSA over
    /// SHA-256(message), returning the 64-byte compact low-S signature.
    public static func sign(message: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard secretKey.count == secretKeyLength else {
            throw ReallyMeCryptoError.invalidInput
        }
        let ctx = try makeContext(flags: UInt32(SECP256K1_CONTEXT_SIGN), randomize: true)
        defer { secp256k1_context_destroy(ctx) }

        let digest = Array(SHA256.hash(data: Data(message)))

        var signature = secp256k1_ecdsa_signature()
        guard secp256k1_ecdsa_sign(ctx, &signature, digest, secretKey, nil, nil) == 1 else {
            throw ReallyMeCryptoError.invalidInput
        }

        // libsecp256k1 already emits low-S; normalize anyway so the contract
        // does not depend on that implementation detail.
        var normalized = secp256k1_ecdsa_signature()
        _ = withUnsafePointer(to: &signature) {
            secp256k1_ecdsa_signature_normalize(ctx, &normalized, $0)
        }

        var compact = [UInt8](repeating: 0, count: signatureLength)
        let serialized = withUnsafePointer(to: &normalized) {
            secp256k1_ecdsa_signature_serialize_compact(ctx, &compact, $0)
        }
        guard serialized == 1 else {
            throw ReallyMeCryptoError.providerFailure
        }
        return compact
    }

    /// Verifies a 64-byte compact signature over SHA-256(message) against a
    /// 33-byte compressed SEC1 public key.
    ///
    /// Throws on malformed input or any signature that does not verify.
    public static func verify(
        signature: [UInt8],
        message: [UInt8],
        publicKey: [UInt8]
    ) throws {
        guard signature.count == signatureLength,
              publicKey.count == compressedPublicKeyLength
        else {
            throw ReallyMeCryptoError.invalidInput
        }
        let ctx = try makeContext(flags: UInt32(SECP256K1_CONTEXT_VERIFY), randomize: false)
        defer { secp256k1_context_destroy(ctx) }

        var parsedKey = secp256k1_pubkey()
        guard secp256k1_ec_pubkey_parse(ctx, &parsedKey, publicKey, publicKey.count) == 1 else {
            throw ReallyMeCryptoError.invalidInput
        }

        var parsedSignature = secp256k1_ecdsa_signature()
        guard secp256k1_ecdsa_signature_parse_compact(ctx, &parsedSignature, signature) == 1 else {
            throw ReallyMeCryptoError.invalidInput
        }

        let digest = Array(SHA256.hash(data: Data(message)))
        let ok = withUnsafePointer(to: &parsedSignature) { signaturePointer in
            withUnsafePointer(to: &parsedKey) { publicKeyPointer in
                secp256k1_ecdsa_verify(ctx, signaturePointer, digest, publicKeyPointer)
            }
        }
        guard ok == 1 else {
            throw ReallyMeCryptoError.invalidSignature
        }
    }

    private static func makeContext(flags: UInt32, randomize: Bool) throws -> OpaquePointer {
        guard let ctx = secp256k1_context_create(flags) else {
            throw ReallyMeCryptoError.providerFailure
        }
        if randomize {
            var seed = [UInt8](repeating: 0, count: 32)
            defer { ReallyMeCryptoMemory.bestEffortClear(&seed) }
            guard SecRandomCopyBytes(kSecRandomDefault, seed.count, &seed) == errSecSuccess else {
                secp256k1_context_destroy(ctx)
                throw ReallyMeCryptoError.providerFailure
            }
            guard secp256k1_context_randomize(ctx, seed) == 1 else {
                secp256k1_context_destroy(ctx)
                throw ReallyMeCryptoError.providerFailure
            }
        }
        return ctx
    }
}
