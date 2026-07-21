// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Swift implementation of the secp256k1 C ABI backed by Bitcoin Core
// libsecp256k1, consumed through the reallyme/CSecp256k1 binary package.
// CSecp256k1 exposes upstream's headers as a proper Clang module, so the C
// types, functions, and flag macros are imported directly — no bridging
// header, raw-symbol declarations, or hand-modeled struct layouts. The
// wrapper keeps the C boundary narrow because libsecp256k1 treats malformed
// low-level arguments as programmer errors.

import CryptoKit
import CSecp256k1
import Foundation

// =======================
// Constants (keep in sync with secp256k1_abi.h / Rust expectations)
// =======================

private let SECP256K1_SECRET_KEY_LEN = 32
private let SECP256K1_PUBLIC_KEY_COMPRESSED_LEN = 33
private let SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN = 65
private let SECP256K1_SIGNATURE_LEN = 64
private let BIP340_SCHNORR_PUBLIC_KEY_LEN = 32
private let BIP340_SCHNORR_MESSAGE_LEN = 32
private let BIP340_SCHNORR_AUX_RAND_LEN = 32
private let BIP340_SCHNORR_SIGNATURE_LEN = 64

private let CRYPTO_OK: Int32 = 0
private let CRYPTO_INVALID_KEY: Int32 = -1
private let CRYPTO_INVALID_SIGNATURE: Int32 = -2
private let CRYPTO_INTERNAL_ERROR: Int32 = -128

// =======================
// Context (singleton)
// =======================

private enum SecpCtx {
    nonisolated(unsafe) static let shared: OpaquePointer? =
        secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE))
}

@inline(__always)
private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

// =======================
// ABI: Keypair (compressed SEC1 pubkey + 32-byte secret)
// =======================

@_cdecl("secp256k1_generate_keypair")
public func secp256k1_generate_keypair(
    _ publicOut: UnsafeMutablePointer<UInt8>,
    _ secretOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        return CRYPTO_INTERNAL_ERROR
    }

    // Generate random 32-byte secret and ensure it’s valid on curve.
    var sk = [UInt8](repeating: 0, count: SECP256K1_SECRET_KEY_LEN)

    for _ in 0..<1024 {
        _ = SecRandomCopyBytes(kSecRandomDefault, sk.count, &sk)

        let ok = sk.withUnsafeBytes { bytes -> Int32 in
            guard let secretPointer = bytes.bindMemory(to: UInt8.self).baseAddress else {
                return CRYPTO_INTERNAL_ERROR
            }
            return secp256k1_ec_seckey_verify(ctx, secretPointer)
        }

        if ok != 1 { continue }

        memcpy(secretOut, sk, SECP256K1_SECRET_KEY_LEN)

        // Create pubkey from secret
        var pub = secp256k1_pubkey()

        let created = sk.withUnsafeBytes { bytes -> Int32 in
            guard let secretPointer = bytes.bindMemory(to: UInt8.self).baseAddress else {
                return CRYPTO_INTERNAL_ERROR
            }
            return secp256k1_ec_pubkey_create(ctx, &pub, secretPointer)
        }
        if created != 1 { return CRYPTO_INTERNAL_ERROR }

        // Serialize compressed SEC1 pubkey
        var outLen = SECP256K1_PUBLIC_KEY_COMPRESSED_LEN
        var outBuf = [UInt8](repeating: 0, count: outLen)

        let serOk = withUnsafePointer(to: &pub) { pubPtr in
            secp256k1_ec_pubkey_serialize(
                ctx, &outBuf, &outLen, pubPtr, UInt32(SECP256K1_EC_COMPRESSED)
            )
        }

        if serOk != 1 || outLen != SECP256K1_PUBLIC_KEY_COMPRESSED_LEN {
            return CRYPTO_INTERNAL_ERROR
        }

        memcpy(publicOut, outBuf, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN)
        return CRYPTO_OK
    }

    return CRYPTO_INTERNAL_ERROR
}

// =======================
// ABI: Sign (compact 64-byte ECDSA signature, low-S)
// =======================

@_cdecl("secp256k1_sign")
public func secp256k1_sign(
    _ secretKey: UnsafePointer<UInt8>,
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ signatureOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        return CRYPTO_INTERNAL_ERROR
    }

    let skData = Data(bytes: secretKey, count: SECP256K1_SECRET_KEY_LEN)
    let msgData = Data(bytes: message, count: messageLen)
    let digest = sha256(msgData) // 32 bytes

    var sig = secp256k1_ecdsa_signature()

    let signOk = digest.withUnsafeBytes { dPtr -> Int32 in
        skData.withUnsafeBytes { skPtr -> Int32 in
            guard
                let digestPointer = dPtr.bindMemory(to: UInt8.self).baseAddress,
                let secretPointer = skPtr.bindMemory(to: UInt8.self).baseAddress
            else {
                return CRYPTO_INTERNAL_ERROR
            }
            return secp256k1_ecdsa_sign(
                ctx,
                &sig,
                digestPointer,
                secretPointer,
                nil,
                nil
            )
        }
    }

    if signOk != 1 { return CRYPTO_INVALID_KEY }

    // Normalize to low-S (lib accepts both, but we emit low-S)
    var sigNorm = secp256k1_ecdsa_signature()
    _ = withUnsafePointer(to: &sig) { secp256k1_ecdsa_signature_normalize(ctx, &sigNorm, $0) }

    var out64 = [UInt8](repeating: 0, count: SECP256K1_SIGNATURE_LEN)
    let serOk = withUnsafePointer(to: &sigNorm) {
        secp256k1_ecdsa_signature_serialize_compact(ctx, &out64, $0)
    }
    if serOk != 1 { return CRYPTO_INTERNAL_ERROR }

    memcpy(signatureOut, out64, SECP256K1_SIGNATURE_LEN)
    return CRYPTO_OK
}

// =======================
// ABI: Verify (compact 64-byte ECDSA signature, compressed SEC1 pubkey)
// =======================

@_cdecl("secp256k1_verify")
public func secp256k1_verify(
    _ signature: UnsafePointer<UInt8>,
    _ message: UnsafePointer<UInt8>,
    _ messageLen: Int,
    _ publicKeySec1Compressed: UnsafePointer<UInt8>,
    _ validOut: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        validOut.pointee = 0
        return CRYPTO_INTERNAL_ERROR
    }

    let sigBytes = Data(bytes: signature, count: SECP256K1_SIGNATURE_LEN)
    let msgData = Data(bytes: message, count: messageLen)
    let digest = sha256(msgData)

    let pkData = Data(bytes: publicKeySec1Compressed, count: SECP256K1_PUBLIC_KEY_COMPRESSED_LEN)

    // Parse pubkey
    var pub = secp256k1_pubkey()

    let pkOk = pkData.withUnsafeBytes { pkPtr -> Int32 in
        guard let publicPointer = pkPtr.bindMemory(to: UInt8.self).baseAddress else {
            return CRYPTO_INTERNAL_ERROR
        }
        return secp256k1_ec_pubkey_parse(
            ctx,
            &pub,
            publicPointer,
            pkData.count
        )
    }
    if pkOk != 1 { validOut.pointee = 0; return CRYPTO_INVALID_KEY }

    // Parse signature
    var sig = secp256k1_ecdsa_signature()

    let sigOk = sigBytes.withUnsafeBytes { sPtr -> Int32 in
        guard let signaturePointer = sPtr.bindMemory(to: UInt8.self).baseAddress else {
            return CRYPTO_INTERNAL_ERROR
        }
        return secp256k1_ecdsa_signature_parse_compact(
            ctx,
            &sig,
            signaturePointer
        )
    }
    if sigOk != 1 { validOut.pointee = 0; return CRYPTO_INVALID_SIGNATURE }

    // Verify
    let ok = digest.withUnsafeBytes { dPtr -> Int32 in
        guard let digestPointer = dPtr.bindMemory(to: UInt8.self).baseAddress else {
            return CRYPTO_INTERNAL_ERROR
        }
        return withUnsafePointer(to: &sig) { sigPtr in
            withUnsafePointer(to: &pub) { pubPtr in
                secp256k1_ecdsa_verify(
                    ctx,
                    sigPtr,
                    digestPointer,
                    pubPtr
                )
            }
        }
    }

    validOut.pointee = (ok == 1) ? 1 : 0
    return CRYPTO_OK
}

// =======================
// ABI: BIP-340 Schnorr (x-only pubkey, 32-byte message)
// =======================

@_cdecl("bip340_schnorr_derive_public_key")
public func bip340_schnorr_derive_public_key(
    _ secretKey: UnsafePointer<UInt8>,
    _ publicKeyOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        return CRYPTO_INTERNAL_ERROR
    }

    var keypair = secp256k1_keypair()
    let keypairOk = secp256k1_keypair_create(ctx, &keypair, secretKey)
    if keypairOk != 1 {
        return CRYPTO_INVALID_KEY
    }

    var pubkey = secp256k1_xonly_pubkey()
    var parity: Int32 = 0
    let pubkeyOk = withUnsafePointer(to: &keypair) { keypairPointer in
        secp256k1_keypair_xonly_pub(ctx, &pubkey, &parity, keypairPointer)
    }
    if pubkeyOk != 1 {
        return CRYPTO_INTERNAL_ERROR
    }

    let serializeOk = withUnsafePointer(to: &pubkey) { pubkeyPointer in
        secp256k1_xonly_pubkey_serialize(ctx, publicKeyOut, pubkeyPointer)
    }
    if serializeOk != 1 {
        return CRYPTO_INTERNAL_ERROR
    }

    return CRYPTO_OK
}

@_cdecl("bip340_schnorr_sign")
public func bip340_schnorr_sign(
    _ secretKey: UnsafePointer<UInt8>,
    _ message32: UnsafePointer<UInt8>,
    _ auxRand32: UnsafePointer<UInt8>,
    _ signatureOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        return CRYPTO_INTERNAL_ERROR
    }

    var keypair = secp256k1_keypair()
    let keypairOk = secp256k1_keypair_create(ctx, &keypair, secretKey)
    if keypairOk != 1 {
        return CRYPTO_INVALID_KEY
    }

    let signOk = withUnsafePointer(to: &keypair) { keypairPointer in
        secp256k1_schnorrsig_sign32(
            ctx,
            signatureOut,
            message32,
            keypairPointer,
            auxRand32
        )
    }
    if signOk != 1 {
        return CRYPTO_INTERNAL_ERROR
    }

    return CRYPTO_OK
}

@_cdecl("bip340_schnorr_verify")
public func bip340_schnorr_verify(
    _ signature: UnsafePointer<UInt8>,
    _ message32: UnsafePointer<UInt8>,
    _ publicKeyXonly: UnsafePointer<UInt8>,
    _ validOut: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        validOut.pointee = 0
        return CRYPTO_INTERNAL_ERROR
    }

    var pubkey = secp256k1_xonly_pubkey()
    let parseOk = secp256k1_xonly_pubkey_parse(ctx, &pubkey, publicKeyXonly)
    if parseOk != 1 {
        validOut.pointee = 0
        return CRYPTO_INVALID_KEY
    }

    let verifyOk = withUnsafePointer(to: &pubkey) { pubkeyPointer in
        secp256k1_schnorrsig_verify(
            ctx,
            signature,
            message32,
            BIP340_SCHNORR_MESSAGE_LEN,
            pubkeyPointer
        )
    }

    validOut.pointee = (verifyOk == 1) ? 1 : 0
    return CRYPTO_OK
}

// =======================
// ABI: Encode/Decode (identity passthrough)
// =======================

@_cdecl("secp256k1_encode_public_key")
public func secp256k1_encode_public_key(
    _ publicKeyCompressed: UnsafePointer<UInt8>,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    memcpy(out, publicKeyCompressed, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN)
    return CRYPTO_OK
}

@_cdecl("secp256k1_decode_public_key")
public func secp256k1_decode_public_key(
    _ publicKeyCompressed: UnsafePointer<UInt8>,
    _ out: UnsafeMutablePointer<UInt8>
) -> Int32 {
    memcpy(out, publicKeyCompressed, SECP256K1_PUBLIC_KEY_COMPRESSED_LEN)
    return CRYPTO_OK
}

// =======================
// ABI: Decompress compressed SEC1 pubkey to x,y (32 bytes each)
// =======================

@_cdecl("secp256k1_decompress_public_key")
public func secp256k1_decompress_public_key(
    _ publicKeyCompressed: UnsafePointer<UInt8>,
    _ xOut: UnsafeMutablePointer<UInt8>,
    _ yOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard let ctx = SecpCtx.shared else {
        return CRYPTO_INTERNAL_ERROR
    }
    let pkData = Data(bytes: publicKeyCompressed, count: SECP256K1_PUBLIC_KEY_COMPRESSED_LEN)

    var pub = secp256k1_pubkey()

    let pkOk = pkData.withUnsafeBytes { pkPtr -> Int32 in
        guard let publicPointer = pkPtr.bindMemory(to: UInt8.self).baseAddress else {
            return CRYPTO_INTERNAL_ERROR
        }
        return secp256k1_ec_pubkey_parse(
            ctx,
            &pub,
            publicPointer,
            pkData.count
        )
    }
    if pkOk != 1 { return CRYPTO_INVALID_KEY }

    var outLen = SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN
    var outBuf = [UInt8](repeating: 0, count: outLen)

    let serOk = withUnsafePointer(to: &pub) { pubPtr in
        secp256k1_ec_pubkey_serialize(
            ctx, &outBuf, &outLen, pubPtr, UInt32(SECP256K1_EC_UNCOMPRESSED)
        )
    }
    if serOk != 1 || outLen != SECP256K1_PUBLIC_KEY_UNCOMPRESSED_LEN {
        return CRYPTO_INTERNAL_ERROR
    }
    if outBuf[0] != 0x04 { return CRYPTO_INTERNAL_ERROR }

    // outBuf = 0x04 || X(32) || Y(32)
    let copied = outBuf.withUnsafeBytes { buf -> Bool in
        guard let baseAddress = buf.baseAddress else {
            return false
        }
        memcpy(xOut, baseAddress.advanced(by: 1), 32)
        memcpy(yOut, baseAddress.advanced(by: 33), 32)
        return true
    }
    if !copied {
        return CRYPTO_INTERNAL_ERROR
    }

    return CRYPTO_OK
}
