// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

package me.really.crypto

/**
 * Typed SDK errors. Variants intentionally carry no secret or user-provided
 * bytes so callers can log the error without leaking key material or PII.
 */
public sealed class ReallyMeCryptoException(message: String) : Exception(message) {
    /** Input had the wrong shape: bad length, undecodable key, invalid scalar. */
    public class InvalidInput : ReallyMeCryptoException("invalid input")

    /** A well-formed signature did not verify. */
    public class InvalidSignature : ReallyMeCryptoException("invalid signature")

    /** The backing provider failed internally. */
    public class ProviderFailure : ReallyMeCryptoException("provider failure")

    /** Authentication or key-wrap integrity verification failed. */
    public class AuthenticationFailed : ReallyMeCryptoException("authentication failed")

    /** The package facade does not expose the requested algorithm yet. */
    public class UnsupportedAlgorithm : ReallyMeCryptoException("unsupported algorithm")
}
