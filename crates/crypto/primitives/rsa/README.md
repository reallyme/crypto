<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-rsa

RSA verification for ReallyMe Crypto.

This crate verifies RSASSA-PKCS1-v1_5 and RSASSA-PSS signatures over SHA-1,
SHA-256, SHA-384, and SHA-512. SHA-1 is present only for legacy verification
contexts such as X.509 and eMRTD passive authentication; it is not exposed as a
general-purpose hash primitive.

Public keys may be supplied as PKCS#1 `RSAPublicKey` DER or X.509 SPKI DER.
Multikey callers should use PKCS#1 DER for the `rsa-pub` multicodec.

This crate verifies signatures only. It does not expose RSA encryption,
decryption, or signing.
