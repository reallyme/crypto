<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# crypto-p521

NIST P-521 ECDSA primitive for ReallyMe Crypto.

The public API uses compressed SEC1 public keys, raw 66-byte private scalars,
SHA-512 prehashing, and DER-encoded ECDSA signatures. Secret key material is
returned in zeroizing buffers.

Verification fails closed with a typed error. It does not return a boolean.
