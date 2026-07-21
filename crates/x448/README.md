<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Crypto X448

Typed X448 key agreement for ReallyMe Crypto. Private keys and shared secrets
are fixed-size zeroize-on-drop owners. Imported public keys are rejected when
they have the wrong length or represent a low-order point.

The crate does not apply a KDF. Protocols such as HPKE remain responsible for
domain separation and shared-secret extraction.
