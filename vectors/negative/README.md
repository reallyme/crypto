<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Negative Vectors

Negative vectors contain malformed, tampered, downgraded, unsupported,
wrong-context, or boundary inputs that must fail closed.

Each vector must identify:

- primitive or backend under test;
- exact tamper or invalid condition;
- expected typed error variant;
- whether state must remain unchanged after failure;
- runtime lanes where the failure is executed or explicitly guarded.
