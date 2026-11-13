// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// One parameter type per RFC 5639 group, shared by the signature and supplied-
// base group interfaces. Neither interface defines a separate arithmetic engine.
#[path = "ecdsa_explicit/portable_brainpool/bp320.rs"]
pub(crate) mod bp320;
#[path = "ecdsa_explicit/portable_brainpool/bp512.rs"]
pub(crate) mod bp512;
