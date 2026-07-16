// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of an SLH-DSA-SHA2-128s public key.
pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of an SLH-DSA-SHA2-128s serialized secret key.
pub const SLH_DSA_SHA2_128S_SECRET_KEY_LEN: usize = 64;
/// Length in bytes of an SLH-DSA-SHA2-128s detached signature.
pub const SLH_DSA_SHA2_128S_SIGNATURE_LEN: usize = 7_856;
/// Length in bytes of each FIPS 205 keygen seed component for SHA2-128s.
pub const SLH_DSA_SHA2_128S_KEYGEN_SEED_LEN: usize = 16;
