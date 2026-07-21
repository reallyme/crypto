// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Deterministic generator that writes the cross-implementation conformance
//! vectors (keys, signatures, AEAD, KEM, and hashing) consumed by the
//! workspace's vector tests.

include!("imports.rs");
include!("constants.rs");
include!("error.rs");
include!("model.rs");
include!("io.rs");
include!("keys.rs");
include!("key_vectors.rs");
include!("rsa_and_symmetric.rs");
include!("kdf_hash_proto.rs");
include!("jwk.rs");
include!("manifest.rs");
include!("run.rs");
