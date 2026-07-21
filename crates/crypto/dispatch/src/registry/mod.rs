// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

mod key_exchange;
mod key_management;
mod signature;

pub use key_exchange::{derive_shared_secret, kem_decapsulate, kem_encapsulate};
pub use key_management::{derive_keypair, generate_keypair};
pub use signature::{sign, verify};
