// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

mod encoding;
mod keypair;
mod sign;
mod verify;

pub use encoding::{assert_public_key, decode_public_key, encode_public_key};
pub use keypair::{generate_ed25519_keypair, generate_ed25519_keypair_from_seed};
pub use sign::sign_ed25519;
pub use verify::verify_ed25519;
