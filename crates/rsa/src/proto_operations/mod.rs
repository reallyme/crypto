// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected standalone RSA contracts; fixed root signature suites are unchanged.

mod admit_inputs;
mod copy_inputs;
mod recover_public_representatives;
mod verify_pss;

pub use recover_public_representatives::PublicRepresentativesInputs;
pub use verify_pss::RsaPssVerifyInputs;
