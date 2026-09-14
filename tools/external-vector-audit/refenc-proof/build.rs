// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registers the `kani` cfg used by the shared reference encoder proof module.

fn main() {
    #[allow(clippy::print_stdout)]
    {
        println!("cargo::rustc-check-cfg=cfg(kani)");
    }
}
