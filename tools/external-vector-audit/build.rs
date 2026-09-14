// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registers the `kani` cfg used by the `#[cfg(kani)]` proof harnesses so that
//! `unexpected_cfgs` stays quiet on normal builds (which run under `-Dwarnings`).
//! The Kani model checker sets `--cfg kani` itself when it compiles the crate.

fn main() {
    #[allow(clippy::print_stdout)]
    {
        println!("cargo::rustc-check-cfg=cfg(kani)");
    }
}
