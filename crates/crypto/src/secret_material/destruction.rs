// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Required destruction behavior for one material owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DestructionPolicy {
    /// Public material has no explicit destruction requirement.
    NoneRequired,
    /// The owning Rust value must zeroize its storage when dropped.
    ZeroizeOnDrop,
    /// The caller retains responsibility for clearing borrowed storage.
    CallerControlled,
    /// A managed runtime must clear mutable storage as a best effort.
    ManagedRuntimeBestEffort,
}
