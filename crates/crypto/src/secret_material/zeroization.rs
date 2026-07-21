// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Zeroization obligation attached to one material owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZeroizationPolicy {
    /// Public material does not require explicit zeroization.
    NotRequired,
    /// The owning Rust value must clear its storage on drop.
    OwnerZeroizesOnDrop,
    /// The operation borrows storage and the caller remains responsible.
    CallerRetainsResponsibility,
    /// Managed memory must be overwritten as soon as practical.
    ManagedRuntimeBestEffort,
}
