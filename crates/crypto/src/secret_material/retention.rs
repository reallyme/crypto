// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Maximum intended lifetime of one material buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionPolicy {
    /// Borrowed only while the operation call is active.
    BorrowedForCall,
    /// Owned only until the operation completes or returns an error.
    OperationTemporary,
    /// Retained by the returned value until its owner drops it.
    ResultLifetime,
    /// Retained by a provider under its documented key-lifecycle policy.
    ProviderManaged,
}
