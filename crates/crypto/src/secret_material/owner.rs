// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Layer responsible for a material buffer at an operation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BufferOwner {
    /// The caller owns borrowed input storage.
    Caller,
    /// The semantic Rust operation owns a result or temporary.
    OperationLayer,
    /// The protobuf contract owns an encoded request or response buffer.
    OperationContract,
    /// A C ABI or JNI adapter owns native memory for a caller.
    NativeAdapter,
    /// A managed SDK/runtime owns memory Rust cannot deterministically wipe.
    ManagedRuntime,
    /// A platform provider owns non-exportable key material.
    PlatformProvider,
}
