// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Best-effort cleanup for caller-owned managed-runtime byte arrays.
 *
 * This overwrites the supplied `Uint8Array` view in place. It does not and
 * cannot clear copies already made by JavaScript engines, WebAssembly
 * marshalling, snapshots, browser developer tools, or native providers.
 */
export const bestEffortClear = (bytes: Uint8Array): void => {
  bytes.fill(0);
};
