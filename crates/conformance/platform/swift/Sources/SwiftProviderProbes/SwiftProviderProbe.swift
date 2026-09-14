// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import BigInt
import Digest
import SwiftDilithium
import SwiftKyber

public enum SwiftProviderProbe {
  public static let compiledProviderNames: [String] = [
    "SwiftKyber",
    "SwiftDilithium",
    "BigInt",
    "Digest",
  ]
}
