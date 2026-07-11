// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
