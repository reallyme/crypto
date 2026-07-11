// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { sha256 as nobleSha256, sha384 as nobleSha384, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";
import {
  sha3_224 as nobleSha3_224,
  sha3_256 as nobleSha3_256,
  sha3_384 as nobleSha3_384,
  sha3_512 as nobleSha3_512,
} from "@noble/hashes/sha3.js";

/**
 * Small digest surface used by package tests and as the first package API
 * slice while algorithm wrappers are added one at a time. Mirrors the Swift
 * package's `ReallyMeDigest` and the Kotlin package's `ReallyMeDigest`.
 */
export const ReallyMeDigest = {
  sha256(bytes: Uint8Array): Uint8Array {
    return nobleSha256(bytes);
  },
  sha384(bytes: Uint8Array): Uint8Array {
    return nobleSha384(bytes);
  },
  sha512(bytes: Uint8Array): Uint8Array {
    return nobleSha512(bytes);
  },
  sha3_224(bytes: Uint8Array): Uint8Array {
    return nobleSha3_224(bytes);
  },
  sha3_256(bytes: Uint8Array): Uint8Array {
    return nobleSha3_256(bytes);
  },
  sha3_384(bytes: Uint8Array): Uint8Array {
    return nobleSha3_384(bytes);
  },
  sha3_512(bytes: Uint8Array): Uint8Array {
    return nobleSha3_512(bytes);
  },
} as const;
