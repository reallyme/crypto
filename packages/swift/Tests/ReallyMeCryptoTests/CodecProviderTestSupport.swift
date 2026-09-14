// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeCodec
import ReallyMeCrypto
import XCTest

func installReallyMeCodecProviderForTest() throws {
  if let libraryPath = ProcessInfo.processInfo.environment["REALLYME_CODEC_FFI_LIBRARY_PATH"],
    !libraryPath.isEmpty
  {
    let codec = try ReallyMeCodec(
      rustCAbiLibrary: ReallyMeCodecRustCAbiLibrary(path: libraryPath)
    )
    ReallyMeCryptoCodecProvider.install(codec)
    return
  }

  let codec = try ReallyMeCodec()
  ReallyMeCryptoCodecProvider.install(codec)
}
