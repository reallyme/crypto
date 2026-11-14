// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeCodec
import ReallyMeCrypto
import XCTest

@discardableResult
func installReallyMeCodecProviderForTest() throws -> ReallyMeCodec {
  let codec: ReallyMeCodec
  if let libraryPath = ProcessInfo.processInfo.environment["REALLYME_CODEC_FFI_LIBRARY_PATH"],
    !libraryPath.isEmpty
  {
    codec = try ReallyMeCodec(
      rustCAbiLibrary: ReallyMeCodecRustCAbiLibrary(path: libraryPath)
    )
  } else {
    codec = try ReallyMeCodec()
  }

  ReallyMeCryptoCodecProvider.install(codec)
  return codec
}
