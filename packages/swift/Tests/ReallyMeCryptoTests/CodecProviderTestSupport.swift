// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import ReallyMeCrypto
import ReallyMeCodec
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
