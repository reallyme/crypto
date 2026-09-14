// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

enum ReallyMeVectorFixtureError: Error {
  case missing
}

func reallyMeVectorURL(_ fileName: String) throws -> URL {
  let fileManager = FileManager.default
  var directory = URL(
    fileURLWithPath: fileManager.currentDirectoryPath,
    isDirectory: true
  ).standardizedFileURL

  for _ in 0..<8 {
    let candidate =
      directory
      .appendingPathComponent("vectors", isDirectory: true)
      .appendingPathComponent(fileName)
    if fileManager.fileExists(atPath: candidate.path) {
      return candidate
    }

    let parent = directory.deletingLastPathComponent()
    if parent.path == directory.path {
      break
    }
    directory = parent
  }

  throw ReallyMeVectorFixtureError.missing
}
