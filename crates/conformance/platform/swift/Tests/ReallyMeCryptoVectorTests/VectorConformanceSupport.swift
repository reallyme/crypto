// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Secp256k1ABI
import Security
import SwiftProviderProbes
import XCTest

enum VectorError: Error {
  case repositoryRootNotFound
  case invalidBase64Url
  case emptyBuffer
  case invalidField
}

func loadVector<T: Decodable>(_ name: String) throws -> T {
  let data = try Data(contentsOf: vectorsDirectory().appendingPathComponent(name))
  return try JSONDecoder().decode(T.self, from: data)
}

func vectorsDirectory() throws -> URL {
  if let override = ProcessInfo.processInfo.environment["REALLYME_CRYPTO_VECTORS_DIR"] {
    return URL(fileURLWithPath: override, isDirectory: true)
  }

  var cursor = URL(fileURLWithPath: #filePath)
  while cursor.path != "/" {
    let candidate =
      cursor
      .appendingPathComponent("vectors", isDirectory: true)
      .appendingPathComponent("manifest.json")
    if FileManager.default.fileExists(atPath: candidate.path) {
      return candidate.deletingLastPathComponent()
    }
    cursor.deleteLastPathComponent()
  }

  throw VectorError.repositoryRootNotFound
}

extension Data {
  init(base64Url: String) throws {
    var value =
      base64Url
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = value.count % 4
    if remainder != 0 {
      value.append(String(repeating: "=", count: 4 - remainder))
    }

    guard let data = Data(base64Encoded: value) else {
      throw VectorError.invalidBase64Url
    }
    self = data
  }

  func base64UrlEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "=", with: "")
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
  }
}

extension SharedSecret {
  var rawBytes: Data {
    withUnsafeBytes { bytes in
      Data(bytes)
    }
  }
}
