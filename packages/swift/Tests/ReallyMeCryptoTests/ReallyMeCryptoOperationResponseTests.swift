// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
@testable import ReallyMeCrypto
import XCTest

extension ReallyMeCryptoRustCAbiTests {
    func testPrimaryOperationResponseProcessorExecutesNativeOnce() throws {
        resetOperationResponseSingleCallFixture()
        let processor = ReallyMeRustCAbiOperationResponseProcessor(
            processOperationResponseFunction: operationResponseSingleCallFixture,
            processOperationResponseJsonFunction: operationResponseSingleCallFixture
        )

        XCTAssertEqual(
            try processor.processOperationResponse([0x09]),
            operationResponseSingleCallFixtureExpectedOutput
        )
        XCTAssertEqual(operationResponseSingleCallFixtureCallCount, 1)
    }

    func testGenericProtoAndProtoJsonLanesMatchGeneratedVector() throws {
        let library = try Self.configuredRustCAbiLibrary()
        let crypto = ReallyMeCrypto(
            providers: ReallyMeCryptoProviders(rustCAbiLibrary: library)
        )
        let vectorURL = try reallyMeVectorURL("operation_response.json")
        let vector = try JSONDecoder().decode(
            OperationResponseVector.self,
            from: Data(contentsOf: vectorURL)
        )

        XCTAssertEqual(
            try crypto.processOperationResponse(Self.base64UrlBytes(vector.requestProtobuf)),
            try Self.base64UrlBytes(vector.operationResponse)
        )
        XCTAssertEqual(
            try crypto.processOperationResponseJson(Self.base64UrlBytes(vector.requestJson)),
            try Self.base64UrlBytes(vector.operationResponse)
        )
        XCTAssertEqual(
            try crypto.processOperationResponse(Self.base64UrlBytes(vector.malformedProtobuf)),
            try Self.base64UrlBytes(vector.malformedProtobufResponse)
        )
        XCTAssertEqual(
            try crypto.processOperationResponseJson(Self.base64UrlBytes(vector.malformedJson)),
            try Self.base64UrlBytes(vector.malformedJsonResponse)
        )
    }
}

nonisolated(unsafe) private var operationResponseSingleCallFixtureCallCount = 0
private let operationResponseSingleCallFixtureExpectedOutput: [UInt8] = [0x01, 0x02, 0x03]

private func resetOperationResponseSingleCallFixture() {
    operationResponseSingleCallFixtureCallCount = 0
}

private func operationResponseSingleCallFixture(
    _: UnsafePointer<UInt8>?,
    _: Int,
    _ output: UnsafeMutablePointer<UInt8>?,
    _ outputLength: Int,
    _ producedLength: UnsafeMutablePointer<Int>?
) -> Int32 {
    operationResponseSingleCallFixtureCallCount += 1
    producedLength?.pointee = operationResponseSingleCallFixtureExpectedOutput.count
    guard let output, outputLength >= operationResponseSingleCallFixtureExpectedOutput.count else {
        return ReallyMeRustCAbiStatus.bufferTooSmall
    }
    for (index, byte) in operationResponseSingleCallFixtureExpectedOutput.enumerated() {
        output.advanced(by: index).pointee = byte
    }
    if outputLength > operationResponseSingleCallFixtureExpectedOutput.count {
        output.advanced(by: operationResponseSingleCallFixtureExpectedOutput.count).pointee = 0xA5
    }
    return ReallyMeRustCAbiStatus.ok
}

private struct OperationResponseVector: Decodable {
    let requestProtobuf: String
    let requestJson: String
    let operationResponse: String
    let malformedProtobuf: String
    let malformedProtobufResponse: String
    let malformedJson: String
    let malformedJsonResponse: String

    private enum CodingKeys: String, CodingKey {
        case requestProtobuf = "request_protobuf"
        case requestJson = "request_json"
        case operationResponse = "operation_response"
        case malformedProtobuf = "malformed_protobuf"
        case malformedProtobufResponse = "malformed_protobuf_response"
        case malformedJson = "malformed_json"
        case malformedJsonResponse = "malformed_json_response"
    }
}
