// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

typealias ReallyMeCryptoOperationResponseFunction = @convention(c) (
    UnsafePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<UInt8>?,
    Int,
    UnsafeMutablePointer<Int>?
) -> Int32

struct ReallyMeRustCAbiOperationResponseProcessor {
    // Mirrors MAX_CRYPTO_PROTO_MESSAGE_BYTES plus protobuf wrapper overhead.
    // Validate before allocation because the dylib path is caller-configurable.
    private static let maxProcessOutputLength = 1_048_608

    private let processOperationResponseFunction: ReallyMeCryptoOperationResponseFunction
    private let processOperationResponseJsonFunction: ReallyMeCryptoOperationResponseFunction

    init(library: ReallyMeRustCAbiLibrary) throws {
        processOperationResponseFunction = try library.loadFunction(
            "rm_crypto_process_operation_response",
            as: ReallyMeCryptoOperationResponseFunction.self
        )
        processOperationResponseJsonFunction = try library.loadFunction(
            "rm_crypto_process_operation_response_json",
            as: ReallyMeCryptoOperationResponseFunction.self
        )
    }

    init(
        processOperationResponseFunction: ReallyMeCryptoOperationResponseFunction,
        processOperationResponseJsonFunction: ReallyMeCryptoOperationResponseFunction
    ) {
        self.processOperationResponseFunction = processOperationResponseFunction
        self.processOperationResponseJsonFunction = processOperationResponseJsonFunction
    }

    func processOperationResponse(_ request: [UInt8]) throws -> [UInt8] {
        try process(request, with: processOperationResponseFunction)
    }

    func processOperationResponseJson(_ requestJson: [UInt8]) throws -> [UInt8] {
        try process(requestJson, with: processOperationResponseJsonFunction)
    }

    private func process(
        _ request: [UInt8],
        with function: ReallyMeCryptoOperationResponseFunction
    ) throws -> [UInt8] {
        var producedLength = 0
        var output = [UInt8](repeating: 0, count: Self.maxProcessOutputLength)
        let outputCapacity = output.count
        let status = request.withUnsafeBufferPointer { requestBuffer in
            output.withUnsafeMutableBufferPointer { outputBuffer in
                function(
                    requestBuffer.baseAddress,
                    request.count,
                    outputBuffer.baseAddress,
                    outputCapacity,
                    &producedLength
                )
            }
        }
        do {
            try ReallyMeRustCAbiStatus.throwIfError(status)
        } catch {
            ReallyMeCryptoMemory.bestEffortClear(&output)
            throw error
        }
        guard producedLength > 0, producedLength <= output.count else {
            ReallyMeCryptoMemory.bestEffortClear(&output)
            throw ReallyMeCryptoError.providerFailure
        }
        if producedLength < output.count {
            // The C ABI writes exactly producedLength bytes. Clear spare
            // capacity before truncating so Swift never retains stale bytes
            // from a future implementation that reuses backing storage.
            for index in producedLength..<output.count {
                output[index] = 0
            }
            output.removeSubrange(producedLength..<output.count)
        }
        return output
    }
}

extension ReallyMeCrypto {
    /// Executes one binary generated `CryptoOperationRequest`.
    ///
    /// The returned bytes are always a binary `CryptoOperationResponse` with a
    /// generated `CryptoOperationResult` or generated `CryptoError` outcome.
    public func processOperationResponse(_ request: [UInt8]) throws -> [UInt8] {
        guard let library = providers.rustCAbiLibrary else {
            throw ReallyMeCryptoError.providerFailure
        }
        return try ReallyMeRustCAbiOperationResponseProcessor(library: library).processOperationResponse(request)
    }

    /// Executes a permitted non-secret generated ProtoJSON request.
    ///
    /// JSON is request-only; secret-bearing selectors fail before value
    /// deserialization. Returned bytes use the same binary response as
    /// `processOperationResponse(_:)`.
    public func processOperationResponseJson(_ requestJson: [UInt8]) throws -> [UInt8] {
        guard let library = providers.rustCAbiLibrary else {
            throw ReallyMeCryptoError.providerFailure
        }
        return try ReallyMeRustCAbiOperationResponseProcessor(library: library).processOperationResponseJson(requestJson)
    }
}
