# Release Integrity

A ReallyMe Crypto release consists of versioned artifacts for Rust, Swift,
Kotlin/JVM, Android, and TypeScript. The [artifact requirements](../RELEASE_CHECKLIST.md)
state the properties that each published package must satisfy.

The release version and reviewed source commit must agree across published
artifacts. The Swift package's binary checksum must match its XCFramework
archive. JVM and Android packages must carry native libraries and integrity
manifests for their supported platforms. The npm package must include the WASM
module used by its public facade.

Release evidence includes package tests, cross-lane conformance vectors,
dependency checks, and integrity checks for the final artifacts. Supported
hardware routes require device evidence; a hardware skip does not count as a
successful device test. Public provenance and repository protection claims are
made only when independently verified.
