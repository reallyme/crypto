#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check that runtime scan records exclude only non-published Gradle scopes."""

import unittest

from scripts.gradle_runtime_lockfiles import runtime_records


RUNTIME_DEPENDENCIES = (
    "com.google.code.gson:gson:2.14.0",
    "com.google.protobuf:protobuf-javalite:4.36.2",
    "com.google.protobuf:protobuf-kotlin-lite:4.36.2",
    "me.really:codec:0.3.0",
    "org.bouncycastle:bcprov-jdk18on:1.86",
    "org.jetbrains.kotlin:kotlin-stdlib:2.4.20",
)
REQUIRED_ARTIFACT = "me.really:codec"


class RuntimeLockfileTests(unittest.TestCase):
    def test_keeps_published_dependencies_and_excludes_tooling(self):
        source = "\n".join(
            [
                "# Gradle dependency lock",
                *(f"{dependency}=runtimeClasspath,testRuntimeClasspath" for dependency in RUNTIME_DEPENDENCIES),
                "io.netty:netty-codec:4.1.93.Final=androidLintTool,unified-test-platform-core",
                "empty=annotationProcessor",
            ]
        )
        generated = runtime_records(source, "runtimeClasspath", REQUIRED_ARTIFACT)
        for dependency in RUNTIME_DEPENDENCIES:
            self.assertIn(f"{dependency}=runtimeClasspath\n", generated)
        self.assertNotIn("netty-codec", generated)
        self.assertNotIn("testRuntimeClasspath", generated)

    def test_rejects_incomplete_or_malformed_source(self):
        complete = "\n".join(
            f"{dependency}=runtimeClasspath" for dependency in RUNTIME_DEPENDENCIES
        )
        for source in (
            complete.replace("runtimeClasspath", "testRuntimeClasspath", 1),
            complete + "\ninvalid-record",
            complete + "\nexample:artifact:1=runtimeClasspath,runtimeClasspath",
            complete + "\nexample:artifact=runtimeClasspath",
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    runtime_records(source, "runtimeClasspath", REQUIRED_ARTIFACT)

    def test_rejects_missing_codec_runtime_dependency(self):
        source = "\n".join(
            f"{dependency}=runtimeClasspath"
            for dependency in RUNTIME_DEPENDENCIES
            if not dependency.startswith("me.really:codec:")
        )
        with self.assertRaisesRegex(ValueError, "runtime dependencies are incomplete"):
            runtime_records(source, "runtimeClasspath", REQUIRED_ARTIFACT)


if __name__ == "__main__":
    unittest.main()
