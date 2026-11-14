# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check proof input validation independently of Cargo and Kani."""

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from verify import CRATES_IO, VerificationError, prepare_archive, verify_resolution


class VerificationInputTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def make_archive(self, entries):
        archive = self.root / "hpke.crate"
        with tarfile.open(archive, "w:gz") as file:
            for name, content in entries:
                member = tarfile.TarInfo(name)
                if content is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../unverified"
                    file.addfile(member)
                    continue
                member.size = len(content)
                file.addfile(member, io.BytesIO(content))
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_extracts_verified_source(self):
        archive, checksum = self.make_archive([("hpke-1/src/aead.rs", b"source")])
        prepare_archive(archive, checksum, self.root, "hpke-1")
        self.assertEqual((self.root / "hpke-1/src/aead.rs").read_bytes(), b"source")

    def test_rejects_wrong_checksum_before_extraction(self):
        archive, _ = self.make_archive([("hpke-1/src/aead.rs", b"source")])
        with self.assertRaisesRegex(VerificationError, "checksum"):
            prepare_archive(archive, "0" * 64, self.root, "hpke-1")
        self.assertFalse((self.root / "hpke-1").exists())

    def test_rejects_unexpected_archive_entries(self):
        valid_entry = ("hpke-1/src/aead.rs", b"source")
        for invalid_entry in (
            ("hpke-1/../elsewhere", b"source"),
            ("/hpke-1/src/aead.rs", b"source"),
            ("unexpected/src/aead.rs", b"source"),
            ("hpke-1/src/alias.rs", None),
            valid_entry,
        ):
            with self.subTest(invalid_entry=invalid_entry):
                archive, checksum = self.make_archive([valid_entry, invalid_entry])
                with self.assertRaisesRegex(VerificationError, "unexpected entry"):
                    prepare_archive(archive, checksum, self.root, "hpke-1")
                self.assertFalse((self.root / "hpke-1").exists())

    def test_resolution_allows_only_the_local_backend_and_locked_dependencies(self):
        backend = {"name": "hpke", "version": "1.0.0"}
        dep = {
            "name": "aead",
            "version": "2.0.0",
            "source": CRATES_IO,
            "checksum": "1" * 64,
        }
        lock = f"""
[[package]]
name = "hpke"
version = "1.0.0"

[[package]]
name = "aead"
version = "2.0.0"
source = "{CRATES_IO}"
checksum = "{dep["checksum"]}"
"""
        verify_resolution(lock, [backend, dep], backend)

        with self.assertRaisesRegex(VerificationError, "HPKE version"):
            verify_resolution(lock.replace("1.0.0", "1.1.0"), [backend, dep], backend)
        with self.assertRaisesRegex(VerificationError, "differs from Cargo.lock"):
            verify_resolution(lock.replace("2.0.0", "2.0.1"), [backend, dep], backend)
        with self.assertRaisesRegex(VerificationError, "differs from Cargo.lock"):
            verify_resolution(lock.replace(dep["checksum"], "2" * 64), [backend, dep], backend)
        with self.assertRaisesRegex(VerificationError, "exactly one local proof package"):
            verify_resolution(
                lock + '\n[[package]]\nname = "extra"\nversion = "1.0.0"\n',
                [backend, dep],
                backend,
            )


if __name__ == "__main__":
    unittest.main()
