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

from verify import (
    CRATES_IO,
    VerificationError,
    locked_dependency,
    observe_x_wing_combiner,
    prepare_archive,
    restrict_ml_kem_to_one_chunk,
    verify_resolution,
)


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

    def test_chunk_projection_keeps_the_loop_bodies(self):
        encoding = self.root / "encoding.rs"
        loop_body = "for (v, b) in vc.zip(bc) { encode_chunk(v, b); }\n"
        original = (
            "let vc = vals.chunks(val_step);\n"
            "let bc = bytes.chunks_mut(byte_step);\n"
            f"{loop_body}"
            "let vc = vals.chunks_mut(val_step);\n"
            "let bc = bytes.chunks(byte_step);\n"
            "for (v, b) in vc.zip(bc) { decode_chunk(v, b); }\n"
        )
        encoding.write_text(original, encoding="utf-8")

        restrict_ml_kem_to_one_chunk(self.root)

        projected = encoding.read_text(encoding="utf-8")
        self.assertEqual(projected.count("vals[..val_step].chunks"), 2)
        self.assertEqual(projected.count("bytes[..byte_step].chunks"), 2)
        self.assertIn(loop_body, projected)
        self.assertIn("for (v, b) in vc.zip(bc) { decode_chunk(v, b); }", projected)

    def test_chunk_projection_rejects_an_unknown_layout(self):
        encoding = self.root / "encoding.rs"
        original = "let vc = vals.chunks(val_step);\n"
        encoding.write_text(original, encoding="utf-8")

        with self.assertRaisesRegex(VerificationError, "chunk layout changed"):
            restrict_ml_kem_to_one_chunk(self.root)

        self.assertEqual(encoding.read_text(encoding="utf-8"), original)

    def test_locked_dependency_picks_version_and_source_from_the_parent_edge(self):
        old = {"name": "keccak", "version": "0.1.6", "source": CRATES_IO}
        current = {"name": "keccak", "version": "0.2.2", "source": CRATES_IO}
        fork = {"name": "keccak", "version": "0.2.2", "source": "git+https://example.com/fork"}
        packages = [old, current, fork]
        owner = {"name": "sha3", "dependencies": [f"keccak 0.2.2 ({CRATES_IO})"]}

        self.assertIs(locked_dependency(packages, owner, "keccak"), current)
        for unresolved in ([], ["keccak"], ["keccak 0.2.2"], ["keccak 0.3.0"]):
            with self.subTest(reference=unresolved), self.assertRaises(VerificationError):
                locked_dependency(packages, {**owner, "dependencies": unresolved}, "keccak")

    def test_x_wing_observer_preserves_digest_input_calls_and_return(self):
        library = self.root / "lib.rs"
        calls = (
            "    hasher.update(ss_m);\n"
            "    hasher.update(ss_x);\n"
            "    hasher.update(ct_x);\n"
            "    hasher.update(pk_x.as_bytes());\n"
            "    hasher.update(X_WING_LABEL);\n"
            "    hasher.finalize()\n"
        )
        original = (
            "use sha3::Sha3_256;\n"
            "\nfn combiner(\n"
            "    ss_x: &x25519_dalek::SharedSecret,\n"
            ") -> SharedKey {\n"
            "    use sha3::Digest;\n\n"
            "    let mut hasher = Sha3_256::new();\n"
            f"{calls}"
            "}\n\nfn read_from() {}\n"
        )
        library.write_text(original, encoding="utf-8")

        observe_x_wing_combiner(library)

        observed = library.read_text(encoding="utf-8")
        self.assertIn(calls, observed)
        self.assertIn("ss_x: &impl AsRef<[u8]>", observed)
        self.assertIn("x_wing_combiner_proof_tests::Transcript::new()", observed)
        self.assertNotIn("Sha3_256", observed)

    def test_x_wing_observer_rejects_an_unknown_layout(self):
        library = self.root / "lib.rs"
        original = "use sha3::Sha3_256;\nfn combiner() {}\n"
        library.write_text(original, encoding="utf-8")

        with self.assertRaisesRegex(VerificationError, "combiner layout changed"):
            observe_x_wing_combiner(library)

        self.assertEqual(library.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
