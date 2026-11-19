# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cover excluded, malformed, nested, and traversal release-archive members."""

import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from urllib.parse import quote
import zipfile


SOURCE = Path(__file__).resolve().parent.parent
CHECKER = SOURCE / "scripts/check_release_privacy.py"


class ReleasePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="release-privacy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        subprocess.run(["git", "-C", str(self.root), "-c", "init.templateDir=", "init", "--quiet"], check=True)
        (self.root / ".gitignore").write_text(
            "private/\ndist/\n.env\n**/generated/**\n!crates/proto/src/generated/**\n"
        )
        subprocess.run(["git", "-C", str(self.root), "add", ".gitignore"], check=True)

    def check(self, *args, data=None):
        return subprocess.run(["python3", "-B", str(CHECKER), *args], cwd=self.root,
                              input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def zip(self, name, members):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, content in members:
                archive.writestr(member, content)
        return path

    def tar(self, name, members):
        path = self.root / name
        with tarfile.open(path, "w:gz") as archive:
            for member, content in members:
                info = tarfile.TarInfo(member)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    def test_clean_zip_and_tar_archives_pass(self):
        for path in (self.zip("clean.zip", [("lib/public.so", b"public")]),
                     self.tar("clean.tgz", [("src/public.rs", b"public")])):
            with self.subTest(path=path):
                self.assertEqual(self.check("--archive", str(path)).returncode, 0)

    def test_all_local_state_names_are_rejected_at_any_depth(self):
        for name in ("AGENTS.md", ".claude/state", ".codex/state", ".local/state", ".build/state"):
            for prefix in ("", "nested/"):
                path = self.zip("private.zip", [(prefix + name, b"local test data")])
                result = self.check("--archive", str(path))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn(b"local test data", result.stderr)

    def test_policy_applies_to_tar_members_and_npm_dist_layout(self):
        for name in ("package/.env", "package/dist/index.js"):
            path = self.tar("package.tgz", [(name, b"public or local test data")])
            result = self.check("--archive", str(path), "--source-root", "packages/ts", "--strip-components", "1")
            self.assertEqual(result.returncode, 1, result.stderr)

    def test_source_mapping_preserves_explicit_generated_binding_exception(self):
        path = self.tar("proto.crate", [("proto-1.0.0/src/generated/public.rs", b"public")])
        result = self.check("--archive", str(path), "--source-root", "crates/proto", "--strip-components", "1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_android_metadata_exception_does_not_admit_adjacent_files(self):
        # Use the production rules so narrowing this exception remains covered.
        (self.root / ".gitignore").write_bytes((SOURCE / ".gitignore").read_bytes())
        subprocess.run(["git", "-C", str(self.root), "add", ".gitignore"], check=True)
        metadata = "META-INF/com/android/build/gradle/aar-metadata.properties"
        path = self.zip("metadata.aar", [(metadata, b"aarFormatVersion=1.0\n")])
        self.assertEqual(self.check("--archive", str(path)).returncode, 0)
        for excluded in (metadata + ".local", "META-INF/com/android/build/private",
                         "META-INF/com/android/build/gradle/private", "nested/build/private"):
            path = self.zip("excluded.aar", [(excluded, b"local test data")])
            self.assertEqual(self.check("--archive", str(path)).returncode, 1, excluded)

    def test_stripped_archive_wrapper_cannot_hide_private_directory(self):
        path = self.tar("private.tgz", [(".local/public.txt", b"local test data")])
        self.assertEqual(self.check("--archive", str(path), "--strip-components", "1").returncode, 1)

    def test_stripped_wrapper_must_also_obey_ordinary_ignore_rules(self):
        for prefix in ("private", "dist"):
            with self.subTest(prefix=prefix):
                path = self.tar("wrapper.tgz", [(prefix + "/public.txt", b"local test data")])
                self.assertEqual(self.check("--archive", str(path), "--strip-components", "1").returncode, 1)

    def test_nested_jar_inside_publication_bundle_is_scanned(self):
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("nested/AGENTS.md", b"local test data")
        path = self.zip("bundle.zip", [("public.jar", nested.getvalue())])
        self.assertEqual(self.check("--archive", str(path)).returncode, 1)

    def test_path_traversal_absolute_and_backslash_names_fail_closed(self):
        for name in ("../AGENTS.md", "/private/data", "C:/private/data", "public\\AGENTS.md"):
            with self.subTest(name=name):
                path = self.zip("unsafe.zip", [(name, b"local test data")])
                self.assertNotEqual(self.check("--archive", str(path)).returncode, 0)

    def test_symlink_to_excluded_target_is_rejected(self):
        path = self.root / "link.zip"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("public-link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, ".local/data")
        self.assertEqual(self.check("--archive", str(path)).returncode, 1)

    def test_tar_link_escaping_archive_is_rejected(self):
        path = self.root / "link.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("public-link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
            archive.addfile(info)
        self.assertNotEqual(self.check("--archive", str(path)).returncode, 0)

    def test_duplicate_and_malformed_archives_are_rejected(self):
        path = self.tar("duplicate.tgz", [("public", b"one"), ("public", b"two")])
        self.assertNotEqual(self.check("--archive", str(path)).returncode, 0)
        path.write_bytes(b"not an archive")
        self.assertEqual(self.check("--archive", str(path)).returncode, 2)

    def test_untrusted_names_cannot_inject_extra_diagnostic_lines(self):
        path = self.zip("unsafe.zip", [(".local/new\nline", b"local test data")])
        result = self.check("--archive", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"new\\nline", result.stderr)
        self.assertEqual(len(result.stderr.splitlines()), 1)

    def test_nul_delimited_publication_paths_and_malformed_list(self):
        self.assertEqual(self.check("--paths-stdin", data=b"lib/public.js\0").returncode, 0)
        self.assertEqual(self.check("--paths-stdin", data=b".local/data\0").returncode, 1)
        self.assertEqual(self.check("--paths-stdin", data=b"lib/public.js").returncode, 1)

    def test_staging_directory_does_not_follow_filesystem_symlinks(self):
        directory = self.root / "staging"
        directory.mkdir()
        (directory / "escape").symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.check("--directory", str(directory)).returncode, 1)

    def test_excluded_empty_directory_is_not_published(self):
        path = self.zip("directory.zip", [("dist/", b"")])
        self.assertEqual(self.check("--archive", str(path)).returncode, 1)

    def test_direct_maven_uploader_rejects_private_artifact_before_network(self):
        for name in ("upload_maven_central_bundle.mjs", "check_release_privacy.py",
                     "check_repository_privacy.py", "repository_privacy.py"):
            destination = self.root / "scripts" / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copyfile(SOURCE / "scripts" / name, destination)
        archive = self.zip("bundle.zip", [("nested/AGENTS.md", b"local test data")])
        environment = dict(os.environ)
        environment.update(CENTRAL_PORTAL_USERNAME="fixture-user", CENTRAL_PORTAL_PASSWORD="fixture-password")
        # Any request is a failure, including on hosts with network access.
        preload = "data:text/javascript," + quote("globalThis.fetch = () => { process.exit(97); };")
        result = subprocess.run(
            ["node", "--import", preload, str(self.root / "scripts/upload_maven_central_bundle.mjs"),
             str(archive), "1.0.0"], cwd=self.root, env=environment, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"publication-privacy-rejected", result.stderr)
        self.assertNotIn(b"local test data", result.stderr)

    def test_nested_archive_depth_limit_fails_closed(self):
        nested = b"public payload"
        name = "public.txt"
        for _ in range(6):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(name, nested)
            nested = stream.getvalue()
            name = "nested.zip"
        path = self.root / "nested.zip"
        path.write_bytes(nested)
        result = self.check("--archive", str(path))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"nested-limit", result.stderr)

    def test_case_variants_cannot_bypass_permanent_exclusions(self):
        for name in ("nested/aGeNtS.Md", ".LOCAL/data", "nested/.BUILD/data"):
            with self.subTest(name=name):
                path = self.zip("private.zip", [(name, b"local test data")])
                self.assertEqual(self.check("--archive", str(path)).returncode, 1)


if __name__ == "__main__":
    unittest.main()
