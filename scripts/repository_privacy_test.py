# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exercise staged, historical, and force-added local-file protections."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parent.parent
CHECKER = SOURCE / "scripts/check_repository_privacy.py"
INSTALLER = SOURCE / "scripts/install_repository_hooks.py"
LOCAL_NAMES = ("AGENTS.md", ".claude/state", ".codex/state", ".local/state", ".build/state")


class RepositoryPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="privacy-guard-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.environment = dict(os.environ)
        identity = subprocess.check_output(
            ["git", "-C", str(SOURCE), "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", "HEAD"]
        ).rstrip(b"\n").decode().split("\0")
        for key, value in zip(
            ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"), identity
        ):
            self.environment[key] = value
        self.git("-c", "init.templateDir=", "init", "--quiet")
        self.write(".gitignore", "private/\n*.key\n**/generated/**\n!src/generated/**\n")
        self.write("public.txt", "public source\n")
        self.git("add", ".")
        self.commit("Initial public source")
        self.base = self.git("rev-parse", "HEAD").stdout.strip().decode()

    def git(self, *arguments, data=None, check=True):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment, check=check,
        )

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def commit(self, message):
        self.git("-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.strip().decode()

    def check(self, *arguments, data=None):
        return subprocess.run(
            ["python3", "-B", str(CHECKER), *arguments], cwd=self.root, input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment, check=False,
        )

    def install_files(self):
        for name in (".githooks/pre-commit", ".githooks/pre-push",
                     "scripts/check_repository_privacy.py", "scripts/repository_privacy.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, path)
            if name.startswith(".githooks/"):
                path.chmod(0o755)

    def test_clean_index_and_explicit_generated_source_exception(self):
        self.write("src/generated/public.rs", "// public binding\n")
        self.git("add", "src/generated/public.rs")
        self.assertEqual(self.check("--index").returncode, 0)

    def test_force_added_reserved_names_are_rejected_at_every_depth(self):
        for name in LOCAL_NAMES:
            for prefix in ("", "nested/"):
                with self.subTest(name=prefix + name):
                    path = self.write(prefix + name, "local test data\n")
                    self.git("add", "--force", "--", prefix + name)
                    result = self.check("--index")
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(path.read_text(), "local test data\n")
                    self.git("rm", "--cached", "--force", "--", prefix + name)

    def test_previously_tracked_file_becomes_rejected_when_policy_excludes_it(self):
        self.write(".gitignore", "private/\npublic.txt\n")
        self.git("add", ".gitignore")
        self.assertEqual(self.check("--index").returncode, 1)
        self.assertEqual((self.root / "public.txt").read_text(), "public source\n")

    def test_unstaged_ignore_edit_cannot_hide_force_added_file(self):
        self.write("private/local.key", "local test data\n")
        self.git("add", "--force", "private/local.key")
        self.write(".gitignore", "# unstaged exclusion removal\n")
        self.assertEqual(self.check("--index").returncode, 1)

    def test_new_unstaged_ignore_rule_also_blocks_a_force_added_file(self):
        path = self.write("new-private.json", "local test data\n")
        with (self.root / ".gitignore").open("a") as policy:
            policy.write("new-private.json\n")
        self.git("add", "--force", "new-private.json")
        self.assertEqual(self.check("--index").returncode, 1)
        self.assertEqual(path.read_text(), "local test data\n")

    def test_staged_policy_removal_cannot_bypass_the_trusted_base(self):
        self.write(".gitignore", "# staged exclusion removal\n")
        self.write("private/local.key", "local test data\n")
        self.git("add", "--force", ".gitignore", "private/local.key")
        self.assertEqual(self.check("--index").returncode, 1)

    def test_nested_rules_and_escaped_diagnostics(self):
        self.write("nested/.gitignore", "local-data/\n")
        self.write("nested/local-data/new\nline.txt", "local test data\n")
        self.git("add", "nested/.gitignore")
        self.git("add", "--force", "nested/local-data/new\nline.txt")
        result = self.check("--index")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"new\\nline.txt", result.stderr)
        self.assertNotIn(b"local test data", result.stderr)

    def test_ignore_symlinks_are_rejected_without_reading_target_contents(self):
        (self.root / ".gitignore").unlink()
        self.write("policy-target", "local policy test data\n")
        (self.root / ".gitignore").symlink_to("policy-target")
        self.git("add", ".gitignore")
        result = self.check("--index")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"local policy test data", result.stderr)

    def test_command_characters_in_names_are_not_executed(self):
        name = "private/$(touch unexpected).key"
        self.write(name, "local test data\n")
        self.git("add", "--force", "--", name)
        self.assertEqual(self.check("--index").returncode, 1)
        self.assertFalse((self.root / "unexpected").exists())

    def test_symlink_cannot_publish_an_ignored_target_under_a_public_name(self):
        self.write(".local/instructions", "local test data\n")
        (self.root / "public-link").symlink_to(".local/instructions")
        self.git("add", "public-link")
        self.assertEqual(self.check("--index").returncode, 1)

    def test_gitlink_cannot_bypass_a_directory_only_exclusion(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},private")
        self.assertEqual(self.check("--index").returncode, 1)

    def test_hook_environment_cannot_redirect_temporary_git_operations(self):
        before = (self.root / ".git/config").read_bytes()
        self.environment.update(GIT_DIR=str(self.root / ".git"), GIT_WORK_TREE=str(self.root))
        self.write("private/local.key", "local test data\n")
        self.git("add", "--force", "private/local.key")
        self.assertEqual(self.check("--index").returncode, 1)
        self.assertEqual((self.root / ".git/config").read_bytes(), before)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip().decode(), self.base)

    def test_alternate_staged_index_is_checked_and_primary_index_preserved(self):
        primary = self.root / ".git/index"
        before = primary.read_bytes()
        alternate = self.root / ".git/privacy-test-index"
        alternate.write_bytes(before)
        self.environment["GIT_INDEX_FILE"] = str(alternate)
        self.write("private/local.key", "local test data\n")
        self.git("add", "--force", "private/local.key")
        self.assertEqual(self.check("--index").returncode, 1)
        self.assertEqual(primary.read_bytes(), before)

    def test_commit_hook_blocks_force_add_and_preserves_local_contents(self):
        self.install_files()
        self.git("config", "core.hooksPath", str(self.root / ".githooks"))
        self.write("AGENTS.md", "local instructions for test\n")
        self.git("add", "--force", "AGENTS.md")
        result = self.git("commit", "--quiet", "-m", "Rejected local file", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip().decode(), self.base)
        self.assertEqual((self.root / "AGENTS.md").read_text(), "local instructions for test\n")

    def private_history(self):
        self.write("private/local.key", "local test data\n")
        self.git("add", "--force", "private/local.key")
        bad = self.commit("Fixture containing an excluded file")
        self.git("rm", "private/local.key")
        tip = self.commit("Fixture with the excluded file removed")
        return bad, tip

    def test_pre_push_rejects_private_intermediate_commit_even_after_deletion(self):
        _, tip = self.private_history()
        data = f"refs/heads/main {tip} refs/heads/main {self.base}\n".encode()
        self.assertEqual(self.check("--pre-push", data=data).returncode, 1)
        self.assertEqual(self.check("--index").returncode, 0)

    def test_new_ref_and_multiple_updates_cannot_hide_ancestral_private_files(self):
        bad, tip = self.private_history()
        data = (f"refs/heads/new {tip} refs/heads/new {'0' * 40}\n"
                f"refs/heads/other {bad} refs/heads/other {bad}\n").encode()
        self.assertEqual(self.check("--pre-push", data=data).returncode, 1)

    def test_unknown_remote_base_fails_closed_by_scanning_outbound_ancestry(self):
        _, tip = self.private_history()
        data = f"refs/heads/main {tip} refs/heads/main {'f' * 40}\n".encode()
        self.assertEqual(self.check("--pre-push", data=data).returncode, 1)

    def test_commit_range_and_new_branch_ci_detect_intermediate_exposure(self):
        _, tip = self.private_history()
        self.assertEqual(self.check("--commit", tip, "--base", self.base).returncode, 1)
        self.assertEqual(self.check("--commit", tip, "--all-ancestors").returncode, 1)

    def test_malformed_push_input_fails_closed(self):
        for data in (b"missing fields\n", b"ref not-an-object ref invalid\n"):
            with self.subTest(data=data):
                self.assertEqual(self.check("--pre-push", data=data).returncode, 2)

    def test_deleted_ref_requires_no_new_content_validation(self):
        data = f"(delete) {'0' * 40} refs/heads/old {self.base}\n".encode()
        self.assertEqual(self.check("--pre-push", data=data).returncode, 0)

    def test_installer_preserves_existing_hook_configuration(self):
        self.install_files()
        self.git("config", "core.hooksPath", "existing-hooks")
        result = subprocess.run(["python3", "-B", str(INSTALLER)], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.git("config", "--get", "core.hooksPath").stdout.strip(), b"existing-hooks")

    def test_installer_preserves_existing_executable_hook(self):
        self.install_files()
        hook = self.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
        result = subprocess.run(["python3", "-B", str(INSTALLER)], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(hook.read_text(), "#!/bin/sh\nexit 0\n")

    def test_installer_is_idempotent_and_uses_a_local_absolute_hook_path(self):
        self.install_files()
        for _ in range(2):
            result = subprocess.run(["python3", "-B", str(INSTALLER)], cwd=self.root, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        configured = self.git("config", "--local", "--get", "core.hooksPath").stdout.strip()
        self.assertEqual(Path(os.fsdecode(configured)), self.root / ".githooks")


if __name__ == "__main__":
    unittest.main()
