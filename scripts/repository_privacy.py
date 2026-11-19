# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Evaluate repository-controlled ignore rules without trusting working files."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import os
import posixpath
import re
import subprocess
import tempfile


MAX_PATH_BYTES = 4096
MAX_PATHS = 250_000
MAX_IGNORE_FILES = 1024
MAX_IGNORE_BYTES = 4 * 1024 * 1024
MAX_COMMITS = 20_000
PRIVATE_COMPONENTS = frozenset(
    (b"agents.md", b".git", b".claude", b".codex", b".local", b".build")
)
OBJECT_ID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class PrivacyReason(Enum):
    GIT_FAILURE = "git-failure"
    INVALID_PATH = "invalid-path"
    INVALID_SNAPSHOT = "invalid-snapshot"
    INVALID_POLICY = "invalid-policy"
    LIMIT_EXCEEDED = "limit-exceeded"
    INVALID_PUSH = "invalid-push"


class RepositoryPrivacyError(Exception):
    def __init__(self, reason):
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True)
class Entry:
    mode: bytes
    object_id: bytes
    path: bytes


@dataclass(frozen=True)
class Violation:
    path: bytes
    rule: bytes
    revision: str = "index"


def git(repository, arguments, data=None, accepted=(0,), isolated=False):
    """Never pass refs or paths through a shell, or expose backend diagnostics."""
    environment = dict(os.environ)
    if isolated:
        # Hooks export repository-local Git variables. Carrying them into the
        # policy sandbox could redirect Git back to the caller's real index
        # or configuration instead of the temporary repository.
        environment = {key: value for key, value in environment.items() if not key.startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    result = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if result.returncode not in accepted:
        raise RepositoryPrivacyError(PrivacyReason.GIT_FAILURE)
    return result.stdout


def repository_root():
    result = git(Path.cwd(), ["rev-parse", "--show-toplevel"])
    return Path(os.fsdecode(result.rstrip(b"\n"))).resolve()


def checked_path(path):
    if (
        not path
        or len(path) > MAX_PATH_BYTES
        or b"\0" in path
        or b"\\" in path
        or path.startswith(b"/")
        or re.match(rb"[A-Za-z]:", path)
        or any(part in (b"", b".", b"..") for part in path.split(b"/"))
    ):
        raise RepositoryPrivacyError(PrivacyReason.INVALID_PATH)
    return path


def private_path(path):
    # These local-state names stay private even if a nested rule tries to
    # unignore them. Case folding covers case-insensitive developer systems.
    return any(part.lower() in PRIVATE_COMPONENTS for part in path.split(b"/"))


def resolve_commit(repository, revision):
    result = git(
        repository,
        ["rev-parse", "--verify", "--end-of-options", revision + "^{commit}"],
    ).strip()
    if OBJECT_ID.fullmatch(result) is None:
        raise RepositoryPrivacyError(PrivacyReason.INVALID_SNAPSHOT)
    return result.decode("ascii")


def entries(repository, revision=None):
    if revision is None:
        output = git(repository, ["ls-files", "--stage", "-z"])
    else:
        revision = resolve_commit(repository, revision)
        output = git(repository, ["ls-tree", "-r", "-z", revision])
    result = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        fields = metadata.split()
        if separator != b"\t" or len(fields) != 3:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_SNAPSHOT)
        if revision is None:
            mode, object_id, stage = fields
            if stage != b"0":
                raise RepositoryPrivacyError(PrivacyReason.INVALID_SNAPSHOT)
        else:
            mode, _, object_id = fields
        if OBJECT_ID.fullmatch(object_id) is None:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_SNAPSHOT)
        result.append(Entry(mode, object_id, checked_path(path)))
        if len(result) > MAX_PATHS:
            raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
    return result


class IgnorePolicy:
    """Let Git interpret escapes, nested rules, directories, and negations.

    Only ignore blobs from the selected Git snapshot are materialized. A
    force-added file cannot hide behind an unstaged .gitignore edit, and no
    candidate source code, symlink, Git config, or hook is executed.
    """

    def __init__(self, repository, snapshot_entries):
        self.repository = repository
        self.snapshot_entries = snapshot_entries
        self.temporary = None
        self.root = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="repository-ignore-policy-")
        self.root = Path(self.temporary.name)
        try:
            git(self.root, ["-c", "init.templateDir=", "init", "--quiet"], isolated=True)
            policies = [
                item for item in self.snapshot_entries
                if item.path.split(b"/")[-1] == b".gitignore"
            ]
            if not any(item.path == b".gitignore" for item in policies):
                raise RepositoryPrivacyError(PrivacyReason.INVALID_POLICY)
            if len(policies) > MAX_IGNORE_FILES:
                raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
            total = 0
            for item in policies:
                if item.mode not in (b"100644", b"100755"):
                    raise RepositoryPrivacyError(PrivacyReason.INVALID_POLICY)
                size = int(git(self.repository, ["cat-file", "-s", item.object_id.decode()]))
                total += size
                if total > MAX_IGNORE_BYTES:
                    raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
                content = git(self.repository, ["cat-file", "blob", item.object_id.decode()])
                if len(content) != size or b"\0" in content:
                    raise RepositoryPrivacyError(PrivacyReason.INVALID_POLICY)
                destination = self.root / os.fsdecode(item.path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
        except BaseException:
            self.temporary.cleanup()
            raise
        return self

    def __exit__(self, *_):
        self.temporary.cleanup()

    def violations(self, paths, revision="index"):
        if len(paths) > MAX_PATHS:
            raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
        for path in paths:
            checked_path(path)
        result = [
            Violation(path, b"permanent local-state exclusion", revision)
            for path in paths if private_path(path)
        ]
        if not paths:
            return result
        output = git(
            self.root,
            ["-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index",
             "--verbose", "--non-matching", "-z", "--stdin"],
            b"\0".join(paths) + b"\0",
            accepted=(0, 1),
            isolated=True,
        )
        fields = output.split(b"\0")
        if fields[-1] != b"" or len(fields) != len(paths) * 4 + 1:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_POLICY)
        for index, expected in enumerate(paths):
            source, _, pattern, actual = fields[index * 4:index * 4 + 4]
            if actual != expected:
                raise RepositoryPrivacyError(PrivacyReason.INVALID_POLICY)
            if pattern and not pattern.startswith(b"!"):
                result.append(Violation(actual, source + b": " + pattern, revision))
        return result


def snapshot_violations(repository, policy, snapshot, label):
    result = policy.violations([item.path for item in snapshot], label)
    for item in snapshot:
        if item.mode == b"160000":
            # A Git link represents a directory. The isolated policy tree
            # contains no submodule checkout, so probe a child explicitly to
            # retain Git's directory-only exclusion semantics.
            for violation in policy.violations([item.path + b"/privacy-directory-probe"], label):
                result.append(Violation(item.path, violation.rule, label))
            continue
        if item.mode != b"120000":
            continue
        size = int(git(repository, ["cat-file", "-s", item.object_id.decode()]))
        if size == 0 or size > MAX_PATH_BYTES:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_PATH)
        target = git(repository, ["cat-file", "blob", item.object_id.decode()])
        if target.startswith(b"/") or b"\\" in target:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_PATH)
        resolved = checked_path(posixpath.normpath(posixpath.join(posixpath.dirname(item.path), target)))
        for violation in policy.violations([resolved], label):
            result.append(Violation(item.path, b"excluded symlink target: " + violation.rule, label))
    return result


def check_snapshot(repository, revision=None, trusted_revision=None):
    selected = entries(repository, revision)
    label = revision or "index"
    with IgnorePolicy(repository, selected) as policy:
        result = snapshot_violations(repository, policy, selected, label)
    # The trusted/base rules prevent a candidate from removing an exclusion
    # and force-adding its previously private files in the same change.
    if trusted_revision is not None:
        with IgnorePolicy(repository, entries(repository, trusted_revision)) as policy:
            result.extend(snapshot_violations(repository, policy, selected, label))
    return sorted(set(result), key=lambda item: (item.path, item.rule, item.revision))


def history_commits(repository, tips, excludes=()):
    resolved = [resolve_commit(repository, tip) for tip in tips]
    arguments = ["rev-list", "--topo-order", *resolved]
    if excludes:
        arguments.extend(["--not", *(resolve_commit(repository, ref) for ref in excludes)])
    result = git(repository, arguments).splitlines()
    if len(result) > MAX_COMMITS or any(OBJECT_ID.fullmatch(row) is None for row in result):
        raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
    return [row.decode("ascii") for row in result]


def check_history(repository, tips, excludes=(), trusted_revision="HEAD"):
    result = []
    with IgnorePolicy(repository, entries(repository, trusted_revision)) as trusted:
        for commit in history_commits(repository, tips, excludes):
            snapshot = entries(repository, commit)
            result.extend(snapshot_violations(repository, trusted, snapshot, commit))
            with IgnorePolicy(repository, snapshot) as candidate:
                result.extend(snapshot_violations(repository, candidate, snapshot, commit))
    return sorted(set(result), key=lambda item: (item.revision, item.path, item.rule))
