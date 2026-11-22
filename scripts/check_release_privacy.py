#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject excluded names in release archives without extracting their contents."""

import argparse
from enum import Enum
import json
import os
from pathlib import Path
import posixpath
import stat
import sys
import tarfile
import tempfile
import zipfile

from repository_privacy import (
    IgnorePolicy, MAX_PATH_BYTES, RepositoryPrivacyError,
    checked_path, entries, private_path, repository_root,
)


MAX_ENTRIES = 100_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_NESTED_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 4
ARCHIVE_SUFFIXES = (".zip", ".jar", ".aar", ".crate", ".tgz", ".tar", ".tar.gz")


class ReleasePrivacyReason(Enum):
    LOCAL_STATE = "local-state"
    EXCLUDED_PATH = "excluded-path"
    INVALID_SIZE = "invalid-size"
    ARCHIVE_LIMIT = "archive-limit"
    UNSAFE_LINK = "unsafe-link"
    NESTED_LIMIT = "nested-limit"
    TRUNCATED_ARCHIVE = "truncated-archive"
    INCONSISTENT_SIZE = "inconsistent-size"
    DUPLICATE_OR_ENCRYPTED = "duplicate-or-encrypted"
    OVERSIZED_LINK = "oversized-link"
    SPECIAL_MEMBER = "special-member"
    DUPLICATE_MEMBER = "duplicate-member"
    UNREADABLE_NESTED = "unreadable-nested"
    INVALID_PATH_LIST = "invalid-path-list"
    NOT_REGULAR_FILE = "not-regular-file"
    NOT_REGULAR_DIRECTORY = "not-regular-directory"
    STAGING_SYMLINK = "staging-symlink"


class ReleasePrivacyError(Exception):
    def __init__(self, reason, path=None):
        super().__init__(reason.value)
        self.reason = reason
        self.path = path


def archive_path(value):
    encoded = os.fsencode(value)
    while encoded.startswith(b"./"):
        encoded = encoded[2:]
    encoded = encoded.rstrip(b"/")
    return checked_path(encoded)


def public_npm_outputs(snapshot):
    """Allow compiler output without treating private build contents as public.

    npm publishes dist directly. Its JavaScript and declarations must correspond
    to tracked TypeScript sources; the Rust-generated WASM provider has a fixed
    file set. Git's exclusions still apply to every other artifact path.
    """
    source_prefix = b"packages/ts/src/"
    output_prefix = b"packages/ts/dist/"
    result = set()
    for entry in snapshot:
        if entry.mode not in (b"100644", b"100755"):
            continue
        if entry.path.startswith(source_prefix) and entry.path.endswith(b".ts") and not entry.path.endswith(b".d.ts"):
            relative = entry.path[len(source_prefix):-3]
            result.update((output_prefix + relative + b".js", output_prefix + relative + b".d.ts"))
    if output_prefix + b"index.js" in result:
        result.update(output_prefix + b"wasm/" + name for name in (
            b"LICENSE", b"reallyme_crypto_wasm.js", b"reallyme_crypto_wasm.d.ts",
            b"reallyme_crypto_wasm_bg.wasm",
        ))
    return frozenset(result)


class ArchiveAudit:
    def __init__(self, policy, source_root=b"", strip_components=0, npm_outputs=frozenset()):
        self.policy = policy
        self.source_root = source_root
        self.strip_components = strip_components
        self.npm_outputs = npm_outputs
        self.entries = 0
        self.total_bytes = 0

    def check_name(self, name, directory=False, nested=False):
        raw = archive_path(name)
        if private_path(raw):
            raise ReleasePrivacyError(ReleasePrivacyReason.LOCAL_STATE, raw)
        parts = raw.split(b"/")
        if not nested:
            prefix = b"/".join(parts[:self.strip_components])
            if prefix and self.policy.violations([prefix + b"/privacy-directory-probe"], "artifact"):
                # Package wrappers are still published paths. Strip them for
                # source mapping only after checking that they are permitted.
                raise ReleasePrivacyError(ReleasePrivacyReason.EXCLUDED_PATH, raw)
            parts = parts[self.strip_components:]
        if not parts:
            return
        mapped = b"/".join(parts)
        if self.source_root and not nested:
            mapped = self.source_root + b"/" + mapped
        if not nested and self.source_root == b"packages/ts":
            if (not directory and mapped in self.npm_outputs) or (
                directory and any(path.startswith(mapped + b"/") for path in self.npm_outputs)
            ):
                return
        if directory:
            mapped += b"/privacy-directory-probe"
        violations = self.policy.violations([mapped], "artifact")
        if violations:
            raise ReleasePrivacyError(ReleasePrivacyReason.EXCLUDED_PATH, raw)

    def account(self, size):
        self.entries += 1
        if size < 0:
            raise ReleasePrivacyError(ReleasePrivacyReason.INVALID_SIZE)
        self.total_bytes += size
        if self.entries > MAX_ENTRIES or self.total_bytes > MAX_TOTAL_BYTES:
            raise ReleasePrivacyError(ReleasePrivacyReason.ARCHIVE_LIMIT)

    def check_link(self, name, target, nested=False, hardlink=False):
        raw = archive_path(name)
        encoded = os.fsencode(target)
        if not encoded or len(encoded) > MAX_PATH_BYTES or encoded.startswith(b"/") or b"\\" in encoded:
            raise ReleasePrivacyError(ReleasePrivacyReason.UNSAFE_LINK)
        base = b"" if hardlink else posixpath.dirname(raw)
        normalized = posixpath.normpath(posixpath.join(base, encoded))
        self.check_name(os.fsdecode(normalized), nested=nested)

    def nested(self, reader, size, name, depth):
        if size > MAX_NESTED_BYTES or depth >= MAX_DEPTH:
            raise ReleasePrivacyError(ReleasePrivacyReason.NESTED_LIMIT)
        # Spool under a private temporary name. Archive-controlled paths are
        # never passed to an extractor or used as filesystem destinations.
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as temporary:
            remaining = size
            while remaining:
                chunk = reader.read(min(remaining, 64 * 1024))
                if not chunk:
                    raise ReleasePrivacyError(ReleasePrivacyReason.TRUNCATED_ARCHIVE)
                temporary.write(chunk)
                remaining -= len(chunk)
            if reader.read(1):
                raise ReleasePrivacyError(ReleasePrivacyReason.INCONSISTENT_SIZE)
            temporary.seek(0)
            self.scan(temporary, name, depth + 1)

    def scan(self, file, name, depth=0):
        nested = depth != 0
        seen = set()
        if name.lower().endswith((".zip", ".jar", ".aar")):
            with zipfile.ZipFile(file) as archive:
                for member in archive.infolist():
                    if member.filename in (".", "./"):
                        continue
                    normalized = archive_path(member.filename)
                    if normalized in seen or member.flag_bits & 1:
                        raise ReleasePrivacyError(ReleasePrivacyReason.DUPLICATE_OR_ENCRYPTED)
                    seen.add(normalized)
                    self.account(member.file_size)
                    self.check_name(member.filename, member.is_dir(), nested)
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        if member.file_size > MAX_PATH_BYTES:
                            raise ReleasePrivacyError(ReleasePrivacyReason.OVERSIZED_LINK)
                        target = archive.read(member).decode("utf-8", errors="strict")
                        self.check_link(member.filename, target, nested)
                    elif stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise ReleasePrivacyError(ReleasePrivacyReason.SPECIAL_MEMBER)
                    elif not member.is_dir() and member.filename.lower().endswith(ARCHIVE_SUFFIXES):
                        with archive.open(member) as reader:
                            self.nested(reader, member.file_size, member.filename, depth)
        else:
            with tarfile.open(fileobj=file, mode="r:*") as archive:
                for member in archive:
                    if member.name in (".", "./"):
                        continue
                    normalized = archive_path(member.name)
                    if normalized in seen:
                        raise ReleasePrivacyError(ReleasePrivacyReason.DUPLICATE_MEMBER)
                    seen.add(normalized)
                    self.account(member.size)
                    self.check_name(member.name, member.isdir(), nested)
                    if member.issym() or member.islnk():
                        self.check_link(member.name, member.linkname, nested, member.islnk())
                    elif not member.isfile() and not member.isdir():
                        raise ReleasePrivacyError(ReleasePrivacyReason.SPECIAL_MEMBER)
                    elif member.isfile() and member.name.lower().endswith(ARCHIVE_SUFFIXES):
                        reader = archive.extractfile(member)
                        if reader is None:
                            raise ReleasePrivacyError(ReleasePrivacyReason.UNREADABLE_NESTED)
                        with reader:
                            self.nested(reader, member.size, member.name, depth)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--archive", type=Path)
    selection.add_argument("--directory", type=Path)
    selection.add_argument("--paths-stdin", action="store_true")
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--strip-components", type=int, default=0)
    arguments = parser.parse_args()
    if arguments.strip_components < 0 or arguments.strip_components > 8:
        parser.error("invalid prefix component count")
    source_root = b"" if arguments.source_root == "." else archive_path(arguments.source_root)
    repository = repository_root()
    snapshot = entries(repository)
    with IgnorePolicy(repository, snapshot) as policy:
        audit = ArchiveAudit(policy, source_root, arguments.strip_components, public_npm_outputs(snapshot))
        if arguments.paths_stdin:
            data = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
            if len(data) > 16 * 1024 * 1024 or (data and not data.endswith(b"\0")):
                raise ReleasePrivacyError(ReleasePrivacyReason.INVALID_PATH_LIST)
            for path in data.split(b"\0"):
                if path:
                    audit.account(0)
                    audit.check_name(os.fsdecode(path), path.endswith(b"/"))
        elif arguments.archive:
            if arguments.archive.is_symlink() or not arguments.archive.is_file():
                raise ReleasePrivacyError(ReleasePrivacyReason.NOT_REGULAR_FILE)
            with arguments.archive.open("rb") as file:
                audit.scan(file, arguments.archive.name)
        else:
            if arguments.directory.is_symlink() or not arguments.directory.is_dir():
                raise ReleasePrivacyError(ReleasePrivacyReason.NOT_REGULAR_DIRECTORY)
            for directory, subdirectories, files in os.walk(arguments.directory, followlinks=False):
                subdirectories.sort()
                files.sort()
                for name in subdirectories + files:
                    path = Path(directory) / name
                    if path.is_symlink():
                        raise ReleasePrivacyError(ReleasePrivacyReason.STAGING_SYMLINK)
                    relative = path.relative_to(arguments.directory).as_posix()
                    audit.account(path.stat().st_size if path.is_file() else 0)
                    audit.check_name(relative, path.is_dir())
                    if path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES):
                        with path.open("rb") as file:
                            audit.scan(file, path.name)
    sys.stdout.write("release artifact privacy check passed\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RepositoryPrivacyError as error:
        sys.stderr.write(f"release artifact privacy check failed [{error.reason.value}]\n")
        sys.exit(2)
    except ReleasePrivacyError as error:
        detail = "" if error.path is None else ": " + json.dumps(os.fsdecode(error.path))
        sys.stderr.write("release artifact privacy check failed [" + error.reason.value + "]" + detail + "\n")
        sys.exit(1)
    except (OSError, ValueError, UnicodeError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        sys.stderr.write("release artifact privacy check failed [unreadable-artifact]\n")
        sys.exit(2)
