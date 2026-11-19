#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reject tracked or outbound files excluded by repository privacy policy."""

import argparse
import json
import os
import sys

from repository_privacy import (
    MAX_PATHS, OBJECT_ID, PrivacyReason, RepositoryPrivacyError, Violation,
    check_history, check_snapshot, checked_path, git, repository_root, resolve_commit,
)


def working_index_violations(repository):
    # Staged/base policy prevents removals from hiding files. This additional
    # check also honors new local exclusions before their rules are staged,
    # including Git's local exclude file and developer-wide exclusions.
    output = git(repository, ["ls-files", "--cached", "--ignored", "--exclude-standard", "-z"])
    paths = [path for path in output.split(b"\0") if path]
    if len(paths) > MAX_PATHS:
        raise RepositoryPrivacyError(PrivacyReason.LIMIT_EXCEEDED)
    return [Violation(checked_path(path), b"working-tree ignore exclusion") for path in paths]


def pushed_commits(repository, stream):
    updates = []
    for line in stream:
        fields = line.split()
        if len(fields) != 4:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_PUSH)
        _, local_object, _, remote_object = fields
        if OBJECT_ID.fullmatch(local_object) is None or OBJECT_ID.fullmatch(remote_object) is None:
            raise RepositoryPrivacyError(PrivacyReason.INVALID_PUSH)
        if set(local_object) == {ord("0")}:
            continue
        base = None
        if set(remote_object) != {ord("0")}:
            # A remote base not present locally must not become a blind spot.
            # Scan the complete outbound ancestry if it cannot be resolved.
            try:
                base = resolve_commit(repository, remote_object.decode("ascii"))
            except RepositoryPrivacyError:
                pass
        updates.append((local_object.decode("ascii"), base))
    return updates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--index", action="store_true")
    mode.add_argument("--commit")
    mode.add_argument("--pre-push", action="store_true")
    mode.add_argument("--all-history", action="store_true")
    parser.add_argument("--base")
    parser.add_argument("--all-ancestors", action="store_true")
    arguments = parser.parse_args()
    repository = repository_root()
    if arguments.base and not arguments.commit:
        parser.error("--base requires --commit")
    if arguments.all_ancestors and not arguments.commit:
        parser.error("--all-ancestors requires --commit")
    if arguments.index:
        head = git(repository, ["rev-parse", "--verify", "HEAD"], accepted=(0, 128)).strip()
        violations = check_snapshot(repository, trusted_revision=head.decode() if head else None)
        violations.extend(working_index_violations(repository))
    elif arguments.commit:
        commit = resolve_commit(repository, arguments.commit)
        violations = check_snapshot(repository, commit, arguments.base)
        if arguments.base:
            violations.extend(check_history(repository, [commit], [arguments.base], arguments.base))
        elif arguments.all_ancestors:
            violations.extend(check_history(repository, [commit], trusted_revision=commit))
    elif arguments.pre_push:
        updates = pushed_commits(repository, sys.stdin.buffer)
        violations = check_snapshot(repository, trusted_revision="HEAD")
        violations.extend(working_index_violations(repository))
        # Bases are per update: a second pushed ref must not hide a private
        # commit in another ref by contributing it to a shared exclusion set.
        for tip, base in updates:
            violations.extend(check_history(repository, [tip], [base] if base else []))
    else:
        refs = git(repository, ["for-each-ref", "--format=%(objectname)"]).splitlines()
        tips = [row.decode("ascii") for row in refs]
        violations = check_history(repository, tips) if tips else []
    violations = sorted(set(violations), key=lambda item: (item.revision, item.path, item.rule))
    if violations:
        for item in violations[:100]:
            record = {
                "path": os.fsdecode(item.path),
                "rule": os.fsdecode(item.rule),
                "revision": item.revision,
            }
            sys.stderr.write("repository privacy violation: " + json.dumps(record, ensure_ascii=True) + "\n")
        sys.stderr.write(f"repository privacy check rejected {len(violations)} excluded file records\n")
        return 1
    sys.stdout.write("repository privacy check passed\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RepositoryPrivacyError as error:
        sys.stderr.write(f"repository privacy check failed [{error.reason.value}]\n")
        sys.exit(2)
    except (OSError, ValueError, UnicodeError):
        sys.stderr.write("repository privacy check failed [invalid-repository-input]\n")
        sys.exit(2)
