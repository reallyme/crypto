#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Install privacy hooks locally without replacing existing hook behavior."""

import os
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()).resolve()
    hooks = root / ".githooks"
    for name in ("pre-commit", "pre-push"):
        path = hooks / name
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            sys.stderr.write("repository hook installation failed: missing executable privacy hook\n")
            return 1
    configured = subprocess.run(["git", "config", "--get", "core.hooksPath"], capture_output=True, text=True)
    if configured.returncode not in (0, 1):
        return 1
    previous = configured.stdout.strip()
    previous_path = Path(previous).expanduser()
    if not previous_path.is_absolute():
        previous_path = root / previous_path
    if previous and previous_path.resolve() != hooks:
        sys.stderr.write("repository hook installation refused: existing hook configuration is preserved\n")
        return 1
    if not previous:
        directory = Path(subprocess.check_output(["git", "rev-parse", "--git-path", "hooks"], text=True).strip())
        for name in ("pre-commit", "pre-push"):
            candidate = directory / name
            if candidate.exists() and os.access(candidate, os.X_OK):
                sys.stderr.write("repository hook installation refused: existing executable hook is preserved\n")
                return 1
    # An absolute local path protects all linked worktrees using this Git
    # directory, including older worktrees that lack the new hook files.
    subprocess.run(["git", "config", "--local", "core.hooksPath", str(hooks)], check=True)
    sys.stdout.write("repository privacy hooks installed locally\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError):
        sys.stderr.write("repository hook installation failed\n")
        sys.exit(1)
