# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Reproduce the PSK corpus with the pinned IETF reference implementation."""

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from check_schedule_vectors import PQ_CORPUS, PQ_PSK_CORPUS, read_corpus
from verify import VerificationError, prepare_archive

REFERENCE_COMMIT = "6433c8fce0b8b749dfc86c1095081a88698ccfab"
REFERENCE_ARCHIVE_SHA256 = "e085859f84865310206fb52bb547eb7c8993a6134bbd2a4cd8f6fda6ee9ef29d"
GENERATOR = Path(__file__).with_name("generate_psk_vectors_tests.rs")


def generate(archive, offline):
    # The Base corpus provides the recipient and record inputs for each pair.
    base_corpus = read_corpus(PQ_CORPUS)
    with tempfile.TemporaryDirectory(prefix="hpke-psk-vector-reference-") as directory:
        scratch = Path(directory)
        package_dir = f"hpke-pq-{REFERENCE_COMMIT}"
        prepare_archive(archive, REFERENCE_ARCHIVE_SHA256, scratch, package_dir)
        reference = scratch / package_dir / "reference-implementation"
        (reference / "tests" / GENERATOR.name).write_bytes(GENERATOR.read_bytes())

        base = scratch / "base-vectors.json"
        base.write_bytes(base_corpus)
        output = scratch / "psk-vectors.json"
        env = dict(
            os.environ,
            HPKE_PSK_VECTOR_INPUT=str(base),
            HPKE_PSK_VECTOR_OUTPUT=str(output),
        )
        command = ["cargo", "test", "--locked", "--test", GENERATOR.stem]
        if offline:
            command.append("--offline")
        subprocess.run(command, cwd=reference, env=env, stdout=sys.stderr, check=True)
        return output.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="source archive for the pinned draft-05 commit")
    parser.add_argument("--offline", action="store_true", help="use cached reference dependencies")
    parser.add_argument("--check", action="store_true", help="compare against the recorded corpus")
    args = parser.parse_args()
    reproduced = generate(args.archive, args.offline)
    if args.check:
        if reproduced != read_corpus(PQ_PSK_CORPUS):
            raise VerificationError("reference output differs from the recorded PSK corpus")
        print("verified the independently generated PSK corpus")
    else:
        sys.stdout.buffer.write(reproduced)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError,
            subprocess.CalledProcessError, VerificationError) as error:
        sys.exit(f"HPKE PSK vector generation failed: {error}")
