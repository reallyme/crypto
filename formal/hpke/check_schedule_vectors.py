# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check intermediate outputs of the locked HPKE backend against CFRG vectors."""

import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from verify import (
    ROOT,
    VerificationError,
    exactly_one,
    locked_backend,
    prepare_backend_package,
    resolve_backend_package,
)

HERE = Path(__file__).resolve().parent
CORPUS_PATH = "hpke/rfc9180_test_vectors.json"
FEATURES = ("--no-default-features", "--features", "aes,alloc,chacha,nistp,x25519")
SUITES = (
    (0x0010, 0x0001, 0x0001), (0x0010, 0x0001, 0x0002), (0x0012, 0x0003, 0x0002),
    (0x0020, 0x0001, 0x0001), (0x0020, 0x0001, 0x0003), (0x0020, 0x0001, 0xFFFF),
)
SCHEDULE_FIELDS = {
    "shared_secret": "shared_secret", "context": "key_schedule_context", "secret": "secret",
    "key": "key", "base_nonce": "base_nonce", "exporter_secret": "exporter_secret",
}
OBSERVATION = """
    crate::schedule_observer::observe(crate::schedule_observer::Schedule {
        shared_secret: shared_secret.0.as_slice(),
        context: sched_context,
        secret: observed_secret.as_slice(),
        key: key.0.as_slice(),
        base_nonce: Some(base_nonce.0.as_slice()),
        exporter_secret: exporter_secret.0.as_slice(),
    });

"""


def load_corpus():
    directory = ROOT / "vectors" / "external"
    provenance = json.loads((directory / "provenance.json").read_bytes())
    record = exactly_one(
        [entry for entry in provenance["files"] if entry["local_path"] == CORPUS_PATH],
        "RFC 9180 vector checksum",
    )
    corpus = (directory / CORPUS_PATH).read_bytes()
    if hashlib.sha256(corpus).hexdigest() != record["sha256"]:
        raise VerificationError("RFC 9180 corpus differs from its pinned checksum")
    return json.loads(corpus)


def rust_bytes(data):
    return "&[" + ",".join(str(byte) for byte in data) + "]"


def write_vectors(corpus, destination):
    # Decode all injected literals as hex first. The generated source contains
    # only reviewed templates, numeric IDs and byte arrays from public vectors.
    rows = ["&["]
    for kem, kdf, aead in SUITES:
        for mode in (0, 1):
            vector = exactly_one(
                [v for v in corpus if (v["mode"], v["kem_id"], v["kdf_id"], v["aead_id"])
                 == (mode, kem, kdf, aead)],
                "RFC 9180 row per selected suite and mode",
            )
            rows.append(f"Vector {{ suite: ({kem}, {kdf}, {aead}),")
            for field, source in (("recipient_key", "skRm"), ("enc", "enc"), ("info", "info")):
                rows.append(f"{field}: {rust_bytes(bytes.fromhex(vector[source]))},")
            psk = "None"
            if mode == 1:
                key = rust_bytes(bytes.fromhex(vector["psk"]))
                identity = rust_bytes(bytes.fromhex(vector["psk_id"]))
                psk = f"Some(({key}, {identity}))"
            rows.extend([f"psk: {psk},", "schedule: Schedule {"])
            for field, source in SCHEDULE_FIELDS.items():
                data = bytes.fromhex(vector[source])
                literal = rust_bytes(data)
                if field == "base_nonce":
                    # Export-only publishes no record nonce. The backend may
                    # hold an internal placeholder that can never encrypt.
                    if (aead == 0xFFFF) != (not data):
                        raise VerificationError("unexpected RFC 9180 base_nonce presence")
                    literal = f"Some({literal})" if data else "None"
                rows.append(f"{field}: {literal},")
            rows.append("}, exports: &[")
            for export in vector["exports"]:
                expected = bytes.fromhex(export["exported_value"])
                if type(export["L"]) is not int or not expected or len(expected) != export["L"]:
                    raise VerificationError("invalid output length in the RFC 9180 corpus")
                context = rust_bytes(bytes.fromhex(export["exporter_context"]))
                rows.append(f"ExportVector {{ context: {context}, expected: {rust_bytes(expected)} }},")
            rows.append("] },")
    rows.append("]\n")
    destination.write_text("\n".join(rows), encoding="utf-8")


def instrument_schedule(package):
    src = package / "src"
    (src / "schedule_observer.rs").write_bytes((HERE / "schedule_observer_tests.rs").read_bytes())
    with (src / "lib.rs").open("a", encoding="utf-8") as library:
        library.write("\nextern crate std;\n#[doc(hidden)]\npub mod schedule_observer;\n")

    schedule = src / "kdf" / "two_stage_kdf.rs"
    source = schedule.read_text(encoding="utf-8")
    extract = "    let (_, secret_ctx) =\n        labeled_extract::<H>(&shared_secret.0, &suite_id, b\"secret\", mode.get_psk_bytes());"
    finish = "    AeadCtx::new(&key, base_nonce, exporter_secret)"
    if source.count(extract) != 1 or source.count(finish) != 1:
        raise VerificationError("HPKE schedule layout changed, review the observation points")
    source = source.replace(extract, extract.replace("(_,", "(observed_secret,"))
    source = source.replace(
        finish,
        "    let observed_secret = zeroize::Zeroizing::new(observed_secret);\n"
        + OBSERVATION + finish,
    )
    schedule.write_text(source, encoding="utf-8")


def main():
    corpus = load_corpus()
    lock_text, packages, backend = locked_backend()
    with tempfile.TemporaryDirectory(prefix="hpke-vector-audit-") as directory:
        manifest = prepare_backend_package(Path(directory), lock_text, backend)
        package = manifest.parent
        instrument_schedule(package)
        tests = package / "tests"
        tests.mkdir(exist_ok=True)
        test = HERE / "rfc9180_schedule_tests.rs"
        (tests / test.name).write_bytes(test.read_bytes())
        # Published crate manifests disable automatic test discovery.
        with manifest.open("a", encoding="utf-8") as cargo_manifest:
            cargo_manifest.write(f'\n[[test]]\nname = "{test.stem}"\npath = "tests/{test.name}"\n')
        write_vectors(corpus, tests / "rfc9180_schedule_vectors.inc")
        resolve_backend_package(manifest, FEATURES, packages, backend)
        subprocess.run(
            ["cargo", "test", "--locked", "--offline", "--manifest-path", manifest,
             *FEATURES, "--test", test.stem],
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            subprocess.CalledProcessError, VerificationError) as error:
        sys.exit(f"HPKE schedule audit failed: {error}")
