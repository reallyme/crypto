# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check HPKE schedules and record sequences against independent vectors."""

import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from rejection_vectors import ACVP_CORPUS, cases_for_row, check_acvp
from verify import (
    ROOT,
    VerificationError,
    exactly_one,
    locked_backend,
    prepare_backend_package,
    resolve_backend_package,
)

HERE = Path(__file__).resolve().parent
CLASSICAL_CORPUS = "hpke/rfc9180_test_vectors.json"
PQ_CORPUS = "hpke/hpke_pq_draft05_test_vectors.json"
PQ_PSK_CORPUS = "hpke/hpke_pq_draft05_psk_test_vectors.json"
FEATURES = ("--no-default-features", "--features", "aes,alloc,chacha,mlkem,nistp,x25519")
CLASSICAL_SUITES = (
    (0x0010, 0x0001, 0x0001), (0x0010, 0x0001, 0x0002), (0x0012, 0x0003, 0x0002),
    (0x0020, 0x0001, 0x0001), (0x0020, 0x0001, 0x0003), (0x0020, 0x0001, 0xFFFF),
)
PQ_SUITES = (
    (0x0040, 0x0001, 0x0001), (0x0041, 0x0001, 0x0001), (0x0042, 0x0002, 0x0002),
    (0x647A, 0x0001, 0x0003), (0x647A, 0x0011, 0x0003),
)
EXPORT_ONLY_AEAD = 0xFFFF
CLASSICAL_RECORD_COUNT = 257
PQ_RECORD_COUNT = 10
RECORD_NONCE_LEN = 12
RECORD_TAG_LEN = 16
SCHEDULE_FIELDS = {
    "shared_secret": "shared_secret", "context": "key_schedule_context", "secret": "secret",
    "key": "key", "base_nonce": "base_nonce", "exporter_secret": "exporter_secret",
}
OBSERVATION = """
    crate::schedule_observer::observe(crate::schedule_observer::Schedule {
        shared_secret: shared_secret.0.as_slice(),
        context: Some(sched_context),
        secret: Some(observed_secret.as_slice()),
        key: key.0.as_slice(),
        base_nonce: Some(base_nonce.0.as_slice()),
        exporter_secret: exporter_secret.0.as_slice(),
    });

"""


def read_corpus(relative_path):
    directory = ROOT / "vectors" / "external"
    provenance = json.loads((directory / "provenance.json").read_bytes())
    record = exactly_one(
        [entry for entry in provenance["files"] + provenance.get("derived_files", [])
         if entry["local_path"] == relative_path],
        "HPKE vector checksum",
    )
    corpus = (directory / relative_path).read_bytes()
    if hashlib.sha256(corpus).hexdigest() != record["sha256"]:
        raise VerificationError("HPKE corpus differs from its pinned checksum")
    return corpus


def rust_bytes(data):
    return "&[" + ",".join(str(byte) for byte in data) + "]"


def select_vectors(corpus, suites, modes, rows_per_mode):
    for kem, kdf, aead in suites:
        for mode in modes:
            rows = [v for v in corpus if (v["mode"], v["kem_id"], v["kdf_id"], v["aead_id"])
                    == (mode, kem, kdf, aead)]
            if len(rows) != rows_per_mode:
                raise VerificationError("unexpected HPKE row count for selected suite and mode")
            yield from rows


def schedule_literal(vector, field, source, classical):
    if field in ("context", "secret") and not classical:
        # The PQ draft publishes the derived outputs, without RFC 9180's
        # extraction secret or schedule-context bytes.
        return "None"
    data = bytes.fromhex(vector[source])
    if field == "base_nonce":
        if (vector["aead_id"] == EXPORT_ONLY_AEAD) != (not data):
            raise VerificationError("unexpected base_nonce presence in HPKE corpus")
        return f"Some({rust_bytes(data)})" if data else "None"
    if field in ("context", "secret"):
        if not data:
            raise VerificationError("missing RFC 9180 schedule intermediate")
        return f"Some({rust_bytes(data)})"
    return rust_bytes(data)


def write_records(rows, vector, classical):
    records = vector["encryptions"]
    if vector["aead_id"] == EXPORT_ONLY_AEAD:
        expected_count = 0
    else:
        expected_count = CLASSICAL_RECORD_COUNT if classical else PQ_RECORD_COUNT
    if len(records) != expected_count:
        raise VerificationError("unexpected record count in HPKE corpus")

    rows.append("], records: &[")
    for record in records:
        nonce, aad, pt, ct = (
            bytes.fromhex(record[field]) for field in ("nonce", "aad", "pt", "ct")
        )
        if len(nonce) != RECORD_NONCE_LEN or len(ct) != len(pt) + RECORD_TAG_LEN:
            raise VerificationError("unexpected nonce or ciphertext length in HPKE record")
        rows.append(f"RecordVector {{ nonce: {rust_bytes(nonce)}, aad: {rust_bytes(aad)},")
        rows.append(f"plaintext: {rust_bytes(pt)}, ciphertext: {rust_bytes(ct)} }},")


def write_vectors(destination):
    # Only hex-decoded bytes and reviewed numeric IDs enter the Rust template.
    rows = ["&["]
    for path, suites, modes, rows_per_mode in (
        (CLASSICAL_CORPUS, CLASSICAL_SUITES, (0, 1), 1),
        (PQ_CORPUS, PQ_SUITES, (0,), 1),
        (PQ_PSK_CORPUS, PQ_SUITES, (1,), 2),
    ):
        classical = path == CLASSICAL_CORPUS
        for vector in select_vectors(json.loads(read_corpus(path)), suites, modes, rows_per_mode):
            suite = (vector["kem_id"], vector["kdf_id"], vector["aead_id"])
            count = 3 if classical else 5
            rows.append(f"Vector {{ suite: {suite}, export_count: {count},")
            for field, source in (
                ("recipient_key", "skRm"), ("recipient_public_key", "pkRm"),
                ("encapsulation_randomness", "ikmE"), ("enc", "enc"), ("info", "info"),
            ):
                rows.append(f"{field}: {rust_bytes(bytes.fromhex(vector[source]))},")
            psk = "None"
            if vector["mode"] == 1:
                key = rust_bytes(bytes.fromhex(vector["psk"]))
                identity = rust_bytes(bytes.fromhex(vector["psk_id"]))
                psk = f"Some(({key}, {identity}))"
            rows.extend([f"psk: {psk},", "schedule: Schedule {"])
            for field, source in SCHEDULE_FIELDS.items():
                rows.append(f"{field}: {schedule_literal(vector, field, source, classical)},")
            rows.append("}, exports: &[")
            for export in vector["exports"]:
                expected = bytes.fromhex(export["exported_value"])
                if type(export["L"]) is not int or not expected or len(expected) != export["L"]:
                    raise VerificationError("invalid output length in HPKE corpus")
                context = rust_bytes(bytes.fromhex(export["exporter_context"]))
                rows.append(f"ExportVector {{ context: {context}, expected: {rust_bytes(expected)} }},")
            write_records(rows, vector, classical)
            rows.append("] },")
    rows.append("]\n")
    destination.write_text("\n".join(rows), encoding="utf-8")


def write_rejection_vectors(destination):
    rows = ["&["]
    for vector in select_vectors(json.loads(read_corpus(PQ_CORPUS)), PQ_SUITES, (0,), 1):
        for kem, private, enc, original, modified, expected in cases_for_row(vector, destination.parent):
            rows.append(f"RejectionVector {{ kem: {kem}, private: {rust_bytes(private)},")
            rows.append(f"enc: {rust_bytes(enc)}, original: {rust_bytes(original)},")
            rows.append(f"modified: {rust_bytes(modified)}, expected: {rust_bytes(expected)} }},")
    rows.append("]\n")
    destination.write_text("\n".join(rows), encoding="utf-8")


def write_acvp_vectors(destination):
    rows = ["&["]
    for kem, private, encapsulated, expected in check_acvp(read_corpus(ACVP_CORPUS)):
        rows.append(f"AcvpDecapsulation {{ kem: {kem}, private: {rust_bytes(private)},")
        rows.append(f"enc: {rust_bytes(encapsulated)}, expected: {rust_bytes(expected)} }},")
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

    # The one-stage KDF exposes its derived outputs at the same construction
    # point. There is no two-stage extraction secret to capture here.
    schedule = src / "kdf" / "one_stage_kdf.rs"
    source = schedule.read_text(encoding="utf-8")
    if source.count(finish) != 1:
        raise VerificationError("one-stage HPKE schedule layout changed")
    observation = OBSERVATION.replace("Some(sched_context)", "None").replace(
        "Some(observed_secret.as_slice())", "None"
    )
    schedule.write_text(source.replace(finish, observation + finish), encoding="utf-8")


def instrument_record_nonce(package):
    aead = package / "src" / "aead.rs"
    source = aead.read_text(encoding="utf-8")
    nonce = "            let nonce = mix_nonce::<A>(&self.0.base_nonce, &self.0.seq);\n"
    observe = "            crate::schedule_observer::observe_nonce(nonce.0.as_slice());\n"
    # Seal and open each calculate exactly one nonce before calling the AEAD.
    if source.count(nonce) != 2:
        raise VerificationError("HPKE record layout changed, review the nonce observation points")
    aead.write_text(source.replace(nonce, nonce + observe), encoding="utf-8")


def main():
    lock_text, packages, backend = locked_backend()
    with tempfile.TemporaryDirectory(prefix="hpke-vector-audit-") as directory:
        manifest = prepare_backend_package(Path(directory), lock_text, backend)
        package = manifest.parent
        instrument_schedule(package)
        instrument_record_nonce(package)
        tests = package / "tests"
        tests.mkdir(exist_ok=True)
        test = HERE / "rfc9180_schedule_tests.rs"
        (tests / test.name).write_bytes(test.read_bytes())
        # Published crate manifests disable automatic test discovery.
        with manifest.open("a", encoding="utf-8") as cargo_manifest:
            cargo_manifest.write(f'\n[[test]]\nname = "{test.stem}"\npath = "tests/{test.name}"\n')
        # ML-KEM-512 is owned by the workspace, so exercise its exact KEM
        # adapter source with the same locked backend and published vectors.
        mlkem512 = ROOT / "crates" / "hpke" / "src" / "mlkem512.rs"
        (tests / "mlkem512.rs").write_bytes(mlkem512.read_bytes())
        randomness = ROOT / "crates" / "hpke" / "src" / "random.rs"
        (tests / "random.rs").write_bytes(randomness.read_bytes())
        write_vectors(tests / "hpke_schedule_vectors.inc")
        write_rejection_vectors(package / "hpke_rejection_vectors.inc")
        write_acvp_vectors(package / "ml_kem_acvp_decapsulation.inc")
        resolve_backend_package(manifest, FEATURES, packages, backend)
        subprocess.run(
            ["cargo", "test", "--locked", "--offline", "--manifest-path", manifest,
             "--target-dir", package / "target", *FEATURES, "--test", test.stem],
            cwd=ROOT,
            check=True,
        )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            subprocess.CalledProcessError, VerificationError) as error:
        sys.exit(f"HPKE schedule audit failed: {error}")
