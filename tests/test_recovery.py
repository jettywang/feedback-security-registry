#    This file is part of python-registry.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Tests for Registry.RegistryRecovery: forensic hive recovery from
transaction logs. Small samples are built in memory; original evidence
buffers are hashed before and after to prove they stay untouched.
"""
import hashlib
import io
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Registry import Registry, RegistryParse, RegistryRecovery

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "testing", "reg_samples")

REGF_HEADER_SIZE = 0x1000
LOG_HEADER_SIZE = 0x200


def build_regf(seq1, seq2, hbins_size, file_type=0, corrupt_checksum=False):
    """A minimal but valid REGF header block (0x1000 bytes)."""
    buf = bytearray(REGF_HEADER_SIZE)
    struct.pack_into("<I", buf, 0x0, 0x66676572)  # "regf"
    struct.pack_into("<I", buf, 0x4, seq1 & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x8, seq2 & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x14, 1)   # major version
    struct.pack_into("<I", buf, 0x18, 5)   # minor version
    struct.pack_into("<I", buf, 0x1C, file_type)
    struct.pack_into("<I", buf, 0x20, 1)   # file format
    struct.pack_into("<I", buf, 0x28, hbins_size)
    struct.pack_into("<I", buf, 0x2C, 1)   # clustering factor
    regf = RegistryParse.REGFBlock(bytes(buf), 0, False)
    struct.pack_into("<I", buf, 0x1FC, regf.calculate_checksum())
    if corrupt_checksum:
        buf[0x30] ^= 0xFF  # damage the header without touching the checksum field
    return bytes(buf)


def build_primary(seq1, seq2, hbins_size=0x1000, fill=b"\xAB",
                  corrupt_checksum=False):
    """A primary hive: REGF header plus a patterned hbin area."""
    return build_regf(seq1, seq2, hbins_size,
                      corrupt_checksum=corrupt_checksum) + fill * hbins_size


def build_log_entry(sequence, pages, hbins_size=0x1000, hive_flags=0,
                    corrupt_hash=False):
    """
    One HvLE log entry. `pages` is a list of (offset, data) tuples where
    offset is relative to the first hbin of the primary file.
    """
    refs = b"".join(struct.pack("<II", offset, len(data)) for offset, data in pages)
    body = refs + b"".join(data for _offset, data in pages)
    size = 0x28 + len(body)  # 0x28 = HvLE fixed header (40 bytes)
    size = (size + 0x1FF) & ~0x1FF
    buf = bytearray(size)
    struct.pack_into("<I", buf, 0x0, 0x454C7648)  # "HvLE"
    struct.pack_into("<I", buf, 0x4, size)
    struct.pack_into("<I", buf, 0x8, hive_flags)
    struct.pack_into("<I", buf, 0xC, sequence & 0xFFFFFFFF)
    struct.pack_into("<I", buf, 0x10, hbins_size)
    struct.pack_into("<I", buf, 0x14, len(pages))
    buf[0x28:0x28 + len(body)] = body
    # Hash-2 covers the first 32 bytes, including Hash-1: patch in order.
    struct.pack_into("<Q", buf, 0x18,
                     RegistryParse.HvLEBlock(bytes(buf), 0, None).calculate_hash_1())
    struct.pack_into("<Q", buf, 0x20,
                     RegistryParse.HvLEBlock(bytes(buf), 0, None).calculate_hash_2())
    if corrupt_hash:
        buf[0x18] ^= 0xFF
    return bytes(buf)


def build_log(entries, first_sequence):
    """A new-format transaction log file holding the given entries."""
    header = bytearray(build_regf(first_sequence, first_sequence, 0x1000,
                                  file_type=6))
    return bytes(header[:LOG_HEADER_SIZE]) + b"".join(entries)


def page(offset, byte, size=0x200):
    return (offset, bytes([byte]) * size)


def sha256(data):
    return hashlib.sha256(bytes(data)).hexdigest()


# --- synthetic in-memory samples -----------------------------------------

def test_log_order_swap_does_not_change_recovery():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x2000)
    log_a = build_log([build_log_entry(9, [page(0x0, 0x11)], hbins_size=0x2000),
                       build_log_entry(10, [page(0x200, 0x22)], hbins_size=0x2000)], 9)
    log_b = build_log([build_log_entry(11, [page(0x400, 0x33)], hbins_size=0x2000),
                       build_log_entry(12, [page(0x600, 0x44)], hbins_size=0x2000)], 11)

    forward = RegistryRecovery.recover_hive(
        primary, [("LOG1", log_a), ("LOG2", log_b)])
    swapped = RegistryRecovery.recover_hive(
        primary, [("LOG2", log_b), ("LOG1", log_a)])

    assert forward.status == RegistryRecovery.STATUS_COMPLETE
    assert swapped.status == RegistryRecovery.STATUS_COMPLETE
    assert forward.derived_data == swapped.derived_data
    assert forward.final_sequence == 12
    # The applied page data really landed in the copy.
    assert forward.derived_data[0x1000:0x1200] == bytes([0x11]) * 0x200
    assert forward.derived_data[0x1600:0x1800] == bytes([0x44]) * 0x200


def test_out_of_bounds_page_is_not_written():
    hbins_size = 0x1000
    primary = build_primary(seq1=2, seq2=1, hbins_size=hbins_size)
    evil = build_log_entry(1, [page(0x0, 0x55),
                               page(0x100000, 0xEE)],  # far past the hbin area
                           hbins_size=hbins_size)
    log = build_log([evil], 1)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log)])

    assert result.status == RegistryRecovery.STATUS_PARTIAL
    assert result.diagnostic_only
    # The valid page was applied, the out-of-bounds page was skipped.
    statuses = {p.page_index: p.status for p in result.provenance}
    assert statuses[0] == RegistryRecovery.PAGE_APPLIED
    assert statuses[1] == RegistryRecovery.PAGE_SKIPPED_OUT_OF_BOUNDS
    # Nothing was written outside the hbin area of the copy.
    assert len(result.derived_data) == 0x1000 + hbins_size
    assert result.derived_data[0x1000:0x1200] == bytes([0x55]) * 0x200
    assert result.derived_data[0x1200:] == primary[0x1200:]
    assert bytes([0xEE]) * 0x200 not in result.derived_data


def test_original_evidence_is_never_modified():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x2000)
    log_a = build_log([build_log_entry(9, [page(0x0, 0x11)], hbins_size=0x2000)], 9)
    log_b = build_log([build_log_entry(10, [page(0x200, 0x22)], hbins_size=0x2000)], 10)
    before = {sha256(primary), sha256(log_a), sha256(log_b)}

    result = RegistryRecovery.recover_hive(
        primary, [("LOG1", log_a), ("LOG2", log_b)])

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    assert {sha256(primary), sha256(log_a), sha256(log_b)} == before


def test_every_modified_range_is_traceable():
    primary = build_primary(seq1=11, seq2=10, hbins_size=0x2000)
    log = build_log([build_log_entry(10, [page(0x0, 0x11), page(0x800, 0x22)],
                                     hbins_size=0x2000),
                     build_log_entry(11, [page(0x400, 0x33)], hbins_size=0x2000)], 10)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log)])
    assert result.status == RegistryRecovery.STATUS_COMPLETE

    # Every applied page cites its log and entry sequence number.
    assert [(p.log_name, p.entry_sequence, p.page_index) for p in result.provenance] == \
        [("LOG1", 10, 0), ("LOG1", 10, 1), ("LOG1", 11, 0)]

    # Every modified hbin-area byte falls inside a provenanced page range.
    regf_fields = [(0x4, 0xC), (0x28, 0x2C), (0x90, 0x94), (0x1FC, 0x200)]
    page_ranges = [(p.target_offset, p.target_offset + p.size)
                   for p in result.provenance
                   if p.status == RegistryRecovery.PAGE_APPLIED]
    derived = result.derived_data
    for i in range(len(derived)):
        if derived[i] != primary[i]:
            in_regf = any(start <= i < end for start, end in regf_fields)
            in_page = any(start <= i < end for start, end in page_ranges)
            assert in_regf or in_page, "untraceable modification at 0x%x" % i


def test_sequence_gap_marks_result_partial():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x1000)
    log_a = build_log([build_log_entry(9, [page(0x0, 0x11)])], 9)
    log_b = build_log([build_log_entry(11, [page(0x200, 0x22)])], 11)  # gap at 10

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log_a), ("LOG2", log_b)])

    assert result.status == RegistryRecovery.STATUS_PARTIAL
    assert result.diagnostic_only
    assert result.plan.gaps == [10]
    assert result.final_sequence == 9
    # The copy is consistent at sequence 9; the entry past the gap was not applied.
    assert result.derived_data[0x1000:0x1200] == bytes([0x11]) * 0x200
    assert result.derived_data[0x1200:0x1400] == primary[0x1200:0x1400]


def test_sequence_wraparound():
    primary = build_primary(seq1=0, seq2=0xFFFFFFFE, hbins_size=0x1000)
    log_a = build_log([build_log_entry(0xFFFFFFFE, [page(0x0, 0x11)]),
                       build_log_entry(0xFFFFFFFF, [page(0x200, 0x22)])], 0xFFFFFFFE)
    log_b = build_log([build_log_entry(0, [page(0x400, 0x33)]),
                       build_log_entry(1, [page(0x600, 0x44)])], 0)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log_a), ("LOG2", log_b)])

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    assert result.final_sequence == 1
    assert [s for s, _log, _e in result.plan.chain] == \
        [0xFFFFFFFE, 0xFFFFFFFF, 0, 1]


def test_overlapping_logs_are_deduplicated():
    primary = build_primary(seq1=11, seq2=10, hbins_size=0x1000)
    log_a = build_log([build_log_entry(10, [page(0x0, 0x11)]),
                       build_log_entry(11, [page(0x200, 0x22)])], 10)
    log_b = build_log([build_log_entry(11, [page(0x200, 0x22)]),
                       build_log_entry(12, [page(0x400, 0x33)])], 11)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log_a), ("LOG2", log_b)])

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    assert [s for s, _log, _e in result.plan.chain] == [10, 11, 12]
    seqs = [p.entry_sequence for p in result.provenance]
    assert seqs.count(11) == 1  # overlapping entry applied exactly once


def test_corrupt_log_entry_stops_chain_and_marks_partial():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x1000)
    log = build_log([build_log_entry(9, [page(0x0, 0x11)]),
                     build_log_entry(10, [page(0x200, 0x22)], corrupt_hash=True),
                     build_log_entry(11, [page(0x400, 0x33)])], 9)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log)])

    assert result.status == RegistryRecovery.STATUS_PARTIAL
    assert result.diagnostic_only
    assert result.final_sequence == 9
    assert result.derived_data[0x1200:0x1400] == primary[0x1200:0x1400]


def test_header_restored_from_log_when_checksum_bad():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x1000,
                            corrupt_checksum=True)
    log = build_log([build_log_entry(9, [page(0x0, 0x11)]),
                     build_log_entry(10, [page(0x200, 0x22)])], 9)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log)])

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    assert result.plan.recover_header
    assert result.plan.header_source_log == "LOG1"
    assert result.verification["checksum_valid"]
    assert result.verification["sequence_numbers_equal"]
    assert result.final_sequence == 10


def test_clean_hive_needs_no_recovery():
    primary = build_primary(seq1=7, seq2=7, hbins_size=0x1000)
    log = build_log([build_log_entry(7, [page(0x0, 0x11)])], 7)

    result = RegistryRecovery.recover_hive(primary, [("LOG1", log)])

    assert result.status == RegistryRecovery.STATUS_NOT_REQUIRED
    assert not result.diagnostic_only
    assert result.derived_data == primary


def test_unusable_log_is_rejected_not_fatal():
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x1000)
    good = build_log([build_log_entry(9, [page(0x0, 0x11)])], 9)

    result = RegistryRecovery.recover_hive(
        primary, [("garbage", b"not a registry file"), ("LOG1", good)])

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    roles = {l["name"]: l["role"] for l in result.plan.logs}
    assert roles["garbage"] == "rejected"
    assert roles["LOG1"] == "applied"


# --- real sample sets -----------------------------------------------------

def _load_sample(name):
    base = os.path.join(SAMPLES, name)
    with open(os.path.join(base, "SYSTEM"), "rb") as f:
        primary = f.read()
    logs = []
    for log_name in ("SYSTEM.LOG1", "SYSTEM.LOG2"):
        with open(os.path.join(base, log_name), "rb") as f:
            logs.append((log_name, f.read()))
    return primary, logs


@pytest.mark.skipif(not os.path.isdir(os.path.join(SAMPLES, "new_log_1")),
                    reason="transaction log samples not available")
def test_real_sample_log_order_swap_gives_identical_hive():
    primary_a, logs_a = _load_sample("new_log_1")
    primary_b, logs_b = _load_sample("new_log_1_reversed")  # LOG1/LOG2 swapped on disk

    result_a = RegistryRecovery.recover_hive(primary_a, logs_a)
    result_b = RegistryRecovery.recover_hive(primary_b, logs_b)

    assert result_a.status == RegistryRecovery.STATUS_COMPLETE
    assert result_b.status == RegistryRecovery.STATUS_COMPLETE
    # File names differ, sequence numbers do not: the copies must match.
    assert result_a.derived_sha256 == result_b.derived_sha256
    # The recovered hive is parseable by python-registry.
    reg = Registry.Registry(io.BytesIO(result_a.derived_data))
    assert reg.root() is not None


@pytest.mark.skipif(not os.path.isdir(os.path.join(
        SAMPLES, "new_log_1_reversed_and_invalid_checksum")),
        reason="transaction log samples not available")
def test_real_sample_invalid_primary_checksum():
    primary, logs = _load_sample("new_log_1_reversed_and_invalid_checksum")

    result = RegistryRecovery.recover_hive(primary, logs)

    assert result.plan.recover_header
    assert result.status == RegistryRecovery.STATUS_COMPLETE
    reg = Registry.Registry(io.BytesIO(result.derived_data))
    assert reg.root() is not None


@pytest.mark.skipif(not os.path.isdir(os.path.join(SAMPLES, "new_log_2")),
                    reason="transaction log samples not available")
def test_real_sample_stale_log_is_not_applied():
    primary, logs = _load_sample("new_log_2")

    result = RegistryRecovery.recover_hive(primary, logs)

    assert result.status == RegistryRecovery.STATUS_COMPLETE
    roles = {l["name"]: l["role"] for l in result.plan.logs}
    assert roles["SYSTEM.LOG2"] == "stale"  # sequence 196 predates the primary
    assert roles["SYSTEM.LOG1"] == "applied"


def test_cli_entry_point_partial_and_manifest(tmp_path):
    """The CLI writes a clearly-marked .partial copy plus manifest on gaps."""
    import subprocess
    primary = build_primary(seq1=10, seq2=9, hbins_size=0x1000)
    log_a = build_log([build_log_entry(9, [page(0x0, 0x11)])], 9)
    log_b = build_log([build_log_entry(11, [page(0x200, 0x22)])], 11)

    primary_path = tmp_path / "HIVE"
    log1_path = tmp_path / "HIVE.LOG1"
    log2_path = tmp_path / "HIVE.LOG2"
    primary_path.write_bytes(primary)
    log1_path.write_bytes(log_a)
    log2_path.write_bytes(log_b)
    out_dir = tmp_path / "out"
    hashes_before = {str(p): sha256(p.read_bytes())
                     for p in (primary_path, log1_path, log2_path)}

    proc = subprocess.run(
        [sys.executable,
         os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "recover_hive.py"),
         "--primary", str(primary_path),
         "--log", str(log1_path), "--log", str(log2_path),
         "--output-dir", str(out_dir)],
        capture_output=True, text=True)

    assert proc.returncode == 1  # partial
    assert not (out_dir / "HIVE.recovered").exists()
    assert (out_dir / "HIVE.partial").exists()

    import json
    manifest = json.loads((out_dir / "HIVE.manifest.json").read_text())
    assert manifest["status"] == "partial"
    assert manifest["diagnostic_only"]
    assert manifest["plan"]["gaps"] == [10]
    assert manifest["evidence_unmodified"]
    assert {k: v for k, v in manifest["evidence_sha256_after"].items()} == hashes_before
