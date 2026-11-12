"""Focused tests for the separated time-evidence backend and synthetic samples."""
import io
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from Registry import Registry, RegistryLog  # noqa: E402

from reg_evidence import scenarios  # noqa: E402
from reg_evidence.extract import extract_all, interpret_filetime  # noqa: E402
from reg_evidence.synth import (  # noqa: E402
    MiniHive,
    MiniLog,
    REG_DWORD,
    REG_SZ,
    HBIN_OFFSET,
    regf_checksum,
)

FT_2019 = scenarios.FT_2019
FT_2020 = scenarios.FT_2020


def test_interpret_filetime_classifications():
    assert interpret_filetime(0).interpretation_kind == "zero_epoch"
    assert interpret_filetime(scenarios.FT_ROLLBACK_1970).interpretation_kind == "implausible"
    assert interpret_filetime(scenarios.FT_INVALID_HUGE).interpretation_kind == "unrenderable"
    assert interpret_filetime(FT_2019).interpretation_kind == "valid"
    # never raises and always preserves the raw integer
    huge = interpret_filetime(scenarios.FT_INVALID_HUGE)
    assert huge.raw_uint64 == scenarios.FT_INVALID_HUGE and huge.interpreted_utc is None


def _build_simple(seq1, seq2, child_ft):
    hive = MiniHive("\\??\\C:\\t", FT_2019, seq1, seq2)
    root = hive.alloc_nk_shell("CMI", FT_2019, is_root=True)
    vk, _ = hive.alloc_vk("Flag", struct.pack("<I", 1), REG_DWORD)
    child = hive.alloc_nk_shell("SvcA", child_ft)
    hive.fill_nk_links(child, 0x20, vk_cell_rels=[vk])
    hive.fill_nk_links(root, 0x20, subkey_cell_rels=[child["cell_rel"]])
    return hive.build(0x20), child


def test_synthetic_hive_parses_and_checksum_valid(tmp_path):
    blob, child = _build_simple(5, 5, FT_2019)
    path = tmp_path / "mini.hive"
    path.write_bytes(blob)
    reg = Registry.Registry(str(path))
    assert reg._regf.validate_checksum() is True
    assert reg.root().name() == "CMI"
    sub = reg.root().subkeys()[0]
    assert sub.name() == "SvcA"
    # cited byte offset really holds the NK FILETIME
    abs_off = child["filetime_field_abs"]
    assert struct.unpack_from("<Q", blob, abs_off)[0] == FT_2019
    assert abs_off == sub._nkrecord.offset() + 0x4


def test_clock_rollback_marks_implausible(tmp_path):
    manifest = scenarios.build_clock_rollback(str(tmp_path))
    doc_b = extract_all(manifest["files"][1])
    child = next(k for k in doc_b["key_evidence"] if k["key_path"].endswith("SvcA"))
    assert child["interpretation_kind"] == "implausible"
    assert child["raw_uint64"] == scenarios.FT_ROLLBACK_1970


def test_invalid_filetime_keeps_raw_without_crashing(tmp_path):
    manifest = scenarios.build_invalid_filetime(str(tmp_path))
    doc = extract_all(manifest["files"][0])
    child = next(k for k in doc["key_evidence"] if k["key_path"].endswith("SvcA"))
    assert child["interpretation_kind"] == "unrenderable"
    assert child["interpreted_utc"] is None
    with pytest.raises(OverflowError):
        Registry.Registry(manifest["files"][0]).root().subkeys()[0].timestamp()


def test_value_only_change_has_no_value_timestamp(tmp_path):
    manifest = scenarios.build_value_only_change(str(tmp_path))
    after = extract_all(manifest["files"][1])
    child = next(k for k in after["key_evidence"] if k["key_path"].endswith("SvcA"))
    assert child["values"][0]["value_timestamp"]["available"] is False
    before = extract_all(manifest["files"][0])
    b = next(k for k in before["key_evidence"] if k["key_path"].endswith("SvcA"))
    assert b["raw_uint64"] == child["raw_uint64"]  # NK time byte-identical


def test_appcontainer_value_timestamp_available(tmp_path):
    manifest = scenarios.build_appcontainer_value_timestamp(str(tmp_path))
    doc = extract_all(manifest["files"][0])
    value = doc["key_evidence"][0]["values"][0]
    assert value["has_value_timestamp"] is True
    assert value["value_timestamp"]["available"] is True


def test_synthetic_log_recovery_updates_nk_but_not_header(tmp_path):
    manifest = scenarios.build_recovery_pair(str(tmp_path))
    dirty_path, log_path = manifest["files"]
    before = extract_all(dirty_path)
    assert before["integrity"]["recovery_required"]["recover_data"] is True

    buf = io.BytesIO(open(dirty_path, "rb").read())
    RegistryLog.RegistryLog(buf, log_path).recover_hive()
    buf.seek(0)
    recovered = buf.read()
    rec_path = tmp_path / "rec.hive"
    rec_path.write_bytes(recovered)
    after = extract_all(str(rec_path))

    assert after["integrity"]["recovery_required"]["recover_data"] is False
    assert after["header_evidence"]["sequence_state"]["seq1"] == 6
    assert after["header_evidence"]["sequence_state"]["seq2"] == 6
    # header FILETIME untouched by library recovery
    assert (
        before["header_evidence"]["fields"][2]["raw_uint64"]
        == after["header_evidence"]["fields"][2]["raw_uint64"]
    )
    # child NK FILETIME replaced by the replayed dirty page (2019 -> 2020)
    cb = next(k for k in before["key_evidence"] if k["key_path"].endswith("SvcA"))
    ca = next(k for k in after["key_evidence"] if k["key_path"].endswith("SvcA"))
    assert cb["raw_uint64"] == FT_2019 and ca["raw_uint64"] == FT_2020


def test_hvle_carries_no_timestamp_field():
    # HvLE fixed header is 0x28 bytes; every field is accounted for and none is
    # a FILETIME. The contract therefore keeps wallclock_inference as null.
    manifest = scenarios.build_recovery_pair(os.path.join(HERE, "samples"))
    log_buf = open(manifest["files"][1], "rb").read()
    assert log_buf[0x200:0x204] == b"HvLE"
    # sequence DWORD at HvLE+0x0C, no 8-byte time field anywhere in the header
    assert struct.unpack_from("<I", log_buf, 0x200 + 0x0C)[0] == 6


def test_checksum_helper_self_cancels():
    hive = MiniHive("\\??\\C:\\cs", FT_2019, 5, 5)
    root = hive.alloc_nk_shell("CMI", FT_2019, is_root=True)
    hive.fill_nk_links(root, 0x20)
    blob = hive.build(0x20)
    assert Registry.Registry  # module import sanity
    assert regf_checksum(blob[:0x1FC] + b"\x00\x00\x00\x00") == struct.unpack_from("<I", blob, 0x1FC)[0]
