"""Generate controlled mini hives that exercise time-evidence edge cases.

Each scenario is built from explicit FILETIME integers so the raw value, its
byte offset, the library interpretation and the uncertainty reason can all be
shown side by side. Nothing here fabricates an "event time"; hives only carry
the fields the Windows format actually defines.
"""
from __future__ import annotations

import os
import struct

from .synth import MiniHive, MiniLog, REG_DWORD, REG_SZ, HBIN_OFFSET, regf_checksum

# Reference FILETIMEs (100ns since 1601-01-01 UTC).
FT_2019 = 131958336000000000            # 2019-02-28 13:20:00 UTC
FT_2020 = 132256800000000000            # 2020-03-01 00:00:00 UTC
FT_ROLLBACK_1970 = 116444736000000000   # 1970-01-01 00:00:00 UTC
FT_INVALID_HUGE = 0xFFFFFFFFFFFFFFFF    # unrenderable by datetime
FT_ZERO = 0


def _tree(hive: MiniHive, root_ft: int, child_ft: int, value_dword: int):
    root = hive.alloc_nk_shell("CMI", root_ft, is_root=True)
    assert root["cell_rel"] == 0x20
    v_flag, _ = hive.alloc_vk("ConfigFlag", struct.pack("<I", value_dword), REG_DWORD)
    v_note, _ = hive.alloc_vk("Note", "baseline\u0000".encode("utf-16le"), REG_SZ)
    child = hive.alloc_nk_shell("SvcA", child_ft)
    hive.fill_nk_links(child, 0x20, vk_cell_rels=[v_flag])
    hive.fill_nk_links(root, 0x20, subkey_cell_rels=[child["cell_rel"]], vk_cell_rels=[v_note])
    return root, child


def build_clock_rollback(out_dir: str) -> dict:
    """Two hives with identical key layout; the later-collected hive has an NK
    time that is *older* than the first, demonstrating host clock rollback."""
    h1 = MiniHive("\\??\\C:\\rollback", FT_2019, 7, 7)
    root1, child1 = _tree(h1, FT_2019, FT_2019, 7)
    hive_a = h1.build(root_cell_rel=0x20)

    h2 = MiniHive("\\??\\C:\\rollback", FT_ROLLBACK_1970, 8, 8)
    root2, child2 = _tree(h2, FT_ROLLBACK_1970, FT_ROLLBACK_1970, 7)
    hive_b = h2.build(root_cell_rel=0x20)

    paths = []
    for name, blob in [("rollback_a.hive", hive_a), ("rollback_b.hive", hive_b)]:
        path = os.path.join(out_dir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        paths.append(path)
    return {
        "scenario": "clock_rollback",
        "files": paths,
        "teaching_point": "hive B was collected after hive A (seq 8 > 7) but its NK FILETIME decodes to 1970, earlier than A's 2019; ordering by raw FILETIME contradicts the write sequence, indicating clock manipulation/skew rather than a real 1970 event",
        "offsets": {
            "root_nk_filetime": hex(root1["filetime_field_abs"]),
            "child_nk_filetime": hex(child1["filetime_field_abs"]),
            "regf_header_filetime": "0x0C",
        },
    }


def build_invalid_filetime(out_dir: str) -> dict:
    """A hive whose NK carries an out-of-range FILETIME the library cannot render."""
    hive_obj = MiniHive("\\??\\C:\\invalid", FT_2019, 9, 9)
    root, child = _tree(hive_obj, FT_2019, FT_INVALID_HUGE, 7)
    blob = hive_obj.build(root_cell_rel=0x20)
    path = os.path.join(out_dir, "invalid_filetime.hive")
    with open(path, "wb") as fh:
        fh.write(blob)
    return {
        "scenario": "invalid_filetime",
        "files": [path],
        "teaching_point": "the child NK raw FILETIME is 0xFFFFFFFFFFFFFFFF; RegistryKey.timestamp() raises OverflowError. The bytes are still evidence, but no UTC interpretation exists and it must not be silently dropped or forced to an epoch.",
        "offsets": {
            "child_nk_filetime": hex(child["filetime_field_abs"]),
            "root_nk_filetime": hex(root["filetime_field_abs"]),
        },
        "raw_values": {"child_nk_filetime": "0x%016X" % FT_INVALID_HUGE},
    }


def build_value_only_change(out_dir: str) -> dict:
    """Two hives differing only in a value; the parent NK time is unchanged,
    so a per-value event time cannot be established."""
    h1 = MiniHive("\\??\\C:\\valonly", FT_2019, 10, 10)
    root1, child1 = _tree(h1, FT_2019, FT_2019, 7)
    before = h1.build(root_cell_rel=0x20)

    h2 = MiniHive("\\??\\C:\\valonly", FT_2019, 11, 11)
    root2, child2 = _tree(h2, FT_2019, FT_2019, 9)   # ConfigFlag 7 -> 9, same NK FILETIME
    after = h2.build(root_cell_rel=0x20)

    paths = []
    for name, blob in [("value_before.hive", before), ("value_after.hive", after)]:
        path = os.path.join(out_dir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        paths.append(path)
    return {
        "scenario": "value_only_change",
        "files": paths,
        "teaching_point": "ConfigFlag changed 7 -> 9 while the SvcA NK last-written FILETIME is byte-identical. Standard hives store no per-value timestamp, so the value change has no independently confirmable time; only the enclosing key time is available, and it did not move.",
        "offsets": {
            "child_nk_filetime": hex(child1["filetime_field_abs"]),
        },
    }


def build_recovery_pair(out_dir: str) -> dict:
    """A dirty primary hive plus a valid Win8.1-style log that rewrites a page
    containing a child NK FILETIME, so pre/post recovery time fields differ."""
    base = MiniHive("\\??\\C:\\recovery", FT_2019, 5, 5)
    root, child = _tree(base, FT_2019, FT_2019, 7)
    clean = base.build(root_cell_rel=0x20)

    dirty = bytearray(clean)
    struct.pack_into("<I", dirty, 0x04, 6)     # seq1 advanced, seq2 stays 5 -> mid-update
    struct.pack_into("<I", dirty, 0x1FC, 0)   # zero slot before recomputing checksum
    struct.pack_into("<I", dirty, 0x1FC, regf_checksum(bytes(dirty[:0x200])))
    dirty_path = os.path.join(out_dir, "recovery_dirty.hive")
    with open(dirty_path, "wb") as fh:
        fh.write(dirty)

    new_ft = FT_2020
    page = bytearray(dirty[HBIN_OFFSET:HBIN_OFFSET + 0x1000])
    page_rel = child["filetime_field_abs"] - HBIN_OFFSET
    struct.pack_into("<Q", page, page_rel, new_ft)

    log = MiniLog("\\??\\C:\\recovery", sequence=6, hbins_size=0x1000,
                  header_filetime=FT_2019)
    log_blob = log.build([(0, bytes(page))])
    log_path = os.path.join(out_dir, "recovery.LOG1")
    with open(log_path, "wb") as fh:
        fh.write(log_blob)

    return {
        "scenario": "transaction_log_recovery",
        "files": [dirty_path, log_path],
        "teaching_point": "dirty primary is seq 6/5; the HvLE (seq 6, no timestamp field) carries a page whose child NK FILETIME is 2020. Recovery replays the page and equalizes seq to 6, but the REGF header FILETIME at 0x0C stays 2019. The log establishes order via sequence numbers, never a wall-clock instant.",
        "offsets": {
            "child_nk_filetime": hex(child["filetime_field_abs"]),
            "hvle_sequence": "LOG1 0x200+0x0C",
            "regf_header_filetime": "0x0C",
        },
        "expected_child_filetime_after": "0x%016X" % new_ft,
    }


def build_appcontainer_value_timestamp(out_dir: str) -> dict:
    """A settings.dat-style hive whose composite value carries its own trailing
    FILETIME, exercising the only per-value timestamp interface in the library."""
    composite_type = 0x100 | 0x105  # REG_COMPOSITE_TYPE | RegUint32
    value_data = struct.pack("<I", 42) + struct.pack("<Q", FT_2019 + 20_000_000)
    hive_obj = MiniHive(
        "\\??\\C:\\Users\\tester\\AppData\\Local\\Packages\\demo\\settings.dat",
        FT_2019, 3, 3,
    )
    root = hive_obj.alloc_nk_shell("Root", FT_2019, is_root=True)
    vk_rel, _ = hive_obj.alloc_vk("AppPref", value_data, composite_type)
    hive_obj.fill_nk_links(root, 0x20, vk_cell_rels=[vk_rel])
    blob = hive_obj.build(root_cell_rel=0x20)
    path = os.path.join(out_dir, "settings_appcontainer.dat")
    with open(path, "wb") as fh:
        fh.write(blob)
    return {
        "scenario": "appcontainer_value_timestamp",
        "files": [path],
        "teaching_point": "VKRecord.has_timestamp() is True only when the value data type has the 0x100 composite flag and >=8 bytes; the timestamp is the final 8 bytes of the value data. RegistryValue.timestamp() works here but raises ValueError on every ordinary SYSTEM/SOFTWARE/NTUSER value, which have no per-value time.",
        "offsets": {"value_timestamp": "final 8 bytes of the AppPref VK data"},
    }


def build_all(out_dir: str) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    return [
        build_clock_rollback(out_dir),
        build_invalid_filetime(out_dir),
        build_value_only_change(out_dir),
        build_appcontainer_value_timestamp(out_dir),
        build_recovery_pair(out_dir),
    ]
