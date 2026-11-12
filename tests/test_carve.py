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

import datetime
import struct

import pytest

from Registry.RegistryCarve import (
    CandidateStatus,
    DeletedRecordScanner,
    ReferenceStatus,
)

FIRST_HBIN = 0x1000
HBIN_SIZE = 0x1000
HBIN_END = FIRST_HBIN + HBIN_SIZE

# a plausible last-write timestamp (2020-01-01 UTC) for synthetic nk records
TIMESTAMP_2020 = int(
    (datetime.datetime(2020, 1, 1) - datetime.datetime(1601, 1, 1)).total_seconds()
    * int(1e7))


def nk_record(name, flags=0x24, parent=0xFFFFFFFF, subkey_count=0,
              subkey_list=0xFFFFFFFF, values_count=0,
              values_list=0xFFFFFFFF, sk=0xFFFFFFFF,
              timestamp=TIMESTAMP_2020):
    """Build an ascii-named nk record body (without the cell header)."""
    name_b = name.encode("windows-1252")
    rec = bytearray(0x4C)
    rec[0:2] = b"nk"
    struct.pack_into("<H", rec, 0x2, flags)
    struct.pack_into("<Q", rec, 0x4, timestamp)
    struct.pack_into("<I", rec, 0x10, parent)
    struct.pack_into("<I", rec, 0x14, subkey_count)
    struct.pack_into("<I", rec, 0x18, 0xFFFFFFFF)
    struct.pack_into("<I", rec, 0x1C, subkey_list)
    struct.pack_into("<I", rec, 0x20, 0xFFFFFFFF)
    struct.pack_into("<I", rec, 0x24, values_count)
    struct.pack_into("<I", rec, 0x28, values_list)
    struct.pack_into("<I", rec, 0x2C, sk)
    struct.pack_into("<I", rec, 0x30, 0xFFFFFFFF)
    struct.pack_into("<H", rec, 0x48, len(name_b))
    return bytes(rec) + name_b


def vk_record(name, data_type, data_rel=0, data_length=0x80000004,
              inline_dword=0):
    """Build an ascii-named vk record body (without the cell header)."""
    name_b = name.encode("windows-1252")
    rec = bytearray(0x14)
    rec[0:2] = b"vk"
    struct.pack_into("<H", rec, 0x2, len(name_b))
    struct.pack_into("<I", rec, 0x4, data_length)
    if data_length >= 0x80000000 or data_length < 5:
        struct.pack_into("<I", rec, 0x8, inline_dword)
    else:
        struct.pack_into("<I", rec, 0x8, data_rel)
    struct.pack_into("<I", rec, 0xC, data_type)
    struct.pack_into("<H", rec, 0x10, 1)
    return bytes(rec) + name_b


class SyntheticHive(object):
    """Builds a minimal single-hbin hive with caller-defined cells."""

    def __init__(self):
        self._cells = []  # [offset, size, data(bytearray), free]
        self._cursor = FIRST_HBIN + 0x20

    def add_cell(self, data, free):
        size = (len(data) + 4 + 7) & ~7
        padded = bytearray(size - 4)
        padded[0:len(data)] = data
        offset = self._cursor
        self._cells.append([offset, size, padded, free])
        self._cursor += size
        return offset

    @staticmethod
    def rel(cell_offset):
        return cell_offset - FIRST_HBIN

    def build(self, root_cell):
        pad_size = HBIN_END - self._cursor
        assert pad_size >= 8

        regf = bytearray(FIRST_HBIN)
        regf[0:4] = b"regf"
        struct.pack_into("<I", regf, 0x4, 1)
        struct.pack_into("<I", regf, 0x8, 1)
        struct.pack_into("<I", regf, 0x14, 1)
        struct.pack_into("<I", regf, 0x18, 3)
        struct.pack_into("<I", regf, 0x20, 1)
        struct.pack_into("<I", regf, 0x24, self.rel(root_cell))
        struct.pack_into("<I", regf, 0x28, HBIN_SIZE)
        struct.pack_into("<I", regf, 0x2C, 1)
        xsum = 0
        for i in range(0, 0x1FC, 4):
            xsum ^= struct.unpack_from("<I", regf, i)[0]
        struct.pack_into("<I", regf, 0x1FC, xsum)

        hbin = bytearray(HBIN_SIZE)
        hbin[0:4] = b"hbin"
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)
        for (offset, size, data, free) in self._cells:
            signed = size if free else -size
            struct.pack_into("<i", hbin, offset - FIRST_HBIN, signed)
            start = offset - FIRST_HBIN + 4
            hbin[start:start + len(data)] = data
        struct.pack_into("<i", hbin, self._cursor - FIRST_HBIN, pad_size)

        return bytes(regf) + bytes(hbin)


@pytest.fixture(scope="module")
def hive_layout():
    """
    A synthetic hive containing:
      - an active root key with an active value named "SameName"
      - a deleted key "DeletedKey" whose values list points at a deleted
        value "DeletedValue", which in turn points at a deleted data cell
      - a deleted value also named "SameName" (name collision with the
        active value; must NOT be associated with the active key)
      - a deleted value "BrokenRef" whose data reference points outside
        the hbins area (overwritten reference)
      - a fake "nk" signature followed by garbage
      - a fake "vk" signature embedded in junk inside a free cell
      - a truncated "nk" fragment (cell too small for the fixed header)
      - a valid deleted vk "Embedded" found mid-cell (cell remnant)
    """
    h = SyntheticHive()

    root = h.add_cell(nk_record("ROOT", values_count=1, values_list=0),
                      free=False)
    active_vk = h.add_cell(vk_record("SameName", 0x4, inline_dword=1234),
                           free=False)
    root_vals = h.add_cell(struct.pack("<I", h.rel(active_vk)), free=False)
    # patch the root nk to point at its values list
    root_nk = nk_record("ROOT", values_count=1, values_list=h.rel(root_vals))
    h._cells[0][2][0:len(root_nk)] = root_nk

    del_data = h.add_cell("Deleted!".encode("utf-16le"), free=True)
    del_vk = h.add_cell(vk_record("DeletedValue", 0x1,
                                  data_rel=h.rel(del_data),
                                  data_length=0x10),
                        free=True)
    del_vals = h.add_cell(struct.pack("<I", h.rel(del_vk)), free=True)
    del_nk = h.add_cell(nk_record("DeletedKey", flags=0x20,
                                  parent=h.rel(root),
                                  values_count=1,
                                  values_list=h.rel(del_vals)),
                        free=True)

    dup_vk = h.add_cell(vk_record("SameName", 0x4, inline_dword=5678),
                        free=True)

    broken_vk = h.add_cell(vk_record("BrokenRef", 0x3,
                                     data_rel=0x00FFFFF0,
                                     data_length=0x20),
                           free=True)

    fake_nk = bytearray(0x5C)
    fake_nk[0:2] = b"nk"
    struct.pack_into("<H", fake_nk, 0x2, 0x20)
    struct.pack_into("<H", fake_nk, 0x48, 4)
    fake_nk[0x4C:0x50] = b"\x01\x02\x03\x04"
    h.add_cell(bytes(fake_nk), free=True)

    junk = bytearray((i * 37 + 11) & 0xFF for i in range(0x3C))
    junk[8:10] = b"vk"
    struct.pack_into("<H", junk, 8 + 0x2, 6)   # odd-length unicode name
    struct.pack_into("<H", junk, 8 + 0x10, 0)  # unicode name flag
    h.add_cell(bytes(junk), free=True)

    trunc_nk = bytearray(0x1C)
    trunc_nk[0:2] = b"nk"
    h.add_cell(bytes(trunc_nk), free=True)

    embed = bytearray(0x44)
    embedded_vk = vk_record("Embedded", 0x4, inline_dword=99)
    embed[8:8 + len(embedded_vk)] = embedded_vk
    embed_off = h.add_cell(bytes(embed), free=True)

    buf = h.build(root)
    return {
        "buf": buf,
        "root": root,
        "active_vk": active_vk,
        "del_nk": del_nk,
        "del_vk": del_vk,
        "del_data": del_data,
        "dup_vk": dup_vk,
        "broken_vk": broken_vk,
        "embedded_record_offset": embed_off + 4 + 8,
    }


@pytest.fixture(scope="module")
def report(hive_layout):
    return DeletedRecordScanner(hive_layout["buf"]).scan()


def candidate_at(report, record_offset):
    for c in report.candidates:
        if c.offset == record_offset:
            return c
    return None


def test_deleted_key_is_reliable_with_verified_associations(hive_layout, report):
    cand = candidate_at(report, hive_layout["del_nk"] + 4)
    assert cand is not None
    assert cand.record_type == "nk"
    assert cand.name == "DeletedKey"
    assert cand.status == CandidateStatus.RELIABLE
    verified = {r.field: r for r in cand.verified_references()}
    # parent association verified against the active root cell
    assert verified["parent_key"].target_offset == hive_layout["root"]
    # values list entry association verified against the deleted vk cell
    assert verified["values_list[0]"].target_offset == hive_layout["del_vk"]


def test_deleted_value_is_reliable_and_back_referenced(hive_layout, report):
    cand = candidate_at(report, hive_layout["del_vk"] + 4)
    assert cand is not None
    assert cand.record_type == "vk"
    assert cand.name == "DeletedValue"
    assert cand.status == CandidateStatus.RELIABLE
    data_refs = [r for r in cand.verified_references() if r.field == "data"]
    assert len(data_refs) == 1
    assert data_refs[0].target_offset == hive_layout["del_data"]
    # verifiable association: the deleted key's values list points here
    assert len(cand.referenced_by) == 1
    source, ref = cand.referenced_by[0]
    assert source.offset == hive_layout["del_nk"] + 4


def test_name_collision_never_associates_with_active_key(hive_layout, report):
    cand = candidate_at(report, hive_layout["dup_vk"] + 4)
    assert cand is not None
    assert cand.name == "SameName"
    assert cand.status == CandidateStatus.RELIABLE
    # the deleted value shares its name with the active value, but no
    # association to the active key/value may be reported
    assert cand.referenced_by == []
    for r in cand.references:
        assert r.target_offset != hive_layout["root"]
        assert r.target_offset != hive_layout["active_vk"]


def test_overwritten_data_reference_is_partial(hive_layout, report):
    cand = candidate_at(report, hive_layout["broken_vk"] + 4)
    assert cand is not None
    assert cand.name == "BrokenRef"
    assert cand.status == CandidateStatus.PARTIAL
    unresolved = cand.unresolved()
    assert any("data" in u for u in unresolved)
    data_ref = [r for r in cand.references if r.field == "data"][0]
    assert data_ref.status == ReferenceStatus.UNVERIFIABLE
    # the clue still points at the raw evidence bytes
    assert data_ref.field_offset == cand.offset + 0x8


def test_fake_signatures_are_rejected(hive_layout, report):
    assert len(report.rejections) == 2
    sigs = sorted(r.signature for r in report.rejections)
    assert sigs == ["nk", "vk"]
    for r in report.rejections:
        assert r.reasons
        # rejections carry their evidence offset as well
        assert hive_layout["buf"][r.offset:r.offset + 2] in (b"nk", b"vk")


def test_truncated_fragment_is_orphan(hive_layout, report):
    orphans = report.orphans()
    assert len(orphans) == 1
    orphan = orphans[0]
    assert orphan.record_type == "nk"
    assert orphan.name is None
    assert orphan.length == 0x1C
    assert any("truncated" in a for a in orphan.anomalies)


def test_embedded_remnant_found_mid_cell(hive_layout, report):
    cand = candidate_at(report, hive_layout["embedded_record_offset"])
    assert cand is not None
    assert cand.record_type == "vk"
    assert cand.name == "Embedded"
    assert cand.status == CandidateStatus.RELIABLE


def test_evidence_bytes_traceable(hive_layout, report):
    buf = hive_layout["buf"]
    for cand in report.candidates:
        assert cand.raw_bytes() == buf[cand.offset:cand.offset + cand.length]
        assert cand.raw_bytes()[0:2] in (b"nk", b"vk")
        for line in cand.hexdump().splitlines():
            assert line.startswith("0x")


def test_scan_does_not_modify_hive(hive_layout):
    buf = hive_layout["buf"]
    before = bytes(buf)
    DeletedRecordScanner(buf).scan()
    assert buf == before


def test_classification_counts(report):
    # DeletedKey, DeletedValue, SameName(deleted), Embedded -> reliable
    assert len(report.reliable()) == 4
    # BrokenRef -> partial
    assert len(report.partial()) == 1
    # truncated nk -> orphan
    assert len(report.orphans()) == 1
