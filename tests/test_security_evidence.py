# -*- coding: utf-8 -*-
"""
Tests for the security descriptor evidence export.

These rely on hand assembled hives produced by
tests/security_tools/make_security_hives.py; regenerate them with:

    python tests/security_tools/make_security_hives.py

The fixtures deliberately cover:
  * two keys sharing one SK record (shared descriptor + reference counting),
  * a present-but-empty DACL versus a missing DACL,
  * an out-of-bounds ACE, an unknown ACE type,
  * and corrupted SK references / reference counters.
"""
import os
import struct

import pytest

from Registry import Registry
from Registry import SecurityParse
from Registry.RegistryParse import NKRecord

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "reg_samples")


def _hive(name):
    return Registry.Registry(os.path.join(SAMPLE_DIR, name))


def _all_keys(key):
    keys = [key]
    for subkey in key.subkeys():
        keys.extend(_all_keys(subkey))
    return keys


def _by_path(key):
    return {item.path(): item for item in _all_keys(key)}


# --------------------------------------------------------------------------
# Structural facts from a well formed hive
# --------------------------------------------------------------------------

def test_clean_hive_tree_loads():
    reg = _hive("security_clean.hive")
    keys = _by_path(reg.root())
    assert set(keys) == {
        "Root",
        "Root\\SharedA",
        "Root\\EmptyDacl",
        "Root\\MissingDacl",
    }


def test_two_keys_share_one_sk_record():
    reg = _hive("security_clean.hive")
    keys = _by_path(reg.root())
    root = keys["Root"].security()
    shared = keys["Root\\SharedA"].security()

    # Both NK records follow the same real reference to the same cell.
    assert root.sk_reference_offset == shared.sk_reference_offset
    assert root.sk_cell_offset == shared.sk_cell_offset
    assert root.sk_offset == shared.sk_offset
    assert root.sk_cell_offset is not None

    # The stored counter and the independently observed pointer count agree.
    assert root.declared_reference_count == 2
    assert root.observed_reference_count == 2
    assert root.reference_count_consistent is True
    assert root.anomalies == []


def test_evidence_objects_are_distinct_per_key():
    reg = _hive("security_clean.hive")
    keys = _by_path(reg.root())
    root = keys["Root"].security()
    shared = keys["Root\\SharedA"].security()
    assert root is not shared
    # Mutable per-key state must never be shared between keys.
    root.anomalies.append("synthetic marker")
    assert "synthetic marker" not in shared.anomalies


def test_owner_group_and_aces_are_parsed():
    reg = _hive("security_clean.hive")
    root = _by_path(reg.root())["Root"].security()
    sd = root.descriptor

    assert sd.owner.sid == "S-1-5-21-1-2-3-500"
    assert sd.group.sid == "S-1-5-21-1-2-3-512"

    dacl = sd.dacl
    assert sd.dacl_present is True
    assert len(dacl.aces) == 2
    allowed, denied = dacl.aces
    assert allowed.ace_type_name == "ACCESS_ALLOWED"
    assert allowed.access_mask == 0x000F001F
    assert allowed.sid.sid == "S-1-5-21-1-2-3-512"
    assert "KEY_ALL_ACCESS" in allowed.access_right_names
    assert denied.ace_type_name == "ACCESS_DENIED"
    assert denied.sid.sid == "S-1-5-32-545"

    sacl = sd.sacl
    assert sd.sacl_present is True
    assert len(sacl.aces) == 1
    audit = sacl.aces[0]
    assert audit.ace_type_name == "SYSTEM_AUDIT"
    assert audit.ace_flag_names == ["SUCCESSFUL_ACCESS", "FAILED_ACCESS"]


def test_raw_bytes_and_offsets_are_retained():
    reg = _hive("security_clean.hive")
    evidence = _by_path(reg.root())["Root"].security()
    sd = evidence.descriptor
    buf = reg._buf

    # Every retained byte span must match the live buffer at its offset.
    assert buf[sd.offset:sd.offset + len(sd.raw_bytes)] == sd.raw_bytes
    for acl in (sd.dacl, sd.sacl):
        assert buf[acl.offset:acl.offset + len(acl.raw_bytes)] == acl.raw_bytes
        for ace in acl.aces:
            assert buf[ace.offset:ace.offset + ace.size] == ace.raw_bytes
            assert buf[ace.sid.offset:
                       ace.sid.offset + len(ace.sid.raw_bytes)] == \
                ace.sid.raw_bytes

    # Offsets are absolute and strictly ordered within the descriptor.
    assert sd.offset == evidence.sk_offset + 0x14
    assert sd.owner.offset > sd.offset
    assert sd.dacl.offset > sd.group.offset


def test_empty_dacl_is_distinct_from_missing_dacl():
    reg = _hive("security_clean.hive")
    keys = _by_path(reg.root())

    empty = keys["Root\\EmptyDacl"].security().descriptor
    missing = keys["Root\\MissingDacl"].security().descriptor

    # Present but empty: a real ACL object with zero ACEs.
    assert empty.dacl_present is True
    assert empty.dacl is not None
    assert empty.dacl.is_empty() is True
    assert empty.dacl.aces == []

    # Missing: control bit clear and no ACL object at all.
    assert missing.dacl_present is False
    assert missing.dacl is None

    # The two must never compare equal or be conflated by a report.
    assert (empty.dacl_present, empty.dacl is None) != \
           (missing.dacl_present, missing.dacl is None)


def test_no_effective_permission_logic_is_exposed():
    # The module offers parsing and evidence only; no access-check API.
    assert not hasattr(SecurityParse, "effective_permissions")
    assert not hasattr(SecurityParse, "access_check")
    assert not hasattr(SecurityParse.SecurityEvidence, "grants")


# --------------------------------------------------------------------------
# Corruption handling: anomalies and unsupported content stay isolated
# --------------------------------------------------------------------------

def test_reference_count_over_declared_is_anomaly():
    reg = _hive("security_bad_refcount.hive")
    root = _by_path(reg.root())["Root"].security()
    assert root.declared_reference_count == 9
    assert root.observed_reference_count == 2
    assert root.reference_count_consistent is False
    assert any("usage counter inconsistency" in n for n in root.anomalies)
    # Descriptor itself still parses cleanly.
    assert root.descriptor is not None
    assert len(root.descriptor.dacl.aces) == 2


def test_reference_count_under_declared_is_anomaly():
    reg = _hive("security_under_refcount.hive")
    root = _by_path(reg.root())["Root"].security()
    assert root.declared_reference_count == 1
    assert root.observed_reference_count == 2
    assert root.reference_count_consistent is False
    assert any("usage counter inconsistency" in n for n in root.anomalies)


def test_corrupt_sk_offset_does_not_leak_into_other_keys():
    reg = _hive("security_bad_sk_offset.hive")
    keys = _by_path(reg.root())
    broken = keys["Root"].security()
    healthy = keys["Root\\SharedA"].security()

    # The broken key gets no descriptor and an explicit anomaly.
    assert broken.descriptor is None
    assert broken.sk_cell_offset is None
    assert any("outside the hive buffer" in n for n in broken.anomalies)

    # The healthy sibling keeps its own independent descriptor display.
    assert healthy.descriptor is not None
    assert healthy.sk_cell_offset is not None
    assert healthy.anomalies == [] or all(
        "usage counter" in n for n in healthy.anomalies)


def test_out_of_bounds_ace_is_structural_anomaly():
    reg = _hive("security_ace_overrun.hive")
    root = _by_path(reg.root())["Root"].security()
    assert any("overruns its ACL" in n for n in root.anomalies)
    dacl = root.descriptor.dacl
    # The offending ACE is not trusted; parsing stops at the boundary.
    assert dacl.aces == []
    assert any("overruns its ACL" in n for n in dacl.anomalies)


def test_unknown_ace_type_is_unsupported_not_anomaly():
    reg = _hive("security_unknown_ace.hive")
    root = _by_path(reg.root())["Root"].security()
    dacl = root.descriptor.dacl

    # The unknown ACE is retained with raw bytes and flagged unsupported.
    unknown = dacl.aces[0]
    assert unknown.ace_type == 0x7F
    assert unknown.ace_type_name is None
    assert unknown.is_known_type() is False
    assert len(unknown.raw_bytes) == unknown.size
    assert any("not recognized" in n for n in root.unsupported)
    assert root.anomalies == []

    # The following, known ACE still parses; unknown type does not abort.
    assert dacl.aces[1].ace_type_name == "ACCESS_DENIED"


def test_each_key_gets_fresh_evidence_when_iterating_corrupt_hive():
    reg = _hive("security_bad_sk_offset.hive")
    seen = []
    for key in _all_keys(reg.root()):
        seen.append(key.security())
    # No two evidence objects share identity, and none inherit prior state.
    assert len({id(item) for item in seen}) == len(seen)
    descriptors = [item for item in seen if item.descriptor is not None]
    assert len(descriptors) == 3  # only the three intact sibling keys


# --------------------------------------------------------------------------
# Low level NK / SK accessors
# --------------------------------------------------------------------------

def test_nk_sk_offsets_and_sk_accessors():
    reg = _hive("security_clean.hive")
    nk = reg.root()._nkrecord
    assert isinstance(nk, NKRecord)
    cell_abs = nk.sk_cell_offset()
    assert cell_abs == 0x1000 + nk.sk_offset()
    sk = nk.sk_record()
    assert sk.offset() == cell_abs + 4
    assert sk.reference_count() == 2
    assert sk.descriptor_size() == len(sk.descriptor_bytes())
    assert sk.descriptor_offset() == sk.offset() + 0x14


def test_sk_list_offsets_are_exposed():
    reg = _hive("security_clean.hive")
    sk = reg.root()._nkrecord.sk_record()
    # Standalone fixture SK records are both first and last in the SK list.
    assert sk.prev_sk_offset() in (0xFFFFFFFF,)
    assert sk.next_sk_offset() in (0xFFFFFFFF,)


def test_regf_reports_raw_sk_references():
    reg = _hive("security_clean.hive")
    refs = list(reg._regf.sk_references())
    # Four NK records; two point at the shared cell.
    assert len(refs) == 4
    targets = [target for _nk, target in refs]
    shared = reg.root()._nkrecord.sk_offset()
    assert targets.count(shared) == 2


def test_real_world_hive_still_parses():
    # Guard against regressions on the shipped, real-world hive.
    path = os.path.join(SAMPLE_DIR, "issue22.hive")
    reg = Registry.Registry(path)
    evidence = reg.root().security()
    assert evidence.reference_count_consistent is True
    assert evidence.descriptor.owner is not None
    assert evidence.descriptor.dacl_present is True


# --------------------------------------------------------------------------
# Direct descriptor parsing (in-memory buffers for edge cases)
# --------------------------------------------------------------------------

def _sid_bytes(authority, subs):
    # revision + sub-authority count, then the 6-byte big-endian authority
    # (five leading zero bytes followed by the authority byte for values < 256).
    out = bytes([1, len(subs), 0, 0, 0, 0, 0, authority])
    for sub in subs:
        out += struct.pack("<I", sub)
    return out


def test_object_ace_guid_and_sid_parse():
    sid = _sid_bytes(5, [21, 7, 8])
    guid = bytes(bytearray(range(16)))
    body = struct.pack("<II", 0x1, 0x00020019) + guid + sid
    ace = struct.pack("<BBH", 0x05, 0, 4 + len(body)) + body
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    raw = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 20, 0) + acl

    evidence = SecurityParse.parse_security_descriptor(raw, 0, len(raw))
    assert evidence.anomalies == []
    ace_evidence = evidence.dacl.aces[0]
    assert ace_evidence.ace_type_name == "ACCESS_ALLOWED_OBJECT"
    assert ace_evidence.object_guid is not None
    assert ace_evidence.inherit_object_guid is None
    assert ace_evidence.sid.sid == "S-1-5-21-7-8"


def test_sid_overrun_reported_as_anomaly_not_trusted():
    # Declares nine sub-authorities but provides no room for them.
    sid_header = bytes([1, 9]) + b"\x00" * 6
    bad_ace = (struct.pack("<BBH", 0, 0, 40) +
               struct.pack("<I", 0x1F) + sid_header)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(bad_ace), 1, 0) + bad_ace
    raw = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 20, 0) + acl

    evidence = SecurityParse.parse_security_descriptor(raw, 0, len(raw))
    assert evidence.dacl is not None
    assert any("overruns" in note for note in evidence.anomalies)
    assert evidence.dacl.aces == []


def test_self_relative_bit_absence_is_anomaly():
    # Control 0x0004 (DACL present) without the self-relative bit.
    raw = struct.pack("<BBHIIII", 1, 0, 0x0004, 0, 0, 0, 0)
    evidence = SecurityParse.parse_security_descriptor(raw, 0, len(raw))
    assert any("self-relative" in note for note in evidence.anomalies)
    assert evidence.dacl_present is True
    # Present bit but null DACL pointer must not be reported as empty.
    assert evidence.dacl is None
    assert any("DACL is marked present but could not be parsed" in note
               for note in evidence.anomalies)


def test_present_dacl_with_bad_offset_is_not_empty():
    # DACL present and pointer outside the descriptor bounds.
    raw = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0xFFFF, 0)
    evidence = SecurityParse.parse_security_descriptor(raw, 0, len(raw))
    assert evidence.dacl_present is True
    assert evidence.dacl is None
    assert any("outside the descriptor" in note for note in evidence.anomalies)
