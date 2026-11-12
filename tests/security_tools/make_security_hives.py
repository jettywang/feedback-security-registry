#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build small, deterministic registry hive fixtures used to validate the
security descriptor evidence export.

The generated hives are hand assembled but valid enough for python-registry:
a REGF header, one HBIN and a set of NK / LF / SK cells. Corruption variants
are produced by byte-patching a clean hive, so the tests exercise exactly the
malformed conditions described in their names.

This is a test helper, not part of the library; it intentionally supports only
the narrow structures the security tests need.
"""
from __future__ import print_function

import os
import struct

FIRST_HBIN = 0x1000
HBIN_SIZE = 0x1000
HIVE_SIZE = FIRST_HBIN + HBIN_SIZE


def _cell(payload):
    """Wrap a record payload in an HBIN cell (negative size = in use)."""
    size = len(payload) + 4
    return struct.pack(str("<i"), -size) + payload


def _free(size):
    return struct.pack(str("<i"), size) + b"\x00" * (size - 4)


def _sid(rev, authority, subs):
    out = struct.pack(str("<BB"), rev, len(subs))
    # 6-byte big-endian identifier authority, zero-padded on the left.
    authority_bytes = struct.pack(str(">Q"), authority)[2:8]
    out += authority_bytes
    for sub in subs:
        out += struct.pack(str("<I"), sub)
    return out


# Well-known SIDs used by the fixtures.
SID_SYSTEM = _sid(1, 5, (21, 1, 2, 3, 500))          # S-1-5-21-1-2-3-500
SID_ADMINS = _sid(1, 5, (21, 1, 2, 3, 512))          # S-1-5-21-1-2-3-512
SID_USERS = _sid(1, 5, (32, 545))                    # S-1-5-32-545


def _ace(ace_type, flags, mask, sid):
    body = struct.pack(str("<I"), mask) + sid
    size = 4 + len(body)
    return struct.pack(str("<BBH"), ace_type, flags, size) + body


def _object_ace(ace_type, flags, mask, sid, object_guid=None,
                inherit_guid=None):
    object_flags = 0
    guids = b""
    if object_guid is not None:
        object_flags |= 0x1
        guids += object_guid
    if inherit_guid is not None:
        object_flags |= 0x2
        guids += inherit_guid
    body = struct.pack(str("<II"), object_flags, mask) + guids + sid
    size = 4 + len(body)
    return struct.pack(str("<BBH"), ace_type, flags, size) + body


def _acl(aces, revision=2):
    payload = struct.pack(str("<BBHHH"), revision, 0, 0, len(aces), 0)
    payload += b"".join(aces)
    size = len(payload)
    payload = struct.pack(str("<BBHHH"), revision, 0, size, len(aces), 0)
    payload += b"".join(aces)
    return payload


def _security_descriptor(control, owner, group, dacl=None, sacl=None):
    """Build a self-relative security descriptor from prebuilt ACLs/SIDs."""
    header_len = 0x14
    parts = []
    cursor = header_len

    owner_off = cursor
    cursor += len(owner)
    parts.append(("owner", owner_off, owner))

    group_off = cursor
    cursor += len(group)
    parts.append(("group", group_off, group))

    dacl_off = 0
    if dacl is not None:
        dacl_off = cursor
        cursor += len(dacl)
    sacl_off = 0
    if sacl is not None:
        sacl_off = cursor
        cursor += len(sacl)

    header = struct.pack(str("<BBHIIII"), 1, 0, control,
                         owner_off, group_off, dacl_off, sacl_off)
    blob = header
    for _name, _off, data in parts:
        blob += data
    if dacl is not None:
        blob += dacl
    if sacl is not None:
        blob += sacl
    return blob


def _sk_record(descriptor, ref_count, prev_rel=0xFFFFFFFF, next_rel=0xFFFFFFFF):
    header = b"sk" + b"\x00\x00"
    header += struct.pack(str("<III"), prev_rel, next_rel, ref_count)
    header += struct.pack(str("<I"), len(descriptor))
    return header + descriptor


def _nk_record(name, parent_rel, sk_rel):
    name_bytes = name.encode("utf-16le")
    nk = bytearray(0x4C + len(name_bytes))
    nk[0:2] = b"nk"
    # flags 0x00: UTF-16LE name, non-root (root sets 0x04 separately)
    struct.pack_into(str("<Q"), nk, 0x4, 0)           # timestamp
    struct.pack_into(str("<I"), nk, 0x10, parent_rel)
    struct.pack_into(str("<I"), nk, 0x14, 0)          # subkey count (patched)
    struct.pack_into(str("<I"), nk, 0x18, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x1C, 0xFFFFFFFF)  # subkey list (patched)
    struct.pack_into(str("<I"), nk, 0x20, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x24, 0xFFFFFFFF)  # value count
    struct.pack_into(str("<I"), nk, 0x28, 0xFFFFFFFF)  # value list
    struct.pack_into(str("<I"), nk, 0x2C, sk_rel)
    struct.pack_into(str("<I"), nk, 0x30, 0xFFFFFFFF)  # class name
    struct.pack_into(str("<I"), nk, 0x34, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x38, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x3C, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x40, 0xFFFFFFFF)
    struct.pack_into(str("<I"), nk, 0x44, 0)
    # python-registry interprets the NK name length as the number of bytes
    # read at offset 0x4C, so store the UTF-16 byte count.
    struct.pack_into(str("<H"), nk, 0x48, len(name_bytes))
    # 0x4A class length stays zero
    nk[0x4C:0x4C + len(name_bytes)] = name_bytes
    return bytes(nk)


def _lf_record(child_rels):
    lf = b"lf" + struct.pack(str("<H"), len(child_rels))
    for rel in child_rels:
        lf += struct.pack(str("<II"), rel, 0)  # 4-byte offset, then name hash
    return lf


def _regf_header():
    header = bytearray(FIRST_HBIN)
    header[0:4] = b"regf"
    struct.pack_into(str("<I"), header, 0x4, 1)      # sequence1
    struct.pack_into(str("<I"), header, 0x8, 1)      # sequence2
    struct.pack_into(str("<Q"), header, 0xC, 0)      # timestamp
    struct.pack_into(str("<I"), header, 0x14, 1)     # major
    struct.pack_into(str("<I"), header, 0x18, 3)     # minor
    struct.pack_into(str("<I"), header, 0x1C, 0)     # file type primary
    struct.pack_into(str("<I"), header, 0x20, 0x20)  # first hbin rel
    struct.pack_into(str("<I"), header, 0x24, 0x20)  # root NK cell rel
    struct.pack_into(str("<I"), header, 0x28, HBIN_SIZE)
    name = b"\\Device\\HarddiskVolume\\fixture\x00"
    header[0x30:0x30 + len(name)] = name
    checksum = 0
    for idx in range(0, 0x200, 4):
        checksum ^= struct.unpack_from(str("<I"), bytes(header), idx)[0]
    if checksum == 0:
        checksum = 1
    elif checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    struct.pack_into(str("<I"), header, 0x1FC, checksum)
    return bytes(header)


def _hbin(cells_blob):
    hbin = bytearray(HBIN_SIZE)
    hbin[0:4] = b"hbin"
    struct.pack_into(str("<I"), hbin, 0x4, 0)          # offset from first hbin
    struct.pack_into(str("<I"), hbin, 0x8, HBIN_SIZE)  # relative next
    struct.pack_into(str("<Q"), hbin, 0xC, 0)
    used = 0x20 + len(cells_blob)
    free_size = HBIN_SIZE - used
    if free_size < 4:
        raise RuntimeError("fixture HBIN overflow")
    hbin[0x20:0x20 + len(cells_blob)] = cells_blob
    hbin[used:used + free_size] = _free(free_size)
    return bytes(hbin)


def build_clean_hive():
    """
    Layout (cell offsets relative to first HBIN):
      root NK, LF list, three SK cells, then three child NKs.

    Security design:
      - root + SharedA child share one SK (shared descriptor, ref count 2).
      - EmptyDacl child points at an SK whose DACL is present but empty.
      - MissingDacl child points at an SK with no DACL control bit at all.
    """
    # Descriptor A: populated DACL + SACL, referenced by two keys.
    dacl_a = _acl([
        _ace(0x00, 0x00, 0x000F001F, SID_ADMINS),       # allow all, admins
        _ace(0x01, 0x00, 0x00020019, SID_USERS),        # deny read, users
    ])
    sacl_a = _acl([
        _ace(0x02, 0x60, 0x00020019, SID_SYSTEM),       # audit success/fail
    ])
    sd_a = _security_descriptor(
        0x8000 | 0x0004 | 0x0010 | 0x0400 | 0x0800,
        SID_SYSTEM, SID_ADMINS, dacl_a, sacl_a)

    # Descriptor B: DACL present but empty (explicitly grants nothing).
    sd_b = _security_descriptor(
        0x8000 | 0x0004 | 0x0400,
        SID_SYSTEM, SID_SYSTEM, _acl([]), None)

    # Descriptor C: DACL missing entirely (control bit clear, null pointer).
    sd_c = _security_descriptor(
        0x8000 | 0x0400,
        SID_SYSTEM, SID_SYSTEM, None, None)

    child_names = ["SharedA", "EmptyDacl", "MissingDacl"]
    descriptors = [sd_a, sd_b, sd_c]
    ref_counts = [2, 1, 1]
    sk_records = [_sk_record(sd, count)
                  for sd, count in zip(descriptors, ref_counts)]
    child_records = [_nk_record(name, 0, 0) for name in child_names]
    root_record = _nk_record("Root", 0x20, 0)
    lf_record = _lf_record([0, 0, 0])

    # First pass: assign cell offsets from full cell sizes.
    layout = []
    cursor = 0x20
    root_rel = cursor
    layout.append(("root", root_rel, len(_cell(root_record))))
    cursor += len(_cell(root_record))
    lf_rel = cursor
    layout.append(("lf", lf_rel, len(_cell(lf_record))))
    cursor += len(_cell(lf_record))

    sk_rels = []
    for index, sk in enumerate(sk_records):
        sk_rels.append(cursor)
        layout.append(("sk%d" % index, cursor, len(_cell(sk))))
        cursor += len(_cell(sk))

    child_rels = []
    for index, child in enumerate(child_records):
        child_rels.append(cursor)
        layout.append(("child%d" % index, cursor, len(_cell(child))))
        cursor += len(_cell(child))

    # Second pass: fill internal pointers now that offsets are known.
    shared_sk_rel, empty_sk_rel, missing_sk_rel = sk_rels
    root = bytearray(root_record)
    struct.pack_into(str("<H"), root, 0x2, 0x04)          # root key flag
    struct.pack_into(str("<I"), root, 0x10, root_rel)     # parent -> self
    struct.pack_into(str("<I"), root, 0x14, 3)            # subkey count
    struct.pack_into(str("<I"), root, 0x1C, lf_rel)       # subkey list
    struct.pack_into(str("<I"), root, 0x2C, shared_sk_rel)
    root_record = bytes(root)

    lf_record = _lf_record(child_rels)

    built_children = []
    for index, name in enumerate(child_names):
        child = bytearray(_nk_record(name, root_rel, sk_rels[index]))
        built_children.append(bytes(child))

    blob = b""
    blob += _cell(root_record)
    blob += _cell(lf_record)
    for sk in sk_records:
        blob += _cell(sk)
    for child in built_children:
        blob += _cell(child)

    meta = {
        "root": root_rel,
        "lf": lf_rel,
        "children": dict(zip(child_names, child_rels)),
        "sk": {
            "shared": shared_sk_rel,
            "empty": empty_sk_rel,
            "missing": missing_sk_rel,
        },
        "descriptors": {"shared": sd_a, "empty": sd_b, "missing": sd_c},
    }
    return _regf_header() + _hbin(blob), meta


def write_hive(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def build_all(out_dir):
    clean, meta = build_clean_hive()
    write_hive(os.path.join(out_dir, "security_clean.hive"), clean)

    # Variant 1: refcount mismatch on the shared SK (declared 2 -> 9).
    bad_ref = bytearray(clean)
    sk_data = FIRST_HBIN + meta["sk"]["shared"] + 4
    struct.pack_into(str("<I"), bad_ref, sk_data + 0xC, 9)
    write_hive(os.path.join(out_dir, "security_bad_refcount.hive"),
               bytes(bad_ref))

    # Variant 2: root NK points at an out-of-range SK offset.
    bad_ptr = bytearray(clean)
    root_data = FIRST_HBIN + meta["root"] + 4
    struct.pack_into(str("<I"), bad_ptr, root_data + 0x2C, 0x0FFFFF00)
    write_hive(os.path.join(out_dir, "security_bad_sk_offset.hive"),
               bytes(bad_ptr))

    # Variant 3: an ACE in the shared DACL declares an overrun size.
    bad_ace = bytearray(clean)
    sd = meta["descriptors"]["shared"]
    # DACL begins after the 20-byte SD header, owner SID and group SID.
    dacl_rel = struct.unpack_from(str("<I"), sd, 12)[0]
    ace_rel = dacl_rel + 8  # first ACE immediately after ACL header
    sk_cell = FIRST_HBIN + meta["sk"]["shared"] + 4
    ace_abs = sk_cell + 0x14 + ace_rel
    struct.pack_into(str("<H"), bad_ace, ace_abs + 2, 0x7FFF)
    write_hive(os.path.join(out_dir, "security_ace_overrun.hive"),
               bytes(bad_ace))

    # Variant 4: unknown ACE type (0x7F) inside an otherwise valid DACL.
    unknown = bytearray(clean)
    struct.pack_into(str("<B"), unknown, ace_abs, 0x7F)
    write_hive(os.path.join(out_dir, "security_unknown_ace.hive"),
               bytes(unknown))

    # Variant 5: shared SK counter says 1 while two NKs still reference it.
    under_ref = bytearray(clean)
    struct.pack_into(str("<I"), under_ref, sk_data + 0xC, 1)
    write_hive(os.path.join(out_dir, "security_under_refcount.hive"),
               bytes(under_ref))


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "reg_samples")
    target = os.path.abspath(target)
    if not os.path.isdir(target):
        os.makedirs(target)
    build_all(target)
    print("wrote security fixtures to", target)
