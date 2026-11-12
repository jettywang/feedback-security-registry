"""
A minimal, deterministic Windows Registry hive writer used only by the diff
tests.  It produces byte streams that python-registry can parse, and lets a
test pin exact cell offsets so cell reuse and relocation can be engineered.

It deliberately supports just the subset the diff interface relies on:
NK cells, lh subkey lists, value lists, VK cells and inline/external data
cells.  It is not a general purpose hive writer.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

REG_NONE = 0x0
REG_SZ = 0x1
REG_EXPAND_SZ = 0x2
REG_BINARY = 0x3
REG_DWORD = 0x4
REG_MULTI_SZ = 0x7
REG_QWORD = 0xB

FIRST_HBIN = 0x1000


def _align8(data: bytes) -> bytes:
    pad = (-len(data)) % 8
    return data + (b"\x00" * pad)


@dataclass
class SValue:
    name: str
    type: int
    data: bytes
    default: bool = False
    ascii_name: bool = False
    force_external: bool = False


@dataclass
class SKey:
    name: str
    subkeys: List["SKey"] = field(default_factory=list)
    values: List[SValue] = field(default_factory=list)
    ascii_name: bool = False
    # Optional fixed relative offset (from first HBIN start) of this key's NK
    # *cell*.  When set, the builder reserves that slot before allocating the
    # rest; collisions raise.
    fixed_cell_rel: Optional[int] = None


def _encode_name(name: str, ascii_name: bool) -> Tuple[bytes, int]:
    if ascii_name:
        return name.encode("windows-1252"), 0x20
    return name.encode("utf-16le"), 0x0


def _cell(payload: bytes) -> bytes:
    # On-disk size is negative for allocated cells and includes the size field.
    total = len(payload) + 4
    total += (-total) % 8
    return struct.pack("<i", -total) + payload + (b"\x00" * (total - 4 - len(payload)))


class SyntheticHiveBuilder:
    """
    Allocate every cell in a single HBIN at deterministic relative offsets.
    Allocation order: fixed NK cells first, then everything else depth-first.
    """

    def __init__(self, root: SKey, hive_name: str = "test"):
        self._root = root
        self._hive_name = hive_name
        # Keys are HBIN-relative offsets of cell headers (the first cell sits
        # at 0x20, immediately after the HBIN header).  These are exactly the
        # values python-registry's abs_offset_from_hbin_offset() consumes, so
        # every pointer field stores a slot verbatim and _assemble places a
        # cell at byte `slot` within the HBIN.  One offset convention only.
        self._cells: Dict[int, bytes] = {}
        self._next_slot = 0x20
        self._nk_rel: Dict[int, int] = {}   # id(key) -> cell header offset
        self._fixed_slots: Dict[int, int] = {}  # id(key) -> engineered slot

    def _hbinref(self, slot: int) -> int:
        return slot

    def _all_keys(self, key: SKey) -> List[SKey]:
        out = [key]
        for child in key.subkeys:
            out.extend(self._all_keys(child))
        return out

    def build(self) -> bytes:
        all_keys = self._all_keys(self._root)

        # Engineering pass: every cell is allocated naturally first so all
        # cross references resolve.  Fixed-offset keys are then relocated to
        # their engineered slots and every pointer that names them is
        # rewritten, which keeps fixed cells independent of natural layout.
        fixed = {id(k): k.fixed_cell_rel for k in all_keys
                 if k.fixed_cell_rel is not None}
        # fixed_cell_rel is already an HBIN-relative cell header offset.
        self._fixed_slots = dict(fixed)

        vlist_rels: Dict[int, int] = {}
        sklist_rels: Dict[int, int] = {}
        for key in all_keys:
            self._place_nk(key, vlist_rels, sklist_rels)

        # Pass 2: data cells and VK cells plus each key's value list.
        vk_rels: Dict[Tuple[int, int], int] = {}
        for key in all_keys:
            key_id = id(key)
            for index, value in enumerate(key.values):
                data_rel = self._place_data(value)
                vk_rel = self._place_vk(value, data_rel)
                vk_rels[(key_id, index)] = vk_rel
            if key.values:
                # ValuesList feeds each entry to HBINCell, so name the VK
                # cell header rather than the cell data.
                payload = b"".join(
                    struct.pack("<I", self._hbinref(vk_rels[(key_id, i)]))
                    for i in range(len(key.values))
                )
                vlist_rels[key_id] = self._hbinref(self._allocate(_cell(payload)))

        # Pass 3: lh subkey lists (all child NK offsets are known by now).
        for key in all_keys:
            if key.subkeys:
                count = len(key.subkeys)
                # lh header is exactly four bytes: 2-byte id "lh" plus a
                # 2-byte count; entries begin at data offset 0x4.
                payload = b"lh" + struct.pack("<H", count)
                for child in key.subkeys:
                    # DirectSubkeyList feeds the entry straight to HBINCell,
                    # so it must name the child's cell header.
                    payload += struct.pack("<I", self._nk_rel[id(child)]) + b"\x00\x00\x00\x00"
                sklist_rels[id(key)] = self._hbinref(self._allocate(_cell(payload)))

        # Pass 4: rewrite the NK cells now that list offsets are known.
        for key in all_keys:
            self._place_nk(key, vlist_rels, sklist_rels)

        # Pass 5: relocate fixed-offset NK cells to their engineered slots
        # and rewrite every pointer that refers to them (parent pointers,
        # lh entries and the REGF root pointer), preserving a valid hive.
        self._relocate_fixed(all_keys)

        return self._assemble()

    def _relocate_fixed(self, all_keys: List[SKey]) -> None:
        if not self._fixed_slots:
            return

        old_refs = {key_id: self._nk_rel[key_id] for key_id in self._fixed_slots}
        for key_id, slot in self._fixed_slots.items():
            old_ref = old_refs[key_id]
            cell = self._cells.pop(old_ref)
            if slot in self._cells:
                raise ValueError("fixed cell slot 0x%x collides with another cell"
                                 % slot)
            self._cells[slot] = cell
            self._nk_rel[key_id] = slot

        ref_map = {old_refs[k]: self._nk_rel[k] for k in self._fixed_slots}

        # Rewrite only genuine pointer fields: NK parent (0x10) and lh
        # entries (every 8 bytes from data offset 0x4).  Patching by field
        # position avoids corrupting unrelated bytes that happen to match.
        for slot, cell in list(self._cells.items()):
            signature = cell[4:6]
            mutable = bytearray(cell)
            if signature == b"nk":
                parent_pos = 4 + 0x10
                value = struct.unpack_from("<I", mutable, parent_pos)[0]
                if value in ref_map:
                    struct.pack_into("<I", mutable, parent_pos, ref_map[value])
            elif signature == b"lh":
                count = struct.unpack_from("<H", mutable, 6)[0]
                for index in range(count):
                    # Cell layout: 4-byte size, 4-byte lh header, then
                    # 8-byte entries, so the first entry sits at cell byte 8.
                    entry_pos = 8 + index * 8
                    value = struct.unpack_from("<I", mutable, entry_pos)[0]
                    if value in ref_map:
                        struct.pack_into("<I", mutable, entry_pos, ref_map[value])
            self._cells[slot] = bytes(mutable)

    def _allocate(self, cell: bytes) -> int:
        slot = self._next_slot
        while slot in self._cells:
            slot += 8
        self._cells[slot] = cell
        self._next_slot = slot + len(cell)
        return slot

    def _place_data(self, value: SValue) -> int:
        payload = value.data
        if not value.force_external and len(payload) < 5:
            # Stored inline inside the VK data-offset field; no data cell.
            return -1
        return self._allocate(_cell(payload))

    def _place_vk(self, value: SValue, data_rel: int) -> int:
        name_raw, name_flag_bit = _encode_name(value.name, value.ascii_name)
        name_len = 0 if value.default else len(name_raw)
        flags = name_flag_bit
        raw_len = len(value.data)
        inline = data_rel == -1
        if inline:
            length_field = raw_len | 0x80000000
            data_field = value.data.ljust(4, b"\x00")[:4]
        else:
            length_field = raw_len
            # The VK data offset names the data cell header; the parser adds
            # the 4-byte cell size itself when reading cell contents.
            data_field = struct.pack("<I", self._hbinref(data_rel))
        payload = b"vk"
        payload += struct.pack("<H", name_len)
        payload += struct.pack("<I", length_field)
        payload += data_field
        payload += struct.pack("<I", value.type)
        payload += struct.pack("<H", flags)
        payload += b"\x00\x00"
        payload += name_raw
        return self._allocate(_cell(payload))

    def _place_nk(self, key: SKey,
                  vlist_rels: Dict[int, int],
                  sklist_rels: Dict[int, int]) -> int:
        name_raw, name_flag = _encode_name(key.name, key.ascii_name)
        flags = name_flag
        if key is self._root:
            flags |= 0x4

        parent = self._parent_of(key)
        # Every cross-cell pointer the parser hands to HBINCell (parent,
        # subkey list, value list and data cells) names a cell header.
        parent_rel = self._nk_rel[id(parent)] if parent is not None else 0
        sub_count = len(key.subkeys)
        vlist_rel = vlist_rels.get(id(key), 0xFFFFFFFF)
        vcount = len(key.values)
        sklist_rel = sklist_rels.get(id(key), 0xFFFFFFFF)

        payload = self._nk_header(flags, parent_rel, sub_count, sklist_rel,
                                  vcount, vlist_rel)
        struct.pack_into("<H", payload, 0x48, len(name_raw))
        payload += name_raw
        cell = _cell(bytes(payload))
        if id(key) in self._nk_rel:
            slot = self._nk_rel[id(key)]
            self._cells[slot] = cell
        else:
            slot = self._allocate(cell)
            self._nk_rel[id(key)] = slot
        return self._nk_rel[id(key)]

    def _nk_header(self, flags: int, parent_rel: int, sub_count: int,
                   sklist_rel: int, vcount: int, vlist_rel: int) -> bytearray:
        h = bytearray(0x4C)
        struct.pack_into("<H", h, 0x00, 0x6B6E)       # "nk"
        struct.pack_into("<H", h, 0x02, flags)
        struct.pack_into("<Q", h, 0x04, 0)            # last write timestamp
        struct.pack_into("<I", h, 0x0C, 0)            # access bits
        struct.pack_into("<I", h, 0x10, parent_rel)
        struct.pack_into("<I", h, 0x14, sub_count)
        struct.pack_into("<I", h, 0x18, sub_count)
        struct.pack_into("<I", h, 0x1C, sklist_rel)
        struct.pack_into("<I", h, 0x20, 0xFFFFFFFF)   # volatile subkey list
        struct.pack_into("<I", h, 0x24, vcount)
        struct.pack_into("<I", h, 0x28, vlist_rel)
        struct.pack_into("<I", h, 0x2C, 0)            # SK record offset
        struct.pack_into("<I", h, 0x30, 0xFFFFFFFF)   # class name offset
        struct.pack_into("<I", h, 0x34, 0xFFFFFFFF)
        struct.pack_into("<I", h, 0x38, 0xFFFFFFFF)
        struct.pack_into("<I", h, 0x3C, 0xFFFFFFFF)
        struct.pack_into("<I", h, 0x40, 0xFFFFFFFF)
        struct.pack_into("<I", h, 0x44, 0)
        struct.pack_into("<H", h, 0x48, 0)            # name length patched later
        struct.pack_into("<H", h, 0x4A, 0)            # class name length
        return h

    def _parent_of(self, target: SKey) -> Optional[SKey]:
        def find(key: SKey) -> Optional[SKey]:
            for child in key.subkeys:
                if child is target:
                    return key
                found = find(child)
                if found is not None:
                    return found
            return None
        return find(self._root)

    def _assemble(self) -> bytes:
        end_slot = max(slot + len(cell) for slot, cell in self._cells.items())
        total_size = end_slot
        total_size += (-total_size) % 0x1000

        hbin = bytearray(total_size)
        struct.pack_into("<I", hbin, 0x00, 0x6E696268)  # "hbin"
        struct.pack_into("<I", hbin, 0x04, 0)           # relative to first hbin
        struct.pack_into("<Q", hbin, 0x08, total_size)
        struct.pack_into("<Q", hbin, 0x10, 0)
        # Slots start at 0x20 and index directly into the HBIN buffer (whose
        # first 0x20 bytes are the HBIN header).
        for slot, cell in sorted(self._cells.items()):
            hbin[slot:slot + len(cell)] = cell

        header = bytearray(0x1000)
        struct.pack_into("<I", header, 0x00, 0x66676572)  # "regf"
        struct.pack_into("<I", header, 0x04, 1)           # sequence 1
        struct.pack_into("<I", header, 0x08, 1)           # sequence 2
        struct.pack_into("<Q", header, 0x0C, 0)           # modification date
        struct.pack_into("<I", header, 0x14, 1)           # major
        struct.pack_into("<I", header, 0x18, 3)           # minor
        struct.pack_into("<I", header, 0x1C, 0)           # file type primary
        struct.pack_into("<I", header, 0x20, 1)           # format
        struct.pack_into("<I", header, 0x28, total_size)  # hbins size
        # REGF 0x24 names the root cell *header* as an HBIN-relative offset,
        # which is exactly the nk_rel value (body slot 0 + 0x20 header).
        # Internal NK/lh/VK pointers name cell data and keep the +4 there.
        struct.pack_into("<I", header, 0x24, self._nk_rel[id(self._root)])
        name = self._hive_name.encode("utf-16le")
        header[0x30:0x30 + len(name)] = name
        checksum = 0
        for off in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", header, off)[0]
        if checksum == 0:
            checksum = 1
        struct.pack_into("<I", header, 0x1FC, checksum)

        return bytes(header) + bytes(hbin)
