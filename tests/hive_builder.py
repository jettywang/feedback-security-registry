#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Minimal, in-memory Windows registry hive builder.

The bounded traversal has to be proven against structures that no healthy
registry ever contains (cycles, free cells, out of bounds references), so
the tests construct hives cell by cell instead of relying on Windows.

Only the structures exercised by the key/value traversal are emitted:
REGF header, one HBIN, NK/VK cells and lf/lh/li/ri subkey index cells.
All cell offsets in the records are relative to the start of the first
HBIN, exactly as the on-disk format requires.
"""
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import struct

HBIN_OFFSET = 0x1000
HBIN_PAYLOAD = 0x2000
CELL_DATA_START = HBIN_OFFSET + 0x20

NK_FLAG_ASCII_NAME = 0x0020
NK_FLAG_ROOT = 0x0004


def _align8(value):
    remainder = value % 8
    return value if remainder == 0 else value + (8 - remainder)


class HiveBuilder(object):
    def __init__(self, hive_name=u"\\??\\C:\\Users\\tester\\ntuser.dat"):
        self._hive_name = hive_name
        self._blob = bytearray(b"\x00" * (HBIN_OFFSET + HBIN_PAYLOAD))
        self._cursor = CELL_DATA_START
        self.cells = {}

    # ------------------------------------------------------------------ #
    # low level cell allocation
    # ------------------------------------------------------------------ #
    def _align_cursor(self):
        relative = self._cursor - HBIN_OFFSET
        aligned = _align8(relative)
        self._cursor = HBIN_OFFSET + aligned

    def relative(self, absolute_offset):
        if absolute_offset is None:
            return 0xFFFFFFFF
        return absolute_offset - HBIN_OFFSET

    def _write_cell(self, signature, data):
        self._align_cursor()
        cell_offset = self._cursor
        payload = signature + data
        size = _align8(len(payload) + 4)
        struct.pack_into("<i", self._blob, cell_offset, -size)
        self._blob[cell_offset + 4:cell_offset + 4 + len(payload)] = payload
        self._cursor = cell_offset + size
        self.cells[cell_offset] = size
        return cell_offset

    def patch_dword(self, absolute_offset, value):
        """Overwrite four bytes (used to corrupt otherwise valid hives)."""
        struct.pack_into("<I", self._blob, absolute_offset, value & 0xFFFFFFFF)

    def patch_signed_dword(self, absolute_offset, value):
        struct.pack_into("<i", self._blob, absolute_offset, value)

    # NK record field offsets (relative to the "nk" data start).
    NK_PARENT = 0x10
    NK_SUBKEY_COUNT = 0x14
    NK_SUBKEY_LIST = 0x1C
    NK_VALUES_COUNT = 0x24
    NK_VALUES_LIST = 0x28

    def patch_nk_field(self, nk_cell, field, value):
        """Overwrite a dword field inside an NK cell."""
        self.patch_dword(nk_cell + 4 + field, value)

    def mark_free(self, cell_offset):
        """Flip the allocated (negative) cell size to a free (positive) size."""
        size = struct.unpack_from("<i", self._blob, cell_offset)[0]
        struct.pack_into("<i", self._blob, cell_offset, abs(size))
    # ------------------------------------------------------------------ #
    # records
    # ------------------------------------------------------------------ #
    def add_nk(self, name, parent_cell, subkey_count=0, subkey_list_rel=0xFFFFFFFF,
               values_count=0, values_list_rel=0xFFFFFFFF, root=False,
               ascii_name=False):
        if ascii_name:
            encoded = name.encode("windows-1252")
        else:
            encoded = name.encode("utf-16le")
        flags = NK_FLAG_ASCII_NAME if ascii_name else 0
        if root:
            flags |= NK_FLAG_ROOT

        data = bytearray(0x4C + len(encoded))
        struct.pack_into("<H", data, 0x0, flags)
        struct.pack_into("<Q", data, 0x2, 0)            # timestamp
        parent_rel = 0xFFFFFFFF if root or parent_cell is None \
            else self.relative(parent_cell)
        struct.pack_into("<I", data, 0xE, parent_rel)
        struct.pack_into("<I", data, 0x12, subkey_count)
        struct.pack_into("<I", data, 0x16, 0)           # volatile subkey count
        struct.pack_into("<I", data, 0x1A, subkey_list_rel)
        struct.pack_into("<I", data, 0x1E, 0)           # volatile subkey list
        struct.pack_into("<I", data, 0x22, values_count)
        struct.pack_into("<I", data, 0x26, values_list_rel)
        struct.pack_into("<I", data, 0x2A, 0xFFFFFFFF)  # security key
        struct.pack_into("<H", data, 0x46, len(encoded))
        struct.pack_into("<%ds" % len(encoded), data, 0x4A, encoded)
        return self._write_cell(b"nk", bytes(data))

    def add_index(self, signature, entries):
        """
        Add an lf/lh/li/ri cell.

        `entries` is the list of hbin-relative target offsets.  lf/lh
        entries carry a four byte hash, li/ri entries are plain offsets.
        """
        if signature in ("lf", "lh"):
            stride = 8
        elif signature in ("li", "ri"):
            stride = 4
        else:
            raise ValueError("unsupported index signature %s" % signature)

        data = bytearray(2 + stride * len(entries))
        struct.pack_into("<H", data, 0x0, len(entries))
        for index, target_rel in enumerate(entries):
            position = 2 + index * stride
            struct.pack_into("<I", data, position, target_rel)
            if stride == 8:
                struct.pack_into("<I", data, position + 4, 0)  # name hash
        return self._write_cell(signature.encode("ascii"), bytes(data))

    def add_vk(self, name, data_type, raw_data, ascii_name=False):
        if name:
            encoded = name.encode("windows-1252") if ascii_name \
                else name.encode("utf-16le")
        else:
            encoded = b""

        data_cell = self._write_cell(b"", raw_data)
        data = bytearray(0x12 + len(encoded))
        struct.pack_into("<H", data, 0x0, len(encoded))
        struct.pack_into("<I", data, 0x2, len(raw_data))
        struct.pack_into("<I", data, 0x6, self.relative(data_cell))
        struct.pack_into("<I", data, 0xA, data_type)
        struct.pack_into("<H", data, 0xE, 1 if ascii_name else 0)
        struct.pack_into("<%ds" % len(encoded), data, 0x12, encoded)
        return self._write_cell(b"vk", bytes(data))

    def add_values_list(self, vk_cell_offsets):
        data = bytearray()
        for offset in vk_cell_offsets:
            data += struct.pack("<I", self.relative(offset))
        return self._write_cell(b"", bytes(data))

    # ------------------------------------------------------------------ #
    # finalization
    # ------------------------------------------------------------------ #
    def build(self, root_cell):
        # REGF header (first 0x200 bytes of a 0x1000 byte block).
        struct.pack_into("<I", self._blob, 0x0, 0x66676572)   # "regf"
        struct.pack_into("<I", self._blob, 0x4, 1)             # sequence 1
        struct.pack_into("<I", self._blob, 0x8, 1)             # sequence 2
        struct.pack_into("<Q", self._blob, 0xC, 0)             # timestamp
        struct.pack_into("<I", self._blob, 0x14, 1)            # major
        struct.pack_into("<I", self._blob, 0x18, 3)            # minor
        struct.pack_into("<I", self._blob, 0x1C, 0)            # primary file
        struct.pack_into("<I", self._blob, 0x20, 1)            # format
        struct.pack_into("<I", self._blob, 0x24,
                         self.relative(root_cell))             # first key
        struct.pack_into("<I", self._blob, 0x28, HBIN_PAYLOAD) # hbins size
        struct.pack_into("<I", self._blob, 0x2C, 1)            # clustering
        name_encoded = self._hive_name.encode("utf-16le")
        self._blob[0x30:0x30 + len(name_encoded)] = name_encoded

        # HBIN block.
        struct.pack_into("<I", self._blob, HBIN_OFFSET, 0x6E696268)  # "hbin"
        struct.pack_into("<I", self._blob, HBIN_OFFSET + 0x4, 0)     # rel first
        struct.pack_into("<I", self._blob, HBIN_OFFSET + 0x8,
                         HBIN_PAYLOAD)                                # next offset
        struct.pack_into("<Q", self._blob, HBIN_OFFSET + 0xC, 0)     # timestamp

        # REGF checksum: XOR of every dword in the first 0x200 bytes.
        checksum = 0
        for offset in range(0, 0x200, 4):
            checksum ^= struct.unpack_from("<I", self._blob, offset)[0]
        struct.pack_into("<I", self._blob, 0x1FC, checksum)
        return bytes(self._blob)
