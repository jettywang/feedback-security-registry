#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Forensic integrity regression tests for value data reading.

These tests exercise the three storage shapes a VK value can take:

  1. inline data embedded directly in the VK record (declared length < 5,
     or the high bit of the data length field),
  2. a single external data cell (5 <= length <= 0x3fd8), and
  3. a large value: a DB record plus a DBIndirect block whose segments are
     0x3fd8 byte data cells (length > 0x3fd8).

Expected bytes are never taken from the reader under test. A small synthetic
hive builder lays out explicit cells, and every fragment is independently
described by its absolute offset and the contribution it is expected to make.
The repository's real large-value sample (ProductPolicy, 23712 bytes over two
segments) is also re-checked fragment by fragment. No system registry hive is
touched.
"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
import io
import os
import struct
import unittest
from collections import namedtuple

from Registry import Registry
from Registry.RegistryParse import (
    HBINCell,
    DBIndirectBlock,
    LargeDataParseException,
    RegBin,
    RegDWord,
    RegSZ,
)

REGF_SIGNATURE = 0x66676572
HBIN_SIGNATURE = 0x6E696268
REGF_HEADER_SIZE = 0x1000
HBIN_HEADER_SIZE = 0x20
CELL_HEADER_SIZE = 0x4
MAX_SEGMENT_DATA_SIZE = 0x3fd8
# Distinctive, non-zero fills. Slack must never be mistaken for value data,
# and a neighbour cell must be recognisable if the reader borrows its bytes.
SLACK_FILL = b"\xef"
NEIGHBOUR_FILL = b"\x5a"

# Independently describes what one laid-out fragment must contribute.
FragmentSpec = namedtuple(
    "FragmentSpec",
    ["name", "cell_offset", "data_offset", "expected"],
)


def pattern_byte(index):
    """Deterministic pseudo-random byte, independent of the registry reader."""
    return (index * 1103515245 + 12345 + (index >> 3) * 7919) & 0xFF


def pattern_bytes(length, seed=0):
    return bytes(bytearray(pattern_byte(seed + i) for i in range(length)))


def align8(size):
    return (size + 7) & ~7


class SyntheticHive(object):
    """
    Builds a minimal primary hive containing one root key and an arbitrary
    number of values. The HBIN region is pre-filled with SLACK_FILL so any
    read past an explicit cell boundary is visible in the output.
    """

    def __init__(self, hbin_size=0x20000):
        self._hbin_size = hbin_size
        self._cells = bytearray()
        self._value_layouts = []

    def _add_cell(self, payload):
        cell_size = align8(CELL_HEADER_SIZE + len(payload))
        cell_offset = REGF_HEADER_SIZE + HBIN_HEADER_SIZE + len(self._cells)
        self._cells += struct.pack(str("<i"), -cell_size)
        self._cells += payload
        self._cells += SLACK_FILL * (cell_size - CELL_HEADER_SIZE - len(payload))
        return cell_offset, cell_size

    def add_sentinel_cell(self, payload=b"MARKER!!"):
        """Add an independent neighbouring cell and return its layout."""
        cell_offset, cell_size = self._add_cell(payload)
        return FragmentSpec(
            name="sentinel",
            cell_offset=cell_offset,
            data_offset=cell_offset + CELL_HEADER_SIZE,
            expected=payload,
        )

    def add_value(self, name, data_type, payload, large=False):
        """
        Add a value. `payload` is the ground-truth value content authored by
        the test. External cells and large-value segment cells are created as
        required; the returned layout records every fragment's location and
        expected contribution without consulting the reader.
        """
        fragments = []
        name_bytes = name.encode("utf-16le")
        indirect_cell_offset = None

        if len(payload) < 5:
            data_length_field = len(payload)
            inline = True
            external_offset = None
        else:
            data_length_field = len(payload)
            inline = False
            if large:
                assert len(payload) > MAX_SEGMENT_DATA_SIZE
                segments = []
                for start in range(0, len(payload), MAX_SEGMENT_DATA_SIZE):
                    contribution = payload[start:start + MAX_SEGMENT_DATA_SIZE]
                    cell_offset, _ = self._add_cell(contribution)
                    segments.append(cell_offset)
                    fragments.append(FragmentSpec(
                        name="segment-%d" % (len(segments) - 1),
                        cell_offset=cell_offset,
                        data_offset=cell_offset + CELL_HEADER_SIZE,
                        expected=contribution,
                    ))

                indirect_payload = b"".join(
                    struct.pack(str("<I"), offset - REGF_HEADER_SIZE)
                    for offset in segments
                )
                indirect_offset, _ = self._add_cell(indirect_payload)
                db_payload = b"db" + b"\x00\x00" + struct.pack(
                    str("<I"), indirect_offset - REGF_HEADER_SIZE)
                assert len(db_payload) == 8
                external_offset, _ = self._add_cell(db_payload)
                indirect_cell_offset = indirect_offset
            else:
                cell_offset, _ = self._add_cell(payload)
                external_offset = cell_offset
                fragments.append(FragmentSpec(
                    name="data-cell",
                    cell_offset=cell_offset,
                    data_offset=cell_offset + CELL_HEADER_SIZE,
                    expected=payload,
                ))

        vk_payload = bytearray()
        vk_payload += b"vk"                                  # 0x0
        vk_payload += struct.pack(str("<H"), len(name_bytes))  # 0x2
        vk_payload += struct.pack(str("<I"), data_length_field)  # 0x4
        if inline:
            vk_payload += payload + b"\x00" * (4 - len(payload))  # 0x8
        else:
            vk_payload += struct.pack(
                str("<I"), external_offset - REGF_HEADER_SIZE)  # 0x8
        vk_payload += struct.pack(str("<I"), data_type)     # 0xC
        vk_payload += struct.pack(str("<H"), 0)            # 0x10 flags
        vk_payload += struct.pack(str("<H"), 0)            # 0x12 unused
        assert len(vk_payload) == 0x14
        vk_payload += name_bytes                            # 0x14

        vk_offset, vk_size = self._add_cell(bytes(vk_payload))
        layout = {
            "name": name,
            "vk_offset": vk_offset,
            "vk_size": vk_size,
            "fragments": fragments,
            "payload": payload,
            "large": large,
            "indirect_offset": indirect_cell_offset,
        }
        self._value_layouts.append(layout)
        return layout

    def build(self):
        values_list_payload = b"".join(
            struct.pack(str("<I"), layout["vk_offset"] - REGF_HEADER_SIZE)
            for layout in self._value_layouts
        )
        values_list_offset, _ = self._add_cell(values_list_payload)

        root_name = b"ROOT"
        nk_payload = bytearray(0x4C)
        nk_payload[0x0:0x2] = b"nk"
        # 0x2 flags: bit 0x04 marks the root key; bit 0x20 is an ASCII name.
        struct.pack_into(str("<H"), nk_payload, 0x2, 0x20 | 0x04)
        # 0x10 parent key, 0x14 subkey count, 0x18/0x1C subkey lists
        struct.pack_into(str("<I"), nk_payload, 0x10, 0xFFFFFFFF)
        struct.pack_into(str("<I"), nk_payload, 0x14, 0)
        struct.pack_into(str("<I"), nk_payload, 0x18, 0xFFFFFFFF)
        struct.pack_into(str("<I"), nk_payload, 0x1C, 0xFFFFFFFF)
        # 0x24 value count, 0x28 values list, 0x2C security key,
        # 0x30 class name; unused pointers are the -1 sentinel.
        struct.pack_into(
            str("<I"), nk_payload, 0x24, len(self._value_layouts))
        struct.pack_into(
            str("<I"), nk_payload, 0x28,
            values_list_offset - REGF_HEADER_SIZE)
        struct.pack_into(str("<I"), nk_payload, 0x2C, 0xFFFFFFFF)
        struct.pack_into(str("<I"), nk_payload, 0x30, 0xFFFFFFFF)
        struct.pack_into(str("<I"), nk_payload, 0x48, len(root_name))
        nk_payload[0x4C:0x4C + len(root_name)] = root_name
        root_offset, _ = self._add_cell(bytes(nk_payload))

        used = HBIN_HEADER_SIZE + len(self._cells)
        if used > self._hbin_size:
            raise AssertionError(
                "synthetic hive needs 0x%x bytes but HBIN is 0x%x"
                % (used, self._hbin_size))

        buf = bytearray(SLACK_FILL * (REGF_HEADER_SIZE + self._hbin_size))

        regf = bytearray(REGF_HEADER_SIZE)
        struct.pack_into(str("<I"), regf, 0x0, REGF_SIGNATURE)
        struct.pack_into(str("<I"), regf, 0x4, 1)
        struct.pack_into(str("<I"), regf, 0x8, 1)
        struct.pack_into(str("<I"), regf, 0x14, 1)
        struct.pack_into(str("<I"), regf, 0x18, 3)
        struct.pack_into(str("<I"), regf, 0x1C, 0)
        struct.pack_into(str("<I"), regf, 0x20, 1)
        struct.pack_into(str("<I"), regf, 0x24,
                         root_offset - REGF_HEADER_SIZE)
        struct.pack_into(str("<I"), regf, 0x28, self._hbin_size)
        struct.pack_into(str("<I"), regf, 0x2C, 1)
        hive_name = "synth".encode("utf-16le")
        regf[0x30:0x30 + len(hive_name)] = hive_name
        checksum = 0
        for index in range(0, 0x200, 4):
            checksum ^= struct.unpack_from(str("<I"), regf, index)[0]
        if checksum == 0:
            checksum = 1
        elif checksum == 0xFFFFFFFF:
            checksum = 0xFFFFFFFE
        struct.pack_into(str("<I"), regf, 0x1FC, checksum)
        buf[0:REGF_HEADER_SIZE] = regf

        struct.pack_into(str("<I"), buf, REGF_HEADER_SIZE, HBIN_SIGNATURE)
        struct.pack_into(str("<I"), buf, REGF_HEADER_SIZE + 0x4, 0)
        struct.pack_into(str("<I"), buf, REGF_HEADER_SIZE + 0x8,
                         self._hbin_size)
        buf[REGF_HEADER_SIZE + HBIN_HEADER_SIZE:
            REGF_HEADER_SIZE + HBIN_HEADER_SIZE + len(self._cells)] = self._cells

        return io.BytesIO(bytes(buf))

    def patch_dword(self, buf, absolute_offset, value):
        struct.pack_into(str("<I"), buf, absolute_offset, value)

    def patch_signed_dword(self, buf, absolute_offset, value):
        struct.pack_into(str("<i"), buf, absolute_offset, value)

    def patch_bytes(self, buf, absolute_offset, data):
        buf[absolute_offset:absolute_offset + len(data)] = data

    def vk_field_offset(self, layout, field):
        if field == "data_length":
            return layout["vk_offset"] + CELL_HEADER_SIZE + 0x4
        if field == "data_offset":
            return layout["vk_offset"] + CELL_HEADER_SIZE + 0x8
        raise ValueError(field)


class TestInlineValues(unittest.TestCase):
    """Embedded values must stay inside the four VK data_offset bytes."""

    def test_four_byte_inline_never_reads_beyond_vk_field(self):
        payload = pattern_bytes(4, seed=11)
        hive = SyntheticHive()
        layout = hive.add_value("inline4", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("inline4")
        self.assertEqual(payload, value.raw_data())
        self.assertEqual(payload, value.value())

        # A full four-byte inline value occupies the whole data_offset field;
        # the VK flags word immediately after it is authored zero/slack and
        # must never be appended to the value.
        vk_record = layout["vk_offset"] + CELL_HEADER_SIZE
        self.assertEqual(0, struct.unpack_from(
            str("<I"), buf, vk_record + 0x10)[0])
        self.assertEqual(4, len(value.raw_data()))
        self.assertNotIn(SLACK_FILL, value.raw_data())

    def test_two_byte_inline_ignores_remaining_field_bytes(self):
        payload = pattern_bytes(2, seed=17)
        hive = SyntheticHive()
        layout = hive.add_value("inline2", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("inline2")
        self.assertEqual(payload, value.raw_data())

        # The builder zero-pads the four-byte inline field; the reader must
        # still return only the two declared value bytes.
        vk_record = layout["vk_offset"] + CELL_HEADER_SIZE
        self.assertEqual(
            b"\x00\x00",
            bytes(buf[vk_record + 0xA:vk_record + 0xC]),
        )
        self.assertEqual(2, len(value.raw_data()))

    def test_five_byte_value_switches_to_external_cell(self):
        payload = pattern_bytes(5, seed=22)
        hive = SyntheticHive()
        layout = hive.add_value("external5", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("external5")
        self.assertEqual(payload, value.raw_data())
        self.assertEqual(1, len(layout["fragments"]))
        spec = layout["fragments"][0]
        self.assertEqual(
            payload,
            bytes(buf[spec.data_offset:spec.data_offset + len(payload)]),
        )

    def test_inline_dword_type_interpretation_matches_bytes(self):
        payload = struct.pack(str("<I"), 0xDEADBEEF)
        hive = SyntheticHive()
        hive.add_value("dword", RegDWord, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("dword")
        self.assertEqual(payload, value.raw_data())
        self.assertEqual(0xDEADBEEF, value.value())

    def test_high_bit_inline_flag_is_not_treated_as_external_length(self):
        # The 0x80000000 flag means the four bytes are inline. Stripping the
        # flag must leave an actual length of four, not a huge external size,
        # and the value must stay bounded by the four-byte offset field.
        payload = pattern_bytes(4, seed=29)
        hive = SyntheticHive()
        layout = hive.add_value("flagged-inline", RegBin, payload)
        buf = bytearray(hive.build().getvalue())
        hive.patch_dword(
            buf, hive.vk_field_offset(layout, "data_length"),
            0x80000000 | len(payload))

        value = Registry.Registry(io.BytesIO(bytes(buf))).root().value(
            "flagged-inline")
        self.assertEqual(payload, value.raw_data())
        self.assertEqual(4, len(value.raw_data()))


class TestExternalDataCells(unittest.TestCase):
    """Single external data cells must be bounded by their own size."""

    def test_external_cell_at_segment_threshold_is_complete(self):
        payload = pattern_bytes(MAX_SEGMENT_DATA_SIZE, seed=33)
        hive = SyntheticHive()
        layout = hive.add_value("at-threshold", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("at-threshold")
        self.assertEqual(payload, value.raw_data())
        spec = layout["fragments"][0]
        self.assertEqual(
            payload,
            bytes(buf[spec.data_offset:spec.data_offset + len(payload)]),
        )

    def test_legal_tail_padding_is_not_part_of_the_value(self):
        payload = pattern_bytes(9, seed=44)
        hive = SyntheticHive()
        layout = hive.add_value("padded", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("padded")
        raw = value.raw_data()
        self.assertEqual(payload, raw)
        self.assertNotIn(SLACK_FILL, raw)

        spec = layout["fragments"][0]
        # Cell payload is 8-byte aligned; the three slack bytes are padding.
        self.assertEqual(
            SLACK_FILL * 3,
            bytes(buf[spec.data_offset + 9:spec.data_offset + 12]),
        )

    def test_overrun_only_reaches_in_cell_slack_not_neighbour(self):
        payload = pattern_bytes(9, seed=45)
        hive = SyntheticHive()
        sentinel = hive.add_sentinel_cell()
        layout = hive.add_value("overrun", RegBin, payload)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("overrun")
        # Three slack bytes exist inside the value cell; overrun can see them.
        self.assertEqual(
            payload + SLACK_FILL * 3, value.raw_data(overrun=3))
        # Asking for more overrun than the cell holds is capped at the cell
        # boundary, never reaching the sentinel.
        self.assertEqual(
            payload + SLACK_FILL * 3, value.raw_data(overrun=8))
        # The sentinel beyond the value cell is never reached by overrun.
        sentinel_on_disk = bytes(
            buf[sentinel.data_offset:sentinel.data_offset + 8])
        self.assertNotIn(sentinel_on_disk, value.raw_data(overrun=8))

    def test_declared_length_greater_than_cell_is_structural_error(self):
        # A 28 byte payload makes the external cell exactly 8-byte aligned
        # (4 byte size header + 28 bytes), so it has no slack of its own. Any
        # byte beyond the payload therefore belongs to the neighbouring cell.
        payload = pattern_bytes(28, seed=55)
        hive = SyntheticHive()
        sentinel = hive.add_sentinel_cell()
        layout = hive.add_value("short-cell", RegBin, payload)
        buf = bytearray(hive.build().getvalue())

        # Tag the sentinel so any borrowing from the neighbouring cell is
        # unmistakable.
        hive.patch_bytes(buf, sentinel.data_offset, NEIGHBOUR_FILL * 8)

        # Declare more bytes than the data cell can provide on its own.
        hive.patch_dword(
            buf, hive.vk_field_offset(layout, "data_length"), 36)

        with self.assertRaises(LargeDataParseException) as context:
            Registry.Registry(io.BytesIO(bytes(buf))).root().value(
                "short-cell").raw_data()

        error = context.exception
        self.assertEqual(36, error.declared_length)
        # The recoverable prefix matches the authored bytes exactly and stops
        # at the cell boundary; the neighbouring sentinel is never borrowed.
        self.assertEqual(payload, error.recovered_data)
        self.assertEqual(len(payload), error.recovered_length)
        self.assertNotIn(NEIGHBOUR_FILL, error.recovered_data)


class TestLargeValueSegments(unittest.TestCase):
    """DB/DBIndirect large values, including every length boundary."""

    def _build_two_segment(self, total_length, seed):
        payload = pattern_bytes(total_length, seed=seed)
        hive = SyntheticHive()
        layout = hive.add_value("large", RegBin, payload, large=True)
        return hive, layout, payload

    def test_exact_threshold_crossing_uses_two_full_segments(self):
        total_length = MAX_SEGMENT_DATA_SIZE * 2
        hive, layout, payload = self._build_two_segment(total_length, seed=66)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("large")
        raw = value.raw_data()
        self.assertEqual(total_length, len(raw))
        self.assertEqual(payload, raw)

        self.assertEqual(2, len(layout["fragments"]))
        assembled = b""
        for index, spec in enumerate(layout["fragments"]):
            self.assertEqual(
                spec.cell_offset + CELL_HEADER_SIZE, spec.data_offset)
            on_disk = bytes(buf[spec.data_offset:
                                spec.data_offset + len(spec.expected)])
            self.assertEqual(spec.expected, on_disk)
            self.assertEqual(
                MAX_SEGMENT_DATA_SIZE, len(spec.expected),
                "threshold-crossing value must have two full segments",
            )
            assembled += on_disk
        # Expected value is reconstructed from the authored fragments only.
        self.assertEqual(payload, assembled)

    def test_last_segment_shorter_than_full_size(self):
        total_length = MAX_SEGMENT_DATA_SIZE + 7
        hive, layout, payload = self._build_two_segment(total_length, seed=77)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("large")
        self.assertEqual(payload, value.raw_data())

        first, last = layout["fragments"]
        self.assertEqual(MAX_SEGMENT_DATA_SIZE, len(first.expected))
        self.assertEqual(7, len(last.expected))
        self.assertEqual(
            last.expected,
            bytes(buf[last.data_offset:last.data_offset + 7]),
        )
        # Legal padding behind the short final segment must stay out.
        self.assertEqual(
            SLACK_FILL[0],
            buf[last.data_offset + 7],
        )

    def test_large_string_type_interpretation_matches_raw_bytes(self):
        text = "forensic-boundary-" * 1100
        payload = text.encode("utf-16le")
        self.assertGreater(len(payload), MAX_SEGMENT_DATA_SIZE)
        hive = SyntheticHive()
        layout = hive.add_value("large-sz", RegSZ, payload, large=True)
        buf = hive.build().getvalue()

        value = Registry.Registry(io.BytesIO(buf)).root().value("large-sz")
        raw = value.raw_data()
        self.assertEqual(payload, raw)

        assembled = b"".join(
            bytes(buf[spec.data_offset:
                      spec.data_offset + len(spec.expected)])
            for spec in layout["fragments"]
        )
        self.assertEqual(payload, assembled)
        self.assertEqual(text, value.value())

    def test_duplicate_segment_reference_is_structural_error(self):
        total_length = MAX_SEGMENT_DATA_SIZE + 16
        hive, layout, payload = self._build_two_segment(total_length, seed=88)
        buf = bytearray(hive.build().getvalue())

        # Point the DBIndirect block's second entry at the first segment.
        indirect_abs = layout["indirect_offset"]
        first_segment_relative = (
            layout["fragments"][0].cell_offset - REGF_HEADER_SIZE)
        hive.patch_dword(
            buf, indirect_abs + CELL_HEADER_SIZE + 4,
            first_segment_relative)

        with self.assertRaises(LargeDataParseException) as context:
            Registry.Registry(io.BytesIO(bytes(buf))).root().value(
                "large").raw_data()

        error = context.exception
        self.assertIn("Duplicate", str(error))
        self.assertEqual(
            payload[:MAX_SEGMENT_DATA_SIZE], error.recovered_data)
        self.assertEqual(MAX_SEGMENT_DATA_SIZE, error.recovered_length)
        self.assertNotEqual(payload, error.recovered_data)

    def test_declared_length_exceeds_last_segment_is_prefix_only(self):
        total_length = MAX_SEGMENT_DATA_SIZE + 32
        hive, layout, payload = self._build_two_segment(total_length, seed=99)
        buf = bytearray(hive.build().getvalue())

        last = layout["fragments"][1]
        # The DBIndirect cell is laid out immediately after the segment cells.
        # Fill its slack with a neighbour marker; its segment entries stay
        # valid so the intact first segment is recovered first.
        indirect_payload_end = (
            layout["indirect_offset"] + CELL_HEADER_SIZE + 8)
        hive.patch_bytes(
            buf, indirect_payload_end, NEIGHBOUR_FILL * 4)

        # Shrink the final segment cell so its payload cannot satisfy the
        # declared contribution, then claim an even larger value.
        hive.patch_signed_dword(
            buf, last.cell_offset,
            -(CELL_HEADER_SIZE + 8))
        hive.patch_dword(
            buf, hive.vk_field_offset(layout, "data_length"),
            total_length + 16)

        with self.assertRaises(LargeDataParseException) as context:
            Registry.Registry(io.BytesIO(bytes(buf))).root().value(
                "large").raw_data()

        error = context.exception
        # The recovered prefix must equal the authored first segment exactly.
        # A byte borrowed from the marker-tagged neighbour would break it.
        expected_prefix = payload[:MAX_SEGMENT_DATA_SIZE]
        self.assertEqual(expected_prefix, error.recovered_data)
        self.assertEqual(MAX_SEGMENT_DATA_SIZE, error.recovered_length)
        self.assertFalse(
            error.recovered_data.endswith(NEIGHBOUR_FILL * 4),
            "reader must not borrow the neighbour cell's bytes",
        )
        self.assertGreater(error.declared_length, total_length)
        self.assertGreater(total_length, error.recovered_length)

    def test_segment_reference_outside_hbins_is_structural_error(self):
        total_length = MAX_SEGMENT_DATA_SIZE + 4
        hive, layout, payload = self._build_two_segment(
            total_length, seed=111)
        buf = bytearray(hive.build().getvalue())

        hive.patch_dword(
            buf, layout["indirect_offset"] + CELL_HEADER_SIZE + 4,
            0xFFFFF000)

        with self.assertRaises(LargeDataParseException) as context:
            Registry.Registry(io.BytesIO(bytes(buf))).root().value(
                "large").raw_data()

        error = context.exception
        self.assertIn("outside", str(error))
        self.assertEqual(
            payload[:MAX_SEGMENT_DATA_SIZE], error.recovered_data)
        self.assertEqual(1, error.segment_count)


class TestRealLargeValueSample(unittest.TestCase):
    """
    The repository's ProductPolicy value spans two real segments. Each
    segment's offset and expected contribution are recorded independently
    (from the raw file and the DBIndirect entries), never from reader output.
    """

    def setUp(self):
        self.path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "testing", "reg_samples", "new_log_1", "SYSTEM")
        with open(self.path, "rb") as handle:
            self.raw = handle.read()

    def test_each_segment_contribution_matches_independent_record(self):
        registry = Registry.Registry(self.path)
        vk = registry.root().find_key(
            r"ControlSet001\Control\ProductOptions").value(
                "ProductPolicy")._vkrecord
        declared_length = vk.data_length()

        db_cell = HBINCell(vk._buf, vk.data_offset(), vk)
        db_record = db_cell.child()
        indirect_cell = HBINCell(
            vk._buf,
            db_record.abs_offset_from_hbin_offset(
                db_record.unpack_dword(0x4)),
            db_record)
        indirect = DBIndirectBlock(
            vk._buf, indirect_cell.data_offset(), indirect_cell)

        expected = bytearray()
        remaining = declared_length
        index = 0
        while remaining > 0:
            relative = indirect.unpack_dword(4 * index)
            cell_abs = indirect.abs_offset_from_hbin_offset(relative)
            cell = HBINCell(vk._buf, cell_abs, indirect)
            contribution_size = min(MAX_SEGMENT_DATA_SIZE, remaining)

            # Ground truth sliced directly from the file at the recorded
            # cell offset; the reader's large_data() output is not used.
            ground_truth = self.raw[
                cell.data_offset():
                cell.data_offset() + contribution_size]
            self.assertEqual(
                contribution_size, len(ground_truth),
                "segment %d must be fully present on disk" % index,
            )
            expected += ground_truth
            remaining -= contribution_size
            index += 1

        self.assertEqual(2, index)
        self.assertEqual(declared_length, len(expected))
        self.assertEqual(
            "7e96f10f77e1c44771d7045c24b94024",
            hashlib.md5(bytes(expected)).hexdigest(),
        )
        self.assertEqual(bytes(expected), vk.raw_data())


if __name__ == "__main__":
    unittest.main(verbosity=2)
