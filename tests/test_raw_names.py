#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Tests for the lossless (forensic) representation of registry key and
value names: raw name bytes, encoding flags, structured path
components, safe display text, and relocation by raw names.

The tests build a synthetic in-memory hive containing names that
display alike but differ in their stored bytes (compressed vs. UTF-16,
control characters, invalid UTF-16, non-BMP characters, and a default
value).
"""
import io
import json
import struct
import unittest

from Registry import Registry


def _align8(n):
    return (n + 7) & ~7


class HiveBuilder(object):
    """
    Assembles a minimal, valid registry hive in memory.
    Cell offsets are relative to the start of the first HBIN, as in a
    real hive. Parents may patch their payloads after children are
    added, because add_cell() keeps the payload object by reference.
    """
    def __init__(self):
        self._cells = []
        self._next_offset = 0x20

    def add_cell(self, payload):
        offset = self._next_offset
        size = _align8(len(payload) + 4)
        self._cells.append((offset, size, payload))
        self._next_offset += size
        return offset

    def build(self, root_offset):
        hbin_size = max(0x1000, (self._next_offset + 0xFFF) & ~0xFFF)
        hbin = bytearray(hbin_size)
        hbin[0:4] = b"hbin"
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, hbin_size)
        for offset, size, payload in self._cells:
            struct.pack_into("<i", hbin, offset, -size)
            hbin[offset + 4:offset + 4 + len(payload)] = payload
        if self._next_offset < hbin_size:
            struct.pack_into("<i", hbin, self._next_offset,
                             hbin_size - self._next_offset)

        header = bytearray(0x1000)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x4, 1)           # sequence1
        struct.pack_into("<I", header, 0x8, 1)           # sequence2
        struct.pack_into("<I", header, 0x14, 1)          # major version
        struct.pack_into("<I", header, 0x18, 3)          # minor version
        struct.pack_into("<I", header, 0x1C, 0)          # primary file
        struct.pack_into("<I", header, 0x20, 1)          # file format
        struct.pack_into("<I", header, 0x24, root_offset)
        struct.pack_into("<I", header, 0x28, hbin_size)
        struct.pack_into("<I", header, 0x2C, 1)          # clustering factor
        hive_name = u"\\??\\RAWNAMES".encode("utf-16le")
        header[0x30:0x30 + len(hive_name)] = hive_name
        checksum = 0
        for i in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", header, i)[0]
        if checksum == 0:
            checksum = 1
        elif checksum == 0xFFFFFFFF:
            checksum = 0xFFFFFFFE
        struct.pack_into("<I", header, 0x1FC, checksum)
        return bytes(header) + bytes(hbin)


def make_nk_record(name_raw, compressed, parent_offset, subkey_count=0,
                   subkey_list_offset=0xFFFFFFFF, value_count=0,
                   values_list_offset=0xFFFFFFFF, is_root=False):
    record = bytearray(0x4C + len(name_raw))
    record[0:2] = b"nk"
    flags = 0x20 if compressed else 0x00
    if is_root:
        flags |= 0x04
    struct.pack_into("<H", record, 0x2, flags)
    struct.pack_into("<Q", record, 0x4, 133485456000000000)
    struct.pack_into("<I", record, 0x10, parent_offset)
    struct.pack_into("<I", record, 0x14, subkey_count)
    struct.pack_into("<I", record, 0x18, 0)
    struct.pack_into("<I", record, 0x1C, subkey_list_offset)
    struct.pack_into("<I", record, 0x20, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x24, value_count)
    struct.pack_into("<I", record, 0x28, values_list_offset)
    struct.pack_into("<I", record, 0x2C, 0xFFFFFFFF)
    struct.pack_into("<I", record, 0x30, 0xFFFFFFFF)
    struct.pack_into("<H", record, 0x48, len(name_raw))
    struct.pack_into("<H", record, 0x4A, 0)
    record[0x4C:] = name_raw
    return record


def make_vk_record(builder, name_raw, compressed, data_type, data):
    record = bytearray(0x14 + len(name_raw))
    record[0:2] = b"vk"
    struct.pack_into("<H", record, 0x2, len(name_raw))
    if len(data) <= 4:
        struct.pack_into("<I", record, 0x4, 0x80000000 | len(data))
        record[0x8:0x8 + len(data)] = data
    else:
        data_offset = builder.add_cell(data)
        struct.pack_into("<I", record, 0x4, len(data))
        struct.pack_into("<I", record, 0x8, data_offset)
    struct.pack_into("<I", record, 0xC, data_type)
    struct.pack_into("<H", record, 0x10, 1 if compressed else 0)
    record[0x14:] = name_raw
    return record


def make_lf_list(offsets):
    record = bytearray(4 + 8 * len(offsets))
    record[0:2] = b"lf"
    struct.pack_into("<H", record, 0x2, len(offsets))
    for i, offset in enumerate(offsets):
        struct.pack_into("<I", record, 4 + 8 * i, offset)
    return record


COMPRESSED_ABC = b"ABC"
UTF16_ABC = u"ABC".encode("utf-16le")
CONTROL_NAME = b"A\x1b[31mB"
INVALID_UTF16 = b"A\x00B"
NONBMP_KEY = u"\U00010348Key".encode("utf-16le")
NONBMP_VALUE = u"\U00010348".encode("utf-16le")
CONTROL_VALUE = b"ev\x1b[31mil"
INVALID_UTF16_VALUE = b"X\x00Y"


def build_hive():
    builder = HiveBuilder()

    root_record = make_nk_record(b"ROOT", True, 0xFFFFFFFF, is_root=True)
    root_offset = builder.add_cell(root_record)

    value_defs = [
        (b"", False, Registry.RegSZ, u"default-data\x00".encode("utf-16le")),
        (b"Data", True, Registry.RegDWord, struct.pack("<I", 1)),
        (u"Data".encode("utf-16le"), False, Registry.RegDWord, struct.pack("<I", 2)),
        (CONTROL_VALUE, True, Registry.RegSZ, u"x\x00".encode("utf-16le")),
        (INVALID_UTF16_VALUE, False, Registry.RegDWord, struct.pack("<I", 3)),
        (NONBMP_VALUE, False, Registry.RegDWord, struct.pack("<I", 4)),
    ]
    vk_offsets = []
    for name_raw, compressed, data_type, data in value_defs:
        record = make_vk_record(builder, name_raw, compressed, data_type, data)
        vk_offsets.append(builder.add_cell(record))
    values_list_offset = builder.add_cell(
        struct.pack("<%dI" % len(vk_offsets), *vk_offsets))

    subkey_defs = [
        (COMPRESSED_ABC, True, len(vk_offsets), values_list_offset),
        (UTF16_ABC, False, 0, 0xFFFFFFFF),
        (CONTROL_NAME, True, 0, 0xFFFFFFFF),
        (NONBMP_KEY, False, 0, 0xFFFFFFFF),
        (INVALID_UTF16, False, 0, 0xFFFFFFFF),
        (b"Normal", True, 0, 0xFFFFFFFF),
    ]
    subkey_offsets = []
    for name_raw, compressed, value_count, values_offset in subkey_defs:
        record = make_nk_record(name_raw, compressed, root_offset,
                                value_count=value_count,
                                values_list_offset=values_offset)
        subkey_offsets.append(builder.add_cell(record))

    lf_offset = builder.add_cell(make_lf_list(subkey_offsets))
    struct.pack_into("<I", root_record, 0x14, len(subkey_offsets))
    struct.pack_into("<I", root_record, 0x1C, lf_offset)

    return builder.build(root_offset)


HIVE = build_hive()


class TestRawNames(unittest.TestCase):
    def setUp(self):
        self.registry = Registry.Registry(io.BytesIO(HIVE))
        self.root = self.registry.root()

    def subkeys_by_raw_name(self):
        return dict((k.raw_name(), k) for k in self.root.subkeys())

    def test_raw_names_and_flags_preserved(self):
        keys = self.subkeys_by_raw_name()
        self.assertIn(COMPRESSED_ABC, keys)
        self.assertIn(UTF16_ABC, keys)
        self.assertIn(CONTROL_NAME, keys)
        self.assertIn(NONBMP_KEY, keys)
        self.assertIn(INVALID_UTF16, keys)

        compressed = keys[COMPRESSED_ABC].name_component()
        utf16 = keys[UTF16_ABC].name_component()
        self.assertTrue(compressed.is_compressed)
        self.assertFalse(utf16.is_compressed)
        # the two names display alike but are not equal as evidence
        self.assertEqual(keys[COMPRESSED_ABC].name(), u"ABC")
        self.assertEqual(keys[UTF16_ABC].name(), u"ABC")
        self.assertNotEqual(compressed, utf16)
        self.assertEqual(compressed, Registry.RegistryNameComponent(COMPRESSED_ABC, True))

    def test_structured_path_components_relocate_cells(self):
        for key in self.root.subkeys():
            components = key.path_components()
            self.assertIsInstance(components, list)
            self.assertEqual(components[0], self.root.name_component())
            self.assertEqual(components[-1], key.name_component())

            relocated = self.registry.open_components(components)
            self.assertEqual(relocated._nkrecord.offset(), key._nkrecord.offset())

            exported = json.loads(json.dumps([c.export() for c in components]))
            relocated = self.registry.open_components(exported)
            self.assertEqual(relocated._nkrecord.offset(), key._nkrecord.offset())

    def test_display_similar_keys_relocate_to_distinct_cells(self):
        compressed = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        utf16 = self.root.subkey_by_raw_name(UTF16_ABC, False)
        self.assertNotEqual(compressed._nkrecord.offset(), utf16._nkrecord.offset())
        # the plain string lookup can only ever reach one of them
        self.assertEqual(self.root.subkey("ABC")._nkrecord.offset(),
                         compressed._nkrecord.offset())

    def test_display_text_has_no_control_character_injection(self):
        def check(key):
            self.assertTrue(key.display_path().isprintable(), key.display_path())
            self.assertTrue(str(key).isprintable(), str(key))
            self.assertTrue(repr(key).isprintable(), repr(key))
            for value in key.values():
                self.assertTrue(value.display_name().isprintable(), value.display_name())
                self.assertTrue(repr(value).isprintable(), repr(value))
            for subkey in key.subkeys():
                check(subkey)
        check(self.root)

        control_key = self.subkeys_by_raw_name()[CONTROL_NAME]
        self.assertNotIn(u"\x1b", control_key.display_path())
        self.assertIn(u"\\x1b", control_key.display_path())
        self.assertIn(u"A\\x1b[31mB", control_key.display_path())

        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        control_value = key_a.value_by_raw_name(CONTROL_VALUE, True)
        self.assertNotIn(u"\x1b", control_value.display_name())
        self.assertIn(u"ev\\x1b[31mil", control_value.display_name())

    def test_invalid_utf16_names_do_not_crash(self):
        names = [k.name() for k in self.root.subkeys()]
        self.assertIn(u"AB", names)  # b"A\x00B" decoded best-effort
        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        value = key_a.value_by_raw_name(INVALID_UTF16_VALUE, False)
        self.assertEqual(value.name(), u"XY")
        self.assertEqual(value.value(), 3)
        # raw bytes remain the authoritative, lossless representation
        self.assertEqual(value.raw_name(), INVALID_UTF16_VALUE)
        self.assertEqual(self.subkeys_by_raw_name()[INVALID_UTF16].raw_name(), INVALID_UTF16)

    def test_default_value(self):
        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        default = key_a.value_by_raw_name(b"")
        self.assertTrue(default.is_default())
        self.assertEqual(default.raw_name(), b"")
        self.assertEqual(default.name(), u"(default)")
        self.assertEqual(default.display_name(), u"(default)")
        self.assertEqual(default.value(), u"default-data")
        # the existing string API keeps working for the default value
        self.assertEqual(key_a.value("(default)").value(), u"default-data")

    def test_normal_string_queries_unaffected(self):
        key = self.root.subkey("normal")
        self.assertEqual(key.name(), u"Normal")
        self.assertEqual(self.registry.open("Normal")._nkrecord.offset(),
                         key._nkrecord.offset())
        # valid non-BMP unicode names work through the plain string API
        nonbmp = self.root.subkey(u"\U00010348Key")
        self.assertEqual(nonbmp.raw_name(), NONBMP_KEY)
        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        self.assertIn(key_a.value("Data").value(), (1, 2))

    def test_values_relocate_by_raw_name(self):
        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        self.assertEqual(key_a.value_by_raw_name(b"Data", True).value(), 1)
        self.assertEqual(key_a.value_by_raw_name(u"Data".encode("utf-16le"), False).value(), 2)
        self.assertEqual(key_a.value_by_raw_name(NONBMP_VALUE, False).value(), 4)
        # raw bytes alone also locate the value, regardless of encoding
        self.assertEqual(key_a.value_by_raw_name(b"Data").value(), 1)
        with self.assertRaises(Registry.RegistryValueNotFoundException):
            key_a.value_by_raw_name(b"NoSuchValue")
        with self.assertRaises(Registry.RegistryKeyNotFoundException):
            self.root.subkey_by_raw_name(b"NoSuchKey")

    def test_export_is_lossless_and_json_serializable(self):
        key_a = self.root.subkey_by_raw_name(COMPRESSED_ABC, True)
        exported = key_a.export()
        exported = json.loads(json.dumps(exported))

        self.assertEqual(exported["path_components"][-1]["raw_hex"], "414243")
        self.assertTrue(exported["path_components"][-1]["compressed"])
        self.assertTrue(exported["display_path"].isprintable())

        relocated = self.registry.open_components(exported["path_components"])
        self.assertEqual(relocated._nkrecord.offset(), key_a._nkrecord.offset())

        values = dict((v["name"]["raw_hex"], v) for v in exported["values"])
        self.assertIn("4400610074006100", values)  # "Data" as UTF-16LE
        self.assertIn("65761b5b33316d696c", values)  # control characters preserved
        default_exports = [v for v in exported["values"] if v["is_default"]]
        self.assertEqual(len(default_exports), 1)
        self.assertEqual(default_exports[0]["name"]["raw_hex"], "")


if __name__ == '__main__':
    unittest.main(verbosity=2)
