"""Byte-level builder for minimal but python-registry-parseable hives.

Two-pass design: every cell is allocated first (so all relative offsets are
known), then link fields are written in a second pass. The layout fits in a
single 0x1000 HBIN so every field can be cited by an absolute file offset.
Offsets inside cells are relative to the first HBIN (0x1000); file offsets are
absolute. Teaching/test artifact, not a general-purpose hive writer.
"""
from __future__ import annotations

import struct

REGF_SIZE = 0x1000
HBIN_OFFSET = 0x1000
HBIN_SIZE = 0x1000
REGF_SIGNATURE = 0x66676572
HBIN_SIGNATURE = 0x6E696268

REG_NONE = 0x0
REG_SZ = 0x1
REG_DWORD = 0x4
REG_QWORD = 0xB
REG_FILETIME = 0x10


def regf_checksum(buf_512: bytes) -> int:
    """REGF checksum: XOR of DWORDs 0x0..0x1FB with the checksum slot (0x1FC)
    treated as zero, matching how the on-disk value self-cancels on validation.
    The library's REGFBlock.calculate_checksum reads the stored slot, so callers
    must pass a header whose 0x1FC is zero when computing a fresh value.
    """
    xsum = 0
    for off in range(0, 0x1FC, 4):
        xsum ^= struct.unpack_from("<I", buf_512, off)[0]
    if xsum == 0:
        return 1
    if xsum == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return xsum


class MiniHive:
    """Allocate cells for a small fixed tree and serialize a primary hive."""

    def __init__(self, hive_name: str, header_filetime: int, seq1: int, seq2: int):
        self.hive_name = hive_name
        self.header_filetime = header_filetime
        self.seq1 = seq1
        self.seq2 = seq2
        self._blobs: list[bytearray] = []   # cell payloads (no size prefix)
        self._rel: list[int] = []
        self._cursor = 0x20                  # relative offset inside first HBIN

    def _alloc(self, payload: bytearray) -> int:
        rel = self._cursor
        self._rel.append(rel)
        self._blobs.append(payload)
        self._cursor += len(payload) + 4
        if self._cursor > HBIN_SIZE:
            raise ValueError("mini hive overflowed single HBIN")
        return rel

    def alloc_data(self, data: bytes) -> int:
        return self._alloc(bytearray(data))

    def alloc_vk(self, name: str, data: bytes, data_type: int) -> tuple[int, int]:
        """Return (vk_cell_rel, file_offset_of_FILETIME_or_data_field)."""
        name_b = name.encode("utf-16le")
        inline = len(data) < 5
        payload = bytearray(0x14 + len(name_b))
        payload[0:2] = b"vk"
        struct.pack_into("<H", payload, 0x2, len(name_b))
        raw_len = len(data) | (0x80000000 if inline else 0)
        struct.pack_into("<I", payload, 0x4, raw_len)
        if inline:
            payload[0x8:0x8 + len(data)] = data
            data_field_abs = None
        else:
            data_rel = self.alloc_data(data)
            struct.pack_into("<I", payload, 0x8, data_rel)
            data_field_abs = None
        struct.pack_into("<I", payload, 0xC, data_type)
        struct.pack_into("<H", payload, 0x10, 0x0000)
        payload[0x14:0x14 + len(name_b)] = name_b
        rel = self._alloc(payload)
        return rel, data_field_abs

    def alloc_lf(self, nk_cell_rels: list[int]) -> int:
        payload = bytearray(4 + 8 * len(nk_cell_rels))
        payload[0:2] = b"lf"
        struct.pack_into("<H", payload, 0x2, len(nk_cell_rels))
        for i, cell_rel in enumerate(nk_cell_rels):
            struct.pack_into("<I", payload, 4 + 8 * i, cell_rel)
        return self._alloc(payload)

    def alloc_values_list(self, vk_cell_rels: list[int]) -> int:
        payload = bytearray(b"".join(struct.pack("<I", r) for r in vk_cell_rels))
        return self._alloc(payload)

    def alloc_nk_shell(self, name: str, filetime: int, is_root: bool = False) -> dict:
        """Reserve an NK cell before its children/values exist.

        Link fields stay zero until fill_nk_links() runs, which lets the root
        NK occupy the first cell while subkeys and VKs are allocated later.
        """
        name_b = name.encode("utf-16le")
        payload = bytearray(0x4C + len(name_b))
        payload[0:2] = b"nk"
        flags = 0x0004 if is_root else 0x0000
        struct.pack_into("<H", payload, 0x2, flags)
        struct.pack_into("<Q", payload, 0x4, filetime)
        struct.pack_into("<H", payload, 0x48, len(name_b))
        payload[0x4C:0x4C + len(name_b)] = name_b
        rel = self._alloc(payload)
        return {
            "cell_rel": rel,
            "record_abs": HBIN_OFFSET + rel + 4,
            "filetime_field_abs": HBIN_OFFSET + rel + 4 + 0x4,
            "name": name,
            "blob": payload,
        }

    def fill_nk_links(
        self,
        shell: dict,
        parent_cell_rel: int,
        subkey_cell_rels: list[int] | None = None,
        vk_cell_rels: list[int] | None = None,
    ) -> None:
        payload = shell["blob"]
        struct.pack_into("<I", payload, 0x10, parent_cell_rel)
        nsub = len(subkey_cell_rels or [])
        struct.pack_into("<I", payload, 0x14, nsub)
        struct.pack_into("<I", payload, 0x18, nsub)
        sublist_rel = self.alloc_lf(subkey_cell_rels) if nsub else 0
        struct.pack_into("<I", payload, 0x1C, sublist_rel)
        nval = len(vk_cell_rels or [])
        struct.pack_into("<I", payload, 0x24, nval)
        vlist_rel = self.alloc_values_list(vk_cell_rels) if nval else 0
        struct.pack_into("<I", payload, 0x28, vlist_rel)
        struct.pack_into("<I", payload, 0x2C, 0x20)

    def alloc_nk(
        self,
        name: str,
        filetime: int,
        parent_cell_rel: int,
        subkey_cell_rels: list[int] | None = None,
        vk_cell_rels: list[int] | None = None,
        is_root: bool = False,
    ) -> dict:
        name_b = name.encode("utf-16le")
        payload = bytearray(0x4C + len(name_b))
        payload[0:2] = b"nk"
        flags = 0x0004 if is_root else 0x0000
        struct.pack_into("<H", payload, 0x2, flags)
        struct.pack_into("<Q", payload, 0x4, filetime)
        struct.pack_into("<I", payload, 0x10, parent_cell_rel)
        nsub = len(subkey_cell_rels or [])
        struct.pack_into("<I", payload, 0x14, nsub)
        struct.pack_into("<I", payload, 0x18, nsub)
        sublist_rel = self.alloc_lf(subkey_cell_rels) if nsub else 0
        struct.pack_into("<I", payload, 0x1C, sublist_rel)
        nval = len(vk_cell_rels or [])
        struct.pack_into("<I", payload, 0x24, nval)
        vlist_rel = self.alloc_values_list(vk_cell_rels) if nval else 0
        struct.pack_into("<I", payload, 0x28, vlist_rel)
        struct.pack_into("<I", payload, 0x2C, 0x20)
        struct.pack_into("<H", payload, 0x48, len(name_b))
        payload[0x4C:0x4C + len(name_b)] = name_b
        rel = self._alloc(payload)
        return {
            "cell_rel": rel,
            "record_abs": HBIN_OFFSET + rel + 4,
            "filetime_field_abs": HBIN_OFFSET + rel + 4 + 0x4,
            "name": name,
        }

    def build(
        self,
        root_cell_rel: int,
        reorg_filetime: int = 0,
        flags: int = 0,
        file_type: int = 0,
    ) -> bytes:
        regf = bytearray(REGF_SIZE)
        struct.pack_into("<I", regf, 0x0, REGF_SIGNATURE)
        struct.pack_into("<I", regf, 0x4, self.seq1)
        struct.pack_into("<I", regf, 0x8, self.seq2)
        struct.pack_into("<Q", regf, 0xC, self.header_filetime)
        struct.pack_into("<I", regf, 0x14, 1)
        struct.pack_into("<I", regf, 0x18, 5)
        struct.pack_into("<I", regf, 0x1C, file_type)
        struct.pack_into("<I", regf, 0x20, 1)
        struct.pack_into("<I", regf, 0x24, root_cell_rel)
        struct.pack_into("<I", regf, 0x28, HBIN_SIZE)
        struct.pack_into("<I", regf, 0x2C, 1)
        name_b = self.hive_name.encode("utf-16le")
        regf[0x30:0x30 + len(name_b)] = name_b
        struct.pack_into("<I", regf, 0x90, flags)
        struct.pack_into("<Q", regf, 0xA8, reorg_filetime)

        hbin = bytearray(HBIN_SIZE)
        struct.pack_into("<I", hbin, 0x0, HBIN_SIGNATURE)
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)
        struct.pack_into("<Q", hbin, 0xC, self.header_filetime)
        pos = 0x20
        for rel, payload in zip(self._rel, self._blobs):
            cell = struct.pack("<i", -(len(payload) + 4)) + bytes(payload)
            hbin[pos:pos + len(cell)] = cell
            pos += len(cell)
        free = HBIN_SIZE - pos
        if free >= 4:
            struct.pack_into("<i", hbin, pos, free)

        out = bytearray(regf + hbin)
        struct.pack_into("<I", out, 0x1FC, regf_checksum(out[:0x200]))
        return bytes(out)


def _marvin32(buf: bytes, seed: int = 0x82EF4D887A4E55C5) -> int:
    """Marvin32 identical to RegistryParse.HvLEBlock.marvin32_hash.

    Delegates to the library's own ctypes-based implementation so a synthetic
    HvLE validates under the exact code an investigator will parse it with.
    """
    from Registry.RegistryParse import HvLEBlock

    class _SeedCarrier(HvLEBlock):
        def __init__(self, marvin_seed: int):
            self._marvin32seed = marvin_seed

    return _SeedCarrier(seed).marvin32_hash(buf)


class MiniLog:
    """Build a minimal Windows 8.1-style transaction log (one HvLE entry)."""

    HVLE_SIGNATURE = 0x454C7648
    LOG_HEADER_SIZE = 0x200
    ENTRY_HEADER_SIZE = 0x28
    PAGE_ALIGN = 0x200

    def __init__(self, hive_name: str, sequence: int, hbins_size: int,
                 header_filetime: int, reorg_filetime: int = 0):
        self.hive_name = hive_name
        self.sequence = sequence
        self.hbins_size = hbins_size
        self.header_filetime = header_filetime
        self.reorg_filetime = reorg_filetime

    def build(self, dirty_pages: list[tuple[int, bytes]], hive_flags: int = 0) -> bytes:
        # dirty_pages: list of (offset relative to first HBIN, page bytes)
        count = len(dirty_pages)
        refs_size = 8 * count
        data_offset = self.ENTRY_HEADER_SIZE + refs_size
        body = bytearray()
        for _, page in dirty_pages:
            body += page
        entry_size = data_offset + len(body)
        # align total HvLE size up to 0x200
        if entry_size % self.PAGE_ALIGN:
            entry_size += self.PAGE_ALIGN - (entry_size % self.PAGE_ALIGN)

        hvle = bytearray(entry_size)
        struct.pack_into("<I", hvle, 0x0, self.HVLE_SIGNATURE)
        struct.pack_into("<I", hvle, 0x4, entry_size)
        struct.pack_into("<I", hvle, 0x8, hive_flags)
        struct.pack_into("<I", hvle, 0xC, self.sequence)
        struct.pack_into("<I", hvle, 0x10, self.hbins_size)
        struct.pack_into("<I", hvle, 0x14, count)
        struct.pack_into("<I", hvle, 0x18, 0)  # hash-1 placeholder
        struct.pack_into("<I", hvle, 0x20, 0)  # hash-2 placeholder (DWORD slot)
        for i, (rel_off, page) in enumerate(dirty_pages):
            struct.pack_into("<I", hvle, 0x28 + 8 * i, rel_off)
            struct.pack_into("<I", hvle, 0x28 + 8 * i + 4, len(page))
        pos = data_offset
        for _, page in dirty_pages:
            hvle[pos:pos + len(page)] = page
            pos += len(page)
        # Hash-1 covers the dirty-page body (unaffected by header hash slots).
        hash1 = _marvin32(bytes(hvle[self.ENTRY_HEADER_SIZE:entry_size]))
        struct.pack_into("<Q", hvle, 0x18, hash1)
        # Hash-2 is a self-consistent Marvin32 over the populated 32-byte header:
        # it hashes bytes that include the hash-2 slot itself, so iterate to a
        # fixed point. One pass already converges for this 64-bit construction.
        for _ in range(8):
            candidate = _marvin32(bytes(hvle[0:32]))
            struct.pack_into("<Q", hvle, 0x20, candidate)
        if _marvin32(bytes(hvle[0:32])) != struct.unpack_from("<Q", hvle, 0x20)[0]:
            raise RuntimeError("HvLE hash-2 fixed point did not converge")

        regf = bytearray(REGF_SIZE)
        struct.pack_into("<I", regf, 0x0, REGF_SIGNATURE)
        struct.pack_into("<I", regf, 0x4, self.sequence)
        struct.pack_into("<I", regf, 0x8, self.sequence)
        struct.pack_into("<Q", regf, 0xC, self.header_filetime)
        struct.pack_into("<I", regf, 0x14, 1)
        struct.pack_into("<I", regf, 0x18, 5)
        struct.pack_into("<I", regf, 0x1C, 6)   # new transaction log file
        struct.pack_into("<I", regf, 0x20, 1)
        struct.pack_into("<I", regf, 0x28, self.hbins_size)
        struct.pack_into("<I", regf, 0x2C, 1)   # clustering factor = 1
        name_b = self.hive_name.encode("utf-16le")
        regf[0x30:0x30 + len(name_b)] = name_b
        struct.pack_into("<I", regf, 0x90, hive_flags)
        struct.pack_into("<Q", regf, 0xA8, self.reorg_filetime)

        total = self.LOG_HEADER_SIZE + entry_size
        out = bytearray(total)
        out[0:REGF_SIZE] = regf
        out[self.LOG_HEADER_SIZE:self.LOG_HEADER_SIZE + entry_size] = hvle
        struct.pack_into("<I", out, 0x1FC, regf_checksum(out[:0x200]))
        return bytes(out)
