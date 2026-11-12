#!/bin/python

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

"""
Explicit forensic scan mode for python-registry.

This module implements a *deleted record scanner* that carves candidate
nk/vk records from the FREE cells of a hive. It is deliberately separate
from the normal active-tree traversal (Registry.Registry / NKRecord):
the scanner never walks the active key tree, never follows the values
list of an active key, and never modifies the hive buffer.

Design guarantees:

  - A two-byte "nk"/"vk" signature alone is never treated as a recovery.
    Every candidate is validated for cell bounds, name encoding, and
    data/reference consistency before it is classified.
  - Associations between records are only reported when they are
    verifiable through on-disk offsets (e.g. a deleted key's values
    list pointing at a deleted value's cell). A deleted value is NEVER
    attached to an active (or deleted) key merely because the names
    happen to match.
  - Cells that were partially reused, and records of which only a
    fragment survives, are reported as orphans with the reason stated.
  - Every clue carries the absolute file offset of its evidence bytes,
    so each finding can be traced back to the raw hive.
"""

from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import struct
import datetime
from enum import Enum

from Registry import RegistryParse
from Registry.RegistryParse import REGFBlock, ParseException, \
    DEVPROP_MASK_TYPE, parse_windows_timestamp

NK_FIXED_SIZE = 0x4C
VK_FIXED_SIZE = 0x14

SUBKEY_LIST_IDS = (b"lf", b"lh", b"li", b"ri")

# Registry value data types known to this library (see RegistryParse).
KNOWN_DATA_TYPES = set(range(0x0, 0x11)) | set(range(0x101, 0x120))

# Plausibility window for nk timestamps; anything outside is an anomaly.
_MIN_TIMESTAMP = datetime.datetime(1990, 1, 1)


class CandidateStatus(Enum):
    """
    Classification of a carved candidate record.

    RELIABLE: the structure is internally consistent and every reference
      it contains was verified against a real cell in the hive.
    PARTIAL: the structure itself is valid, but at least one reference
      could not be verified (overwritten, out of bounds, or reused).
    ORPHAN: only a fragment of the structure survives (truncated or
      half-overwritten); no recovery is claimed.
    """
    RELIABLE = "reliable"
    PARTIAL = "partial"
    ORPHAN = "orphan"


class ReferenceStatus(Enum):
    VERIFIED = "verified"
    UNVERIFIABLE = "unverifiable"


class Reference(object):
    """
    A single offset reference found inside a candidate record.

    Attributes:
      - field: name of the referencing field (e.g. "parent_key",
        "values_list[0]", "data").
      - field_offset: absolute file offset of the DWORD holding the
        reference (the evidence bytes for this clue).
      - relative_offset: the raw hive-relative offset read from the field.
      - target_offset: absolute file offset the reference points to.
      - status: ReferenceStatus.
      - detail: human readable explanation, including why a reference
        could not be verified.
    """
    def __init__(self, field, field_offset, relative_offset, target_offset,
                 status, detail):
        self.field = field
        self.field_offset = field_offset
        self.relative_offset = relative_offset
        self.target_offset = target_offset
        self.status = status
        self.detail = detail

    def __repr__(self):
        return "Reference(%s @0x%x -> 0x%x, %s)" % (
            self.field, self.field_offset, self.target_offset,
            self.status.value)


class DeletedRecordCandidate(object):
    """
    A candidate deleted nk/vk record carved from a free cell.

    Attributes:
      - record_type: "nk" or "vk".
      - offset: absolute file offset of the record (evidence offset).
      - cell_offset: absolute file offset of the containing free cell.
      - status: CandidateStatus.
      - name: decoded name, or None if it could not be determined.
      - fields: dict of parsed header fields (may be incomplete).
      - references: list of Reference objects found in this record.
      - anomalies: list of strings describing anything suspicious.
      - referenced_by: list of (candidate, Reference) tuples of other
        carved candidates whose verified references point at this record.
      - length: number of evidence bytes covered by this candidate.
    """
    def __init__(self, buf, record_type, offset, cell_offset, status, name,
                 fields, references, anomalies, length):
        self._buf = buf
        self.record_type = record_type
        self.offset = offset
        self.cell_offset = cell_offset
        self.status = status
        self.name = name
        self.fields = fields
        self.references = references
        self.anomalies = anomalies
        self.referenced_by = []
        self.length = length

    def raw_bytes(self):
        """
        The raw evidence bytes of this candidate, read from the hive
        buffer at self.offset. The hive is never modified.
        """
        return self._buf[self.offset:self.offset + self.length]

    def verified_references(self):
        return [r for r in self.references
                if r.status == ReferenceStatus.VERIFIED]

    def unresolved(self):
        """
        Everything about this candidate that could NOT be determined:
        unverifiable references plus anomalies.
        """
        unknowns = ["%s: %s" % (r.field, r.detail) for r in self.references
                    if r.status == ReferenceStatus.UNVERIFIABLE]
        unknowns.extend(self.anomalies)
        return unknowns

    def hexdump(self, width=16):
        """
        Hex dump of the evidence bytes, each line prefixed with the
        absolute file offset, for traceability.
        """
        data = self.raw_bytes()
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hexpart = " ".join("%02x" % (b) for b in bytearray(chunk))
            lines.append("0x%08x  %s" % (self.offset + i, hexpart))
        return "\n".join(lines)

    def __repr__(self):
        return "DeletedRecordCandidate(%s, name=%r, %s, at 0x%x)" % (
            self.record_type, self.name, self.status.value, self.offset)


class RejectedSignature(object):
    """
    An "nk"/"vk"-looking signature that failed validation. Recorded for
    auditability: a signature coincidence is not a recovery.
    """
    def __init__(self, buf, offset, cell_offset, signature, reasons):
        self._buf = buf
        self.offset = offset
        self.cell_offset = cell_offset
        self.signature = signature
        self.reasons = reasons

    def raw_bytes(self, length=0x20):
        return self._buf[self.offset:self.offset + length]

    def __repr__(self):
        return "RejectedSignature(%s at 0x%x: %s)" % (
            self.signature, self.offset, "; ".join(self.reasons))


class CarveReport(object):
    """
    The result of a DeletedRecordScanner scan.
    """
    def __init__(self, candidates, rejections, warnings):
        self.candidates = candidates
        self.rejections = rejections
        self.warnings = warnings

    def with_status(self, status):
        return [c for c in self.candidates if c.status == status]

    def reliable(self):
        return self.with_status(CandidateStatus.RELIABLE)

    def partial(self):
        return self.with_status(CandidateStatus.PARTIAL)

    def orphans(self):
        return self.with_status(CandidateStatus.ORPHAN)


class DeletedRecordScanner(object):
    """
    Read-only forensic scanner that carves deleted nk/vk record
    candidates from the free cells of a Windows Registry hive.

    This is an explicit opt-in forensic mode; it is not used by, and
    does not interfere with, the normal Registry.Registry active-tree
    traversal. The hive buffer is only ever read, never written.
    """
    def __init__(self, buf):
        """
        Constructor.
        Arguments:
        - `buf`: Byte string containing the Windows Registry file.
        """
        self._buf = buf

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls(f.read())

    @classmethod
    def from_registry(cls, registry):
        """
        Build a scanner over the same buffer a Registry.Registry
        instance was opened on. The registry object is not modified.
        """
        return cls(registry._buf)

    def scan(self):
        """
        Scan all free cells in all hbins and return a CarveReport.
        """
        buf = self._buf
        regf = REGFBlock(buf, 0, False)
        self._first_hbin = regf.first_hbin_offset()
        self._hbins_end = self._first_hbin + regf.hbins_size()

        cells = {}
        warnings = []
        for hbin in regf.hbins():
            try:
                for cell in hbin.cells():
                    cells[cell.offset()] = cell
            except (ParseException, struct.error) as e:
                warnings.append("hbin at 0x%x: cell walk failed: %s" %
                                (hbin.offset(), e))
        self._cells = cells

        candidates = []
        rejections = []
        for cell_offset in sorted(cells):
            cell = cells[cell_offset]
            if not cell.is_free():
                continue
            self._scan_free_cell(cell, candidates, rejections)

        self._link_candidates(candidates)
        return CarveReport(candidates, rejections, warnings)

    def _scan_free_cell(self, cell, candidates, rejections):
        """
        Scan one free cell at 8-byte aligned positions (record alignment)
        for nk/vk signatures. Positions covered by an accepted candidate
        are skipped; everything else that fails validation is recorded
        as a rejection with reasons.
        """
        data_start = cell.data_offset()
        data_end = min(cell.offset() + cell.size(), len(self._buf))
        covered = []

        pos = data_start
        while pos + 2 <= data_end:
            sig = self._buf[pos:pos + 2]
            if sig in (b"nk", b"vk") and \
                    not any(s <= pos < e for (s, e) in covered):
                if sig == b"nk":
                    result = self._validate_nk(pos, cell, data_end)
                else:
                    result = self._validate_vk(pos, cell, data_end)
                if isinstance(result, RejectedSignature):
                    rejections.append(result)
                else:
                    candidates.append(result)
                    covered.append((pos, pos + result.length))
            pos += 8

    def _resolve_cell_reference(self, field, field_offset, rel,
                                expected_ids=None, min_cell_size=0):
        """
        Verify that a hive-relative offset read at field_offset points to
        a real cell. Returns a Reference. A reference is VERIFIED only if
        the target is inside the hbins area, lands exactly on a known
        cell boundary, is large enough, and (optionally) contains the
        expected record signature. Anything else is UNVERIFIABLE with
        the reason recorded - typically an overwritten or reused cell.
        """
        target = self._first_hbin + rel
        if rel >= 0x80000000 or \
                not (self._first_hbin <= target < self._hbins_end):
            return Reference(field, field_offset, rel, target,
                             ReferenceStatus.UNVERIFIABLE,
                             "target 0x%x is outside the hbins area "
                             "(reference overwritten or corrupt)" % (target))
        cell = self._cells.get(target)
        if cell is None:
            return Reference(field, field_offset, rel, target,
                             ReferenceStatus.UNVERIFIABLE,
                             "target 0x%x is not a cell boundary "
                             "(cell reused or partially overwritten)" % (target))
        if cell.size() < min_cell_size:
            return Reference(field, field_offset, rel, target,
                             ReferenceStatus.UNVERIFIABLE,
                             "target cell at 0x%x is too small (0x%x bytes, "
                             "need 0x%x)" % (target, cell.size(), min_cell_size))
        if expected_ids is not None:
            data_id = self._buf[cell.data_offset():cell.data_offset() + 2]
            if data_id not in expected_ids:
                return Reference(field, field_offset, rel, target,
                                 ReferenceStatus.UNVERIFIABLE,
                                 "target cell at 0x%x does not contain the "
                                 "expected record (found %r)" %
                                 (target, data_id))
        state = "free" if cell.is_free() else "allocated"
        return Reference(field, field_offset, rel, target,
                         ReferenceStatus.VERIFIED,
                         "target cell at 0x%x (%s)" % (target, state))

    def _decode_name(self, raw, is_ascii, allow_backslash):
        """
        Decode a record name. Returns (name, error). error is None on
        success. Names with control characters (and backslashes for key
        names) are rejected as signature coincidences.
        """
        if is_ascii:
            try:
                name = raw.decode("windows-1252")
            except UnicodeDecodeError as e:
                return None, "name is not decodable as windows-1252: %s" % (e)
        else:
            if len(raw) % 2 != 0:
                return None, "unicode name has odd length 0x%x" % (len(raw))
            try:
                name = raw.decode("utf-16le")
            except UnicodeDecodeError as e:
                return None, "name is not decodable as utf-16le: %s" % (e)
        for c in name:
            if ord(c) < 0x20:
                return None, "name contains control characters"
        if not allow_backslash and "\\" in name:
            return None, "key name contains a backslash"
        return name, None

    def _validate_nk(self, offset, cell, data_end):
        buf = self._buf
        available = data_end - offset
        cell_offset = cell.offset()

        if available < NK_FIXED_SIZE:
            return DeletedRecordCandidate(
                buf, "nk", offset, cell_offset, CandidateStatus.ORPHAN, None,
                {}, [], ["truncated nk record: only 0x%x of 0x%x fixed "
                         "header bytes remain in the cell; the rest was "
                         "overwritten or the cell was reused" %
                         (max(available, 0), NK_FIXED_SIZE)],
                max(available, 0))

        def u16(o):
            return struct.unpack_from(str("<H"), buf, offset + o)[0]

        def u32(o):
            return struct.unpack_from(str("<I"), buf, offset + o)[0]

        def u64(o):
            return struct.unpack_from(str("<Q"), buf, offset + o)[0]

        flags = u16(0x2)
        timestamp_raw = u64(0x4)
        parent_rel = u32(0x10)
        subkey_count = u32(0x14)
        subkey_list_rel = u32(0x1C)
        values_count = u32(0x24)
        values_list_rel = u32(0x28)
        sk_rel = u32(0x2C)
        classname_rel = u32(0x30)
        name_length = u16(0x48)
        classname_length = u16(0x4A)

        if name_length == 0:
            return RejectedSignature(buf, offset, cell_offset, "nk",
                                     ["zero name length"])

        if available < NK_FIXED_SIZE + name_length:
            return DeletedRecordCandidate(
                buf, "nk", offset, cell_offset, CandidateStatus.ORPHAN, None,
                {"name_length": name_length}, [],
                ["truncated nk record: name of 0x%x bytes extends past the "
                 "end of the cell (0x%x bytes available); the cell was "
                 "partially reused" % (name_length, available)],
                available)

        name, error = self._decode_name(
            buf[offset + NK_FIXED_SIZE:offset + NK_FIXED_SIZE + name_length],
            flags & 0x20 != 0, allow_backslash=False)
        if error is not None:
            return RejectedSignature(buf, offset, cell_offset, "nk", [error])

        anomalies = []
        timestamp = None
        try:
            timestamp = parse_windows_timestamp(timestamp_raw)
            if not (_MIN_TIMESTAMP <= timestamp <=
                    datetime.datetime.now() + datetime.timedelta(days=366)):
                anomalies.append("implausible timestamp: %s" % (timestamp))
        except Exception:
            anomalies.append("timestamp 0x%x is not parseable" %
                             (timestamp_raw))

        fields = {
            "flags": flags,
            "timestamp": timestamp,
            "subkey_count": subkey_count,
            "values_count": values_count,
            "name_length": name_length,
            "classname_length": classname_length,
        }

        references = []
        if parent_rel != 0xFFFFFFFF:
            references.append(self._resolve_cell_reference(
                "parent_key", offset + 0x10, parent_rel,
                expected_ids=(b"nk",)))
        if subkey_count not in (0, 0xFFFFFFFF):
            references.append(self._resolve_cell_reference(
                "subkey_list", offset + 0x1C, subkey_list_rel,
                expected_ids=SUBKEY_LIST_IDS))
        if values_count not in (0, 0xFFFFFFFF):
            if values_count > 0xFFFF:
                anomalies.append("implausible values count 0x%x" %
                                 (values_count))
            else:
                ref = self._resolve_cell_reference(
                    "values_list", offset + 0x28, values_list_rel,
                    min_cell_size=4 * values_count + 4)
                references.append(ref)
                if ref.status == ReferenceStatus.VERIFIED:
                    vcell = self._cells[ref.target_offset]
                    for i in range(values_count):
                        entry_off = vcell.data_offset() + 4 * i
                        entry_rel = struct.unpack_from(
                            str("<I"), buf, entry_off)[0]
                        references.append(self._resolve_cell_reference(
                            "values_list[%d]" % (i), entry_off, entry_rel,
                            expected_ids=(b"vk",)))
        if sk_rel != 0xFFFFFFFF:
            references.append(self._resolve_cell_reference(
                "security", offset + 0x2C, sk_rel, expected_ids=(b"sk",)))
        if classname_length > 0:
            references.append(self._resolve_cell_reference(
                "classname", offset + 0x30, classname_rel,
                min_cell_size=classname_length + 4))

        if anomalies or any(r.status == ReferenceStatus.UNVERIFIABLE
                            for r in references):
            status = CandidateStatus.PARTIAL
        else:
            status = CandidateStatus.RELIABLE

        return DeletedRecordCandidate(
            buf, "nk", offset, cell_offset, status, name, fields,
            references, anomalies, NK_FIXED_SIZE + name_length)

    def _validate_vk(self, offset, cell, data_end):
        buf = self._buf
        available = data_end - offset
        cell_offset = cell.offset()

        if available < VK_FIXED_SIZE:
            return DeletedRecordCandidate(
                buf, "vk", offset, cell_offset, CandidateStatus.ORPHAN, None,
                {}, [], ["truncated vk record: only 0x%x of 0x%x fixed "
                         "header bytes remain in the cell; the rest was "
                         "overwritten or the cell was reused" %
                         (max(available, 0), VK_FIXED_SIZE)],
                max(available, 0))

        def u16(o):
            return struct.unpack_from(str("<H"), buf, offset + o)[0]

        def u32(o):
            return struct.unpack_from(str("<I"), buf, offset + o)[0]

        name_length = u16(0x2)
        raw_data_length = u32(0x4)
        data_rel = u32(0x8)
        data_type_raw = u32(0xC)
        flags = u16(0x10)

        if available < VK_FIXED_SIZE + name_length:
            return DeletedRecordCandidate(
                buf, "vk", offset, cell_offset, CandidateStatus.ORPHAN, None,
                {"name_length": name_length}, [],
                ["truncated vk record: name of 0x%x bytes extends past the "
                 "end of the cell (0x%x bytes available); the cell was "
                 "partially reused" % (name_length, available)],
                available)

        reasons = []
        name = ""
        if name_length > 0:
            name, error = self._decode_name(
                buf[offset + VK_FIXED_SIZE:
                    offset + VK_FIXED_SIZE + name_length],
                flags & 1 != 0, allow_backslash=True)
            if error is not None:
                reasons.append(error)

        data_type = data_type_raw & DEVPROP_MASK_TYPE
        if data_type not in KNOWN_DATA_TYPES:
            reasons.append("unknown data type 0x%x" % (data_type))

        references = []
        inline = raw_data_length >= 0x80000000 or raw_data_length < 5
        if raw_data_length >= 0x80000000:
            inline_length = raw_data_length - 0x80000000
            if inline_length > 4:
                reasons.append("inline data length 0x%x exceeds 4 bytes" %
                               (inline_length))
        if reasons:
            return RejectedSignature(buf, offset, cell_offset, "vk", reasons)

        if not inline:
            expected = (b"db",) if raw_data_length > 0x3fd8 else None
            references.append(self._resolve_cell_reference(
                "data", offset + 0x8, data_rel, expected_ids=expected,
                min_cell_size=raw_data_length + 4))

        fields = {
            "data_type": data_type,
            "data_length": (raw_data_length - 0x80000000
                            if raw_data_length >= 0x80000000
                            else raw_data_length),
            "inline_data": inline,
            "name_length": name_length,
        }

        if any(r.status == ReferenceStatus.UNVERIFIABLE for r in references):
            status = CandidateStatus.PARTIAL
        else:
            status = CandidateStatus.RELIABLE

        return DeletedRecordCandidate(
            buf, "vk", offset, cell_offset, status, name, fields,
            references, [], VK_FIXED_SIZE + name_length)

    def _link_candidates(self, candidates):
        """
        Cross-link candidates through VERIFIED offset references only.
        A deleted value is associated with a deleted key solely because
        the key's values list points at the value's cell offset - never
        because of matching names.
        """
        by_offset = {}
        for c in candidates:
            by_offset[c.offset] = c
            if c.offset == c.cell_offset + 4:
                # references target cell offsets, while candidate offsets
                # are record offsets (cell offset + 4)
                by_offset[c.cell_offset] = c
        for c in candidates:
            for ref in c.references:
                if ref.status == ReferenceStatus.VERIFIED and \
                        ref.target_offset in by_offset:
                    by_offset[ref.target_offset].referenced_by.append((c, ref))
