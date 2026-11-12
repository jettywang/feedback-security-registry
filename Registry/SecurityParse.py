#!/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
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

# Added for python2-3 compatibility
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import struct

from .RegistryParse import (
    ParseException,
    NotSupportedException,
    RegistryStructureDoesNotExist,
)


# ---------------------------------------------------------------------------
# Constants
#
# These describe the on-disk, self-relative SECURITY_DESCRIPTOR and its
# ACL / ACE / SID structures. Nothing here performs Windows effective
# permission (access-check) computation; the values are presented exactly as
# found in the hive.
# ---------------------------------------------------------------------------

SECURITY_DESCRIPTOR_REVISION = 0x01
SECURITY_DESCRIPTOR_HEADER_SIZE = 0x14
ACL_HEADER_SIZE = 0x08
ACE_HEADER_SIZE = 0x04

# SECURITY_DESCRIPTOR_CONTROL bit flags.
SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_RM_CONTROL_VALID = 0x4000
SE_SELF_RELATIVE = 0x8000

SECURITY_DESCRIPTOR_CONTROL_FLAGS = [
    (SE_OWNER_DEFAULTED, "OWNER_DEFAULTED"),
    (SE_GROUP_DEFAULTED, "GROUP_DEFAULTED"),
    (SE_DACL_PRESENT, "DACL_PRESENT"),
    (SE_DACL_DEFAULTED, "DACL_DEFAULTED"),
    (SE_SACL_PRESENT, "SACL_PRESENT"),
    (SE_SACL_DEFAULTED, "SACL_DEFAULTED"),
    (SE_DACL_AUTO_INHERITED, "DACL_AUTO_INHERITED"),
    (SE_SACL_AUTO_INHERITED, "SACL_AUTO_INHERITED"),
    (SE_DACL_PROTECTED, "DACL_PROTECTED"),
    (SE_SACL_PROTECTED, "SACL_PROTECTED"),
    (SE_RM_CONTROL_VALID, "RM_CONTROL_VALID"),
    (SE_SELF_RELATIVE, "SELF_RELATIVE"),
]

# ACE types defined for NT security descriptors.
ACE_TYPE_NAMES = {
    0x00: "ACCESS_ALLOWED",
    0x01: "ACCESS_DENIED",
    0x02: "SYSTEM_AUDIT",
    0x03: "SYSTEM_ALARM",
    0x04: "ACCESS_ALLOWED_COMPOUND",
    0x05: "ACCESS_ALLOWED_OBJECT",
    0x06: "ACCESS_DENIED_OBJECT",
    0x07: "SYSTEM_AUDIT_OBJECT",
    0x08: "SYSTEM_ALARM_OBJECT",
    0x09: "ACCESS_ALLOWED_CALLBACK",
    0x0A: "ACCESS_DENIED_CALLBACK",
    0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
    0x0D: "SYSTEM_AUDIT_CALLBACK",
    0x0E: "SYSTEM_ALARM_CALLBACK",
    0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
    0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",
    0x11: "SYSTEM_MANDATORY_LABEL",
    0x12: "SYSTEM_RESOURCE_ATTRIBUTE",
    0x13: "SYSTEM_SCOPED_POLICY_ID",
}

# ACE types whose body carries object-specific GUID fields.
OBJECT_ACE_TYPES = frozenset([
    0x05, 0x06, 0x07, 0x08,
    0x0B, 0x0C, 0x0F, 0x10,
])

ACE_FLAG_NAMES = [
    (0x01, "OBJECT_INHERIT"),
    (0x02, "CONTAINER_INHERIT"),
    (0x04, "NO_PROPAGATE_INHERIT"),
    (0x08, "INHERIT_ONLY"),
    (0x10, "INHERITED"),
    (0x20, "SUCCESSFUL_ACCESS"),
    (0x40, "FAILED_ACCESS"),
]

# Access mask bit decoding (generic and standard rights).
ACCESS_MASK_NAMES = [
    (0x80000000, "GENERIC_READ"),
    (0x40000000, "GENERIC_WRITE"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x10000000, "GENERIC_ALL"),
    (0x02000000, "MAXIMUM_ALLOWED"),
    (0x01000000, "ACCESS_SYSTEM_SECURITY"),
    (0x00100000, "SYNCHRONIZE"),
    (0x00080000, "WRITE_OWNER"),
    (0x00040000, "WRITE_DAC"),
    (0x00020000, "READ_CONTROL"),
    (0x00010000, "DELETE"),
]

# Registry key specific access rights (low 16 bits).
REGISTRY_ACCESS_BIT_NAMES = [
    (0x0001, "KEY_QUERY_VALUE"),
    (0x0002, "KEY_SET_VALUE"),
    (0x0004, "KEY_CREATE_SUB_KEY"),
    (0x0008, "KEY_ENUMERATE_SUB_KEYS"),
    (0x0010, "KEY_NOTIFY"),
    (0x0020, "KEY_CREATE_LINK"),
    (0x1000, "KEY_WOW64_64KEY"),
    (0x2000, "KEY_WOW64_32KEY"),
]

# Composite registry rights, reported only when every constituent bit is set.
# KEY_READ and KEY_EXECUTE share an identical mask, so both names are emitted.
REGISTRY_ACCESS_COMPOSITE_NAMES = [
    (0x000F001F, "KEY_ALL_ACCESS"),
    (0x00020019, "KEY_READ"),
    (0x00020006, "KEY_WRITE"),
    (0x00020019, "KEY_EXECUTE"),
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SecurityEvidenceError(ParseException):
    """
    Base class for problems encountered while collecting security descriptor
    evidence. The evidence collector never raises this directly; problems are
    recorded as anomalies or unsupported items so that a bad record cannot
    leak into another key's display.
    """
    def __init__(self, value):
        super(SecurityEvidenceError, self).__init__(value)

    def __str__(self):
        return "Security evidence error: %s" % (self._value)


class StructuralAnomaly(SecurityEvidenceError):
    """
    Raised when a structure is present but malformed (bad offsets, truncated
    data, mismatched sizes or reference counts).
    """
    def __str__(self):
        return "Structural anomaly: %s" % (self._value)


class UnsupportedSecurityStructure(SecurityEvidenceError, NotSupportedException):
    """
    Raised when a structure is well-formed but uses a type this library does
    not know how to decode (for example an unknown ACE type).
    """
    def __str__(self):
        return "Unsupported security structure: %s" % (self._value)


# ---------------------------------------------------------------------------
# Evidence containers
#
# Every container retains the absolute file offset at which the structure was
# found and the raw bytes covering it, so a forensic report can independently
# verify the parsed facts.
# ---------------------------------------------------------------------------

class EvidenceItem(object):
    """
    Base class for collected evidence.

    Fields:
    - `offset`: absolute byte offset of the structure within the hive buffer.
    - `raw_bytes`: the exact bytes covering this structure.
    - `anomalies`: list of human readable structural problems.
    - `unsupported`: list of human readable items this library cannot decode.
    """
    def __init__(self, offset, raw_bytes):
        self.offset = offset
        self.raw_bytes = raw_bytes
        self.anomalies = []
        self.unsupported = []


class SidEvidence(EvidenceItem):
    """
    A decoded Windows SID (security identifier).

    Fields:
    - `revision`: the SID revision byte (normally 1).
    - `authority`: 6-byte identifier authority rendered as an integer.
    - `subauthorities`: list of 32-bit relative identifier sub-authorities.
    - `sid`: conventional "S-R-I-S-S..." string form.
    """
    def __init__(self, offset, raw_bytes, revision, authority, subauthorities):
        super(SidEvidence, self).__init__(offset, raw_bytes)
        self.revision = revision
        self.authority = authority
        self.subauthorities = subauthorities
        self.sid = self._render()

    def _render(self):
        parts = ["S", str(self.revision), str(self.authority)]
        parts.extend([str(s) for s in self.subauthorities])
        return "-".join(parts)

    def __str__(self):
        return self.sid


class AceEvidence(EvidenceItem):
    """
    A single Access Control Entry.

    Fields:
    - `ace_type`: numeric ACE type byte.
    - `ace_type_name`: symbolic name, or None for an unknown type.
    - `ace_flags`: raw ACE flags byte.
    - `ace_flag_names`: decoded flag names.
    - `size`: ACE size in bytes as declared by the record.
    - `access_mask`: raw 32-bit access mask.
    - `access_right_names`: symbolic names covering the set bits (best effort).
    - `sid`: SidEvidence for a simple ACE, or None.
    - `object_guid` / `inherit_object_guid`: GUID strings for object ACEs,
      or None when the corresponding inherited/object flags are clear.
    - `extra_data`: callback / application data trailing an object or
      callback ACE, kept as raw bytes.
    """
    def __init__(self, offset, raw_bytes, ace_type, ace_type_name, ace_flags,
                 ace_flag_names, size, access_mask, access_right_names,
                 sid, object_guid, inherit_object_guid, extra_data):
        super(AceEvidence, self).__init__(offset, raw_bytes)
        self.ace_type = ace_type
        self.ace_type_name = ace_type_name
        self.ace_flags = ace_flags
        self.ace_flag_names = ace_flag_names
        self.size = size
        self.access_mask = access_mask
        self.access_right_names = access_right_names
        self.sid = sid
        self.object_guid = object_guid
        self.inherit_object_guid = inherit_object_guid
        self.extra_data = extra_data

    def is_known_type(self):
        return self.ace_type in ACE_TYPE_NAMES

    def __str__(self):
        name = self.ace_type_name if self.ace_type_name is not None \
            else "UNKNOWN_0x%02X" % (self.ace_type)
        return "ACE(%s, mask=0x%08X) at 0x%x" % (name, self.access_mask, self.offset)


class AclEvidence(EvidenceItem):
    """
    A DACL or SACL.

    The presence distinction is made by the caller using the control bits:
    a missing ACL (control bit clear) never produces an AclEvidence, while an
    empty but present ACL yields `aces == []`.

    Fields:
    - `revision`: ACL revision byte.
    - `aces`: list of AceEvidence, in stored order.
    """
    def __init__(self, offset, raw_bytes, revision, aces):
        super(AclEvidence, self).__init__(offset, raw_bytes)
        self.revision = revision
        self.aces = aces

    def is_empty(self):
        return len(self.aces) == 0

    def __str__(self):
        return "ACL(revision=%d, %d ACEs) at 0x%x" % \
            (self.revision, len(self.aces), self.offset)


class SecurityDescriptorEvidence(EvidenceItem):
    """
    The parsed self-relative security descriptor embedded in an SK record.

    Fields:
    - `revision`: security descriptor revision byte.
    - `control`: raw 16-bit control mask.
    - `control_flags`: decoded control flag names.
    - `owner` / `group`: SidEvidence or None when the pointer is absent.
    - `dacl` / `sacl`: AclEvidence or None. None means the corresponding
      "*_PRESENT" control bit is clear (or the pointer could not be followed);
      an empty ACL is represented by a non-None AclEvidence with no ACEs.
    - `dacl_present` / `sacl_present`: booleans taken directly from the
      control mask, so missing vs empty DACL are never conflated.
    """
    def __init__(self, offset, raw_bytes, revision, control, control_flags,
                 owner, group, dacl, sacl, dacl_present, sacl_present):
        super(SecurityDescriptorEvidence, self).__init__(offset, raw_bytes)
        self.revision = revision
        self.control = control
        self.control_flags = control_flags
        self.owner = owner
        self.group = group
        self.dacl = dacl
        self.sacl = sacl
        self.dacl_present = dacl_present
        self.sacl_present = sacl_present

    def __str__(self):
        return "SecurityDescriptor(control=0x%04X) at 0x%x" % \
            (self.control, self.offset)


class SecurityEvidence(EvidenceItem):
    """
    Top-level evidence object describing exactly what one registry key (NK
    record) declares through its reference to a shared SK record.

    Fields:
    - `key_path`: NK path for labelling (may be empty if unavailable).
    - `nk_offset`: absolute offset of the referencing NK record.
    - `sk_reference_offset`: raw relative SK pointer stored in the NK record.
    - `sk_cell_offset`: absolute offset of the referenced SK cell, or None if
      the pointer could not be followed.
    - `sk_offset`: absolute offset of the SK record data, or None.
    - `declared_reference_count`: usage counter value stored in the SK record,
      or None if the SK record could not be read.
    - `observed_reference_count`: number of NK records in the hive that point
      at this SK cell (computed independently of the stored counter).
    - `reference_count_consistent`: None when it cannot be evaluated,
      otherwise True/False.
    - `descriptor`: SecurityDescriptorEvidence, or None when the descriptor
      could not be parsed at all.
    """
    def __init__(self, key_path, nk_offset, sk_reference_offset):
        super(SecurityEvidence, self).__init__(nk_offset, b"")
        self.key_path = key_path
        self.nk_offset = nk_offset
        self.sk_reference_offset = sk_reference_offset
        self.sk_cell_offset = None
        self.sk_offset = None
        self.declared_reference_count = None
        self.observed_reference_count = None
        self.reference_count_consistent = None
        self.descriptor = None

    def has_usable_descriptor(self):
        return self.descriptor is not None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_control_flags(control):
    return [name for (bit, name) in SECURITY_DESCRIPTOR_CONTROL_FLAGS
            if control & bit]


def _decode_ace_flags(flags):
    return [name for (bit, name) in ACE_FLAG_NAMES if flags & bit]


def _decode_access_mask(mask):
    """
    Best-effort symbolic decoding of an access mask. The raw mask is always
    retained; names are only a convenience and generic mapping (the Windows
    generic-rights expansion) is deliberately not performed, since that would
    constitute access-check logic rather than evidence presentation.
    """
    names = []
    for (bit, name) in ACCESS_MASK_NAMES:
        if mask & bit and name not in names:
            names.append(name)
    for (bit, name) in REGISTRY_ACCESS_BIT_NAMES:
        if mask & bit and name not in names:
            names.append(name)
    for (bit, name) in REGISTRY_ACCESS_COMPOSITE_NAMES:
        if (mask & bit) == bit and name not in names:
            names.append(name)
    return names


def _safe_read(buf, absolute_offset, length, what):
    """
    Bounds-checked read from the hive buffer. Raises StructuralAnomaly when
    the requested span does not fit entirely inside the buffer.
    """
    if absolute_offset < 0 or length < 0:
        raise StructuralAnomaly(
            "%s has negative offset/length (offset=0x%x length=%d)" %
            (what, absolute_offset, length))
    end = absolute_offset + length
    if end > len(buf):
        raise StructuralAnomaly(
            "%s at 0x%x with length %d overruns hive buffer "
            "(end=0x%x, size=0x%x)" %
            (what, absolute_offset, length, end, len(buf)))
    return buf[absolute_offset:end]


def _parse_sid(buf, absolute_offset, bounds_end, what):
    """
    Parse a SID starting at `absolute_offset`, which must lie within
    `bounds_end`. Returns SidEvidence.
    """
    header = _safe_read(buf, absolute_offset, 8, what + " header")
    if absolute_offset + 8 > bounds_end:
        raise StructuralAnomaly(
            "%s header at 0x%x overruns enclosing structure (end=0x%x)" %
            (what, absolute_offset, bounds_end))
    revision = struct.unpack_from(str("<B"), header, 0)[0]
    sub_count = struct.unpack_from(str("<B"), header, 1)[0]
    authority = struct.unpack_from(str(">Q"), b"\x00\x00" + header[2:8])[0]
    sid_size = 8 + sub_count * 4
    raw = _safe_read(buf, absolute_offset, sid_size, what)
    if absolute_offset + sid_size > bounds_end:
        raise StructuralAnomaly(
            "%s at 0x%x (sub-authorities=%d) overruns enclosing structure "
            "(end=0x%x)" % (what, absolute_offset, sub_count, bounds_end))
    subauthorities = []
    for index in range(sub_count):
        sub = struct.unpack_from(str("<I"), raw, 8 + index * 4)[0]
        subauthorities.append(sub)
    return SidEvidence(absolute_offset, raw, revision, authority, subauthorities)


def _guid_to_string(raw):
    # mixed-endian GUID: three little-endian fields then 8 bytes.
    d1, d2, d3 = struct.unpack_from(str("<IHH"), raw, 0)
    tail = raw[8:16]
    return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
        d1, d2, d3,
        tail[0], tail[1], tail[2], tail[3],
        tail[4], tail[5], tail[6], tail[7])


def _parse_ace(buf, absolute_offset, acl_end):
    """
    Parse one ACE. Unknown types produce an AceEvidence carrying the raw
    bytes and an `unsupported` entry rather than aborting the whole ACL.
    Truncated ACEs raise StructuralAnomaly.
    """
    header = _safe_read(buf, absolute_offset, ACE_HEADER_SIZE, "ACE header")
    if absolute_offset + ACE_HEADER_SIZE > acl_end:
        raise StructuralAnomaly(
            "ACE header at 0x%x overruns ACL (end=0x%x)" %
            (absolute_offset, acl_end))
    ace_type = struct.unpack_from(str("<B"), header, 0)[0]
    ace_flags = struct.unpack_from(str("<B"), header, 1)[0]
    ace_size = struct.unpack_from(str("<H"), header, 2)[0]

    if ace_size < ACE_HEADER_SIZE:
        raise StructuralAnomaly(
            "ACE at 0x%x declares size %d smaller than ACE header (%d)" %
            (absolute_offset, ace_size, ACE_HEADER_SIZE))
    if absolute_offset + ace_size > acl_end:
        raise StructuralAnomaly(
            "ACE at 0x%x declares size %d that overruns its ACL "
            "(end=0x%x)" % (absolute_offset, ace_size, acl_end))
    raw = _safe_read(buf, absolute_offset, ace_size, "ACE body")

    ace_type_name = ACE_TYPE_NAMES.get(ace_type)
    flag_names = _decode_ace_flags(ace_flags)
    evidence = AceEvidence(
        absolute_offset, raw, ace_type, ace_type_name, ace_flags,
        flag_names, ace_size, 0, [], None, None, None, b"")

    if ace_type_name is None:
        evidence.unsupported.append(
            "ACE type 0x%02X at 0x%x is not recognized; %d raw bytes retained"
            % (ace_type, absolute_offset, ace_size))
        return evidence

    body_offset = absolute_offset + ACE_HEADER_SIZE
    if ace_type in OBJECT_ACE_TYPES:
        # Object ACE: flags, mask, optional GUIDs, then SID, then extra data.
        if ace_size < ACE_HEADER_SIZE + 12:
            raise StructuralAnomaly(
                "object ACE at 0x%x too small for mask and object flags" %
                (absolute_offset))
        object_flags = struct.unpack_from(str("<I"), raw, 4)[0]
        access_mask = struct.unpack_from(str("<I"), raw, 8)[0]
        # Cursor is relative to the ACE start; header is 4 bytes, object
        # flags and access mask occupy raw[4:12].
        cursor = 12
        object_guid = None
        inherit_object_guid = None
        if object_flags & 0x00000001:  # ACE_OBJECT_TYPE_PRESENT
            if cursor + 16 > ace_size:
                raise StructuralAnomaly(
                    "object ACE at 0x%x missing object type GUID" %
                    (absolute_offset))
            object_guid = _guid_to_string(raw[cursor:cursor + 16])
            cursor += 16
        if object_flags & 0x00000002:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
            if cursor + 16 > ace_size:
                raise StructuralAnomaly(
                    "object ACE at 0x%x missing inherited object type GUID" %
                    (absolute_offset))
            inherit_object_guid = _guid_to_string(raw[cursor:cursor + 16])
            cursor += 16
        sid_abs = absolute_offset + cursor
        ace_end = absolute_offset + ace_size
        sid = _parse_sid(buf, sid_abs, ace_end,
                         "SID in object ACE at 0x%x" % (absolute_offset))
        sid_end = sid_abs + len(sid.raw_bytes)
        extra = buf[sid_abs:ace_end][len(sid.raw_bytes):]
        evidence.access_mask = access_mask
        evidence.access_right_names = _decode_access_mask(access_mask)
        evidence.object_guid = object_guid
        evidence.inherit_object_guid = inherit_object_guid
        evidence.sid = sid
        evidence.extra_data = extra
    else:
        # Simple ACE: 4-byte access mask followed by a SID, optional extra
        # data is only defined for callback ACE variants.
        if ace_size < ACE_HEADER_SIZE + 8:
            raise StructuralAnomaly(
                "ACE at 0x%x too small for access mask and SID" %
                (absolute_offset))
        access_mask = struct.unpack_from(str("<I"), raw, 4)[0]
        sid_abs = body_offset + 4
        ace_end = absolute_offset + ace_size
        sid = _parse_sid(buf, sid_abs, ace_end,
                         "SID in ACE at 0x%x" % (absolute_offset))
        sid_end = sid_abs + len(sid.raw_bytes)
        extra = buf[sid_end:ace_end]
        evidence.access_mask = access_mask
        evidence.access_right_names = _decode_access_mask(access_mask)
        evidence.sid = sid
        evidence.extra_data = extra
    return evidence


def _parse_acl(buf, absolute_offset, bounds_end, what):
    """
    Parse an ACL structure at `absolute_offset`. `bounds_end` limits every
    nested ACE so an out-of-bounds ACE is reported, not trusted.
    A present but empty ACL (zero ACE count) returns an AclEvidence with no
    ACEs; this is distinct from a missing ACL pointer.
    """
    header = _safe_read(buf, absolute_offset, ACL_HEADER_SIZE, what + " header")
    if absolute_offset + ACL_HEADER_SIZE > bounds_end:
        raise StructuralAnomaly(
            "%s header at 0x%x overruns enclosing structure (end=0x%x)" %
            (what, absolute_offset, bounds_end))
    revision = struct.unpack_from(str("<B"), header, 0)[0]
    ace_count = struct.unpack_from(str("<H"), header, 4)[0]
    acl_size = struct.unpack_from(str("<H"), header, 2)[0]
    if acl_size < ACL_HEADER_SIZE:
        raise StructuralAnomaly(
            "%s at 0x%x declares size %d smaller than ACL header" %
            (what, absolute_offset, acl_size))
    acl_end = absolute_offset + acl_size
    if acl_end > bounds_end:
        raise StructuralAnomaly(
            "%s at 0x%x (size %d) overruns enclosing structure (end=0x%x)" %
            (what, absolute_offset, acl_size, bounds_end))
    raw = _safe_read(buf, absolute_offset, acl_size, what)

    evidence = AclEvidence(absolute_offset, raw, revision, [])
    cursor = absolute_offset + ACL_HEADER_SIZE
    # Guard against absurd counts even when individual ACEs are valid.
    max_aces = max(ace_count, 0)
    for index in range(max_aces):
        try:
            ace = _parse_ace(buf, cursor, acl_end)
        except StructuralAnomaly as exc:
            evidence.anomalies.append(str(exc))
            break
        evidence.aces.append(ace)
        for note in ace.anomalies:
            evidence.anomalies.append(note)
        for note in ace.unsupported:
            evidence.unsupported.append(note)
        cursor += ace.size
        if cursor > acl_end:
            evidence.anomalies.append(
                "ACE chain in %s at 0x%x runs past declared ACL size" %
                (what, absolute_offset))
            break
        if index < max_aces - 1 and cursor == acl_end:
            evidence.anomalies.append(
                "%s at 0x%x declares %d ACEs but only %d fit before its end" %
                (what, absolute_offset, ace_count, index + 1))
            break
    return evidence


def parse_security_descriptor(buf, absolute_offset, expected_length=None):
    """
    Parse a self-relative SECURITY_DESCRIPTOR located at `absolute_offset`
    in `buf`. Returns SecurityDescriptorEvidence.

    Structural problems and unsupported sub-structures are attached to the
    returned object's `anomalies` / `unsupported` lists instead of being
    raised, so callers always receive a coherent object.
    """
    header = _safe_read(buf, absolute_offset, SECURITY_DESCRIPTOR_HEADER_SIZE,
                        "security descriptor header")
    raw = header
    if expected_length is not None:
        raw = _safe_read(buf, absolute_offset, expected_length,
                         "security descriptor body")
    evidence = SecurityDescriptorEvidence(
        absolute_offset, raw, 0, 0, [], None, None, None, None, False, False)
    try:
        revision = struct.unpack_from(str("<B"), header, 0)[0]
        control = struct.unpack_from(str("<H"), header, 2)[0]
        owner_off = struct.unpack_from(str("<I"), header, 4)[0]
        group_off = struct.unpack_from(str("<I"), header, 8)[0]
        dacl_off = struct.unpack_from(str("<I"), header, 12)[0]
        sacl_off = struct.unpack_from(str("<I"), header, 16)[0]
        evidence.revision = revision
        evidence.control = control
        evidence.control_flags = _decode_control_flags(control)
        evidence.dacl_present = bool(control & SE_DACL_PRESENT)
        evidence.sacl_present = bool(control & SE_SACL_PRESENT)

        if not (control & SE_SELF_RELATIVE):
            evidence.anomalies.append(
                "security descriptor at 0x%x does not set the self-relative "
                "bit (control=0x%04X); registry SK records must be "
                "self-relative" % (absolute_offset, control))

        # Bounds: trust the explicit length when given (SK cell), otherwise
        # the remainder of the hive buffer is the only limit available.
        bounds_end = (absolute_offset + expected_length
                      if expected_length is not None else len(buf))

        def _follow(rel, parser, label, required):
            if rel == 0:
                if required:
                    evidence.anomalies.append(
                        "%s present per control bits but offset is zero" %
                        (label))
                return None
            target = absolute_offset + rel
            if target < 0 or target >= bounds_end:
                evidence.anomalies.append(
                    "%s relative offset 0x%x resolves to 0x%x outside the "
                    "descriptor (end=0x%x)" %
                    (label, rel, target, bounds_end))
                return None
            try:
                return parser(target)
            except StructuralAnomaly as exc:
                evidence.anomalies.append(str(exc))
                return None

        evidence.owner = _follow(
            owner_off,
            lambda t: _parse_sid(buf, t, bounds_end, "owner SID"),
            "owner", False)
        evidence.group = _follow(
            group_off,
            lambda t: _parse_sid(buf, t, bounds_end, "group SID"),
            "group", False)
        evidence.dacl = _follow(
            dacl_off,
            lambda t: _parse_acl(buf, t, bounds_end, "DACL"),
            "DACL", evidence.dacl_present)
        evidence.sacl = _follow(
            sacl_off,
            lambda t: _parse_acl(buf, t, bounds_end, "SACL"),
            "SACL", evidence.sacl_present)

        # A present control bit with a null pointer must not be mistaken for
        # an empty (but valid) ACL.
        if evidence.dacl_present and evidence.dacl is None:
            evidence.anomalies.append(
                "DACL is marked present but could not be parsed; it is not an "
                "empty DACL")
        if evidence.sacl_present and evidence.sacl is None:
            evidence.anomalies.append(
                "SACL is marked present but could not be parsed")

        # Roll child ACL notes up so a report can read one list on the
        # descriptor while the per-ACL lists retain their own context.
        for acl in (evidence.dacl, evidence.sacl):
            if acl is None:
                continue
            for note in acl.anomalies:
                if note not in evidence.anomalies:
                    evidence.anomalies.append(note)
            for note in acl.unsupported:
                if note not in evidence.unsupported:
                    evidence.unsupported.append(note)
    except StructuralAnomaly as exc:
        evidence.anomalies.append(str(exc))
    return evidence


# ---------------------------------------------------------------------------
# Orchestration: NK record -> shared SK record -> security descriptor
# ---------------------------------------------------------------------------

def _find_regf(block):
    current = block
    seen = set()
    while current is not None and current is not False:
        name = current.__class__.__name__
        if name == "REGFBlock":
            return current
        ident = id(current)
        if ident in seen:
            return None
        seen.add(ident)
        current = current.parent()
    return None


def _observed_reference_count(regf, sk_relative):
    if regf is None:
        return None
    count = 0
    try:
        for (_nk, referenced) in regf.sk_references():
            if referenced == sk_relative:
                count += 1
    except Exception:  # pragma: no cover - defensive: scan must not crash
        return None
    return count


def extract_security_evidence(nk_record):
    """
    Follow the real NK -> SK reference and collect everything it declares.

    The returned SecurityEvidence is specific to the supplied NK record: a
    fresh object is always allocated, so a failure on one key can never cause
    a later key to display another key's permissions. Problems are reported
    via `anomalies` / `unsupported`; this routine does not raise for corrupt
    registry structures (only for programmer errors such as a wrong argument
    type).

    Arguments:
    - `nk_record`: a RegistryParse.NKRecord.

    Returns:
    - SecurityEvidence
    """
    if nk_record.__class__.__name__ != "NKRecord":
        raise TypeError(
            "extract_security_evidence expects an NKRecord, got %s" %
            (nk_record.__class__.__name__))

    buf = nk_record._buf
    raw_sk_relative = nk_record.sk_offset()
    try:
        key_path = nk_record.path()
    except Exception:
        key_path = ""

    evidence = SecurityEvidence(key_path, nk_record.offset(), raw_sk_relative)

    # 1. Resolve the reference to an absolute cell inside the hive.
    # All HBIN-relative offsets are anchored at the first HBIN, whose buffer
    # offset is fixed at 0x1000 by the registry file format.
    first_hbin = 0x1000
    sk_cell_absolute = first_hbin + raw_sk_relative
    if sk_cell_absolute < first_hbin or sk_cell_absolute + 4 > len(buf):
        evidence.anomalies.append(
            "NK record at 0x%x holds SK relative offset 0x%x that resolves "
            "to 0x%x outside the hive buffer (size 0x%x); no security "
            "descriptor can be attributed to this key" %
            (nk_record.offset(), raw_sk_relative, sk_cell_absolute, len(buf)))
        return evidence
    evidence.sk_cell_offset = sk_cell_absolute

    # Import locally to avoid a circular import at module load time.
    from .RegistryParse import HBINCell, SKRecord

    # 2. Validate the cell and the SK record signature.
    try:
        cell = HBINCell(buf, sk_cell_absolute, nk_record.parent())
        if cell.is_free():
            evidence.anomalies.append(
                "NK record at 0x%x references free cell at 0x%x; no "
                "security descriptor available" %
                (nk_record.offset(), sk_cell_absolute))
            return evidence
        sk = SKRecord(buf, cell.data_offset(), cell)
    except RegistryStructureDoesNotExist as exc:
        evidence.anomalies.append(
            "SK reference at 0x%x cannot be read: %s" %
            (sk_cell_absolute, exc))
        return evidence
    except ParseException as exc:
        evidence.anomalies.append(
            "cell at 0x%x is not a valid SK record: %s" %
            (sk_cell_absolute, exc))
        return evidence

    evidence.sk_offset = sk.offset()

    # 3. Reference-count cross-check (stored counter vs independently counted
    #    NK pointers), reported as a fact, never "repaired".
    evidence.declared_reference_count = sk.reference_count()
    regf = _find_regf(sk)
    evidence.observed_reference_count = _observed_reference_count(
        regf, raw_sk_relative)
    if evidence.observed_reference_count is not None:
        evidence.reference_count_consistent = (
            evidence.declared_reference_count ==
            evidence.observed_reference_count)
        if not evidence.reference_count_consistent:
            evidence.anomalies.append(
                "SK usage counter inconsistency: record at 0x%x declares %d "
                "reference(s), but %d NK record(s) in the hive point at it" %
                (sk.offset(), evidence.declared_reference_count,
                 evidence.observed_reference_count))

    # 4. Locate and bound the embedded self-relative security descriptor.
    try:
        descriptor_length = sk.descriptor_size()
    except struct.error:
        evidence.anomalies.append(
            "SK record at 0x%x is truncated before its descriptor size field" %
            (sk.offset()))
        return evidence

    descriptor_absolute = sk.descriptor_offset()
    if descriptor_length == 0:
        evidence.anomalies.append(
            "SK record at 0x%x declares a zero-length security descriptor" %
            (sk.offset()))
        return evidence
    if descriptor_absolute + descriptor_length > len(buf):
        evidence.anomalies.append(
            "security descriptor at 0x%x with declared size %d overruns the "
            "hive buffer (end=0x%x, size=0x%x)" %
            (descriptor_absolute, descriptor_length,
             descriptor_absolute + descriptor_length, len(buf)))
        return evidence

    descriptor = parse_security_descriptor(
        buf, descriptor_absolute, descriptor_length)
    # Roll descriptor-level problems (already including nested ACL/ACE notes)
    # up to the per-key evidence object. The descriptor keeps its own lists
    # untouched so both views remain independently inspectable.
    for note in descriptor.anomalies:
        if note not in evidence.anomalies:
            evidence.anomalies.append(note)
    for note in descriptor.unsupported:
        if note not in evidence.unsupported:
            evidence.unsupported.append(note)
    evidence.descriptor = descriptor
    return evidence
