#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
reg_security.py

Export security descriptor evidence for every key in a Windows Registry hive.

This is an evidence renderer, not an access checker. For each NK record it
follows the real NK -> SK reference to the shared security record and reports:
  * the owner and group SIDs,
  * whether a DACL / SACL is present, and whether present ACLs are empty,
  * every ACE that can be parsed (type, flags, access mask, trustee SID),
  * the raw bytes and absolute offsets of each structure,
  * structural anomalies and unsupported structures in separate sections.

Missing and empty DACLs are deliberately distinguished, and a corrupt record
affects only the key that references it.

Usage:
    python reg_security.py <registry hive>
"""
from __future__ import print_function
from __future__ import absolute_import

import sys
import binascii

from Registry import Registry


def _hex(data, width=16):
    lines = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        lines.append("      0x%08x  %s" %
                     (start, binascii.hexlify(chunk).decode("ascii")))
    return "\n".join(lines) if lines else "      (empty)"


def _walk(key):
    yield key
    for subkey in key.subkeys():
        for item in _walk(subkey):
            yield item


def _print_acl(label, acl, present):
    if not present:
        print("  %s: ABSENT (control bit clear; no ACL pointer)" % label)
        return
    if acl is None:
        print("  %s: PRESENT per control bits but unparseable (see anomalies)"
              % label)
        return
    if acl.is_empty():
        print("  %s: PRESENT and EMPTY (0 ACEs) at 0x%x, revision %d" %
              (label, acl.offset, acl.revision))
        return
    print("  %s: PRESENT, %d ACE(s) at 0x%x, revision %d" %
          (label, len(acl.aces), acl.offset, acl.revision))
    for ace in acl.aces:
        type_name = ace.ace_type_name or ("UNKNOWN_0x%02X" % ace.ace_type)
        trustee = ace.sid.sid if ace.sid is not None else "(no SID decoded)"
        print("      ACE 0x%x  %-24s flags=0x%02X %-30s mask=0x%08X  %s" %
              (ace.offset, type_name, ace.ace_flags,
               ",".join(ace.ace_flag_names) or "-", ace.access_mask,
               trustee))
        if ace.access_right_names:
            print("             rights: %s" %
                  ", ".join(ace.access_right_names))
        if ace.object_guid or ace.inherit_object_guid:
            print("             object GUID=%s inherit GUID=%s" %
                  (ace.object_guid, ace.inherit_object_guid))


def report(evidence):
    print("=" * 78)
    print("Key: %s" % evidence.key_path)
    print("  NK record offset : 0x%x" % evidence.nk_offset)
    print("  SK pointer (raw) : 0x%x" % evidence.sk_reference_offset)
    if evidence.sk_cell_offset is None:
        print("  SK cell          : UNRESOLVABLE")
    else:
        print("  SK cell offset   : 0x%x" % evidence.sk_cell_offset)
        print("  SK record offset : 0x%s" %
              ("(none)" if evidence.sk_offset is None
               else ("%x" % evidence.sk_offset)))
    if evidence.declared_reference_count is not None:
        print("  SK usage counter : declared=%s observed=%s consistent=%s" %
              (evidence.declared_reference_count,
               evidence.observed_reference_count,
               evidence.reference_count_consistent))

    descriptor = evidence.descriptor
    if descriptor is None:
        print("  Security descriptor: NONE ATTRIBUTED TO THIS KEY")
    else:
        print("  Descriptor offset: 0x%x  revision=%d  control=0x%04X [%s]" %
              (descriptor.offset, descriptor.revision, descriptor.control,
               ", ".join(descriptor.control_flags)))
        print("  Owner SID: %s" %
              (descriptor.owner.sid if descriptor.owner else "(none)"))
        print("  Group SID: %s" %
              (descriptor.group.sid if descriptor.group else "(none)"))
        _print_acl("DACL", descriptor.dacl, descriptor.dacl_present)
        _print_acl("SACL", descriptor.sacl, descriptor.sacl_present)
        print("  Raw descriptor bytes (%d):" % len(descriptor.raw_bytes))
        print(_hex(descriptor.raw_bytes))

    if evidence.anomalies:
        print("  STRUCTURAL ANOMALIES:")
        for note in evidence.anomalies:
            print("    - %s" % note)
    if evidence.unsupported:
        print("  UNSUPPORTED CONTENT:")
        for note in evidence.unsupported:
            print("    - %s" % note)
    if not evidence.anomalies and not evidence.unsupported:
        print("  Status: parsed cleanly (no anomalies, no unsupported items)")


def main():
    if len(sys.argv) != 2:
        print("usage: %s <registry hive>" % sys.argv[0])
        return 1
    reg = Registry.Registry(sys.argv[1])
    for key in _walk(reg.root()):
        report(key.security())
    return 0


if __name__ == "__main__":
    sys.exit(main())
