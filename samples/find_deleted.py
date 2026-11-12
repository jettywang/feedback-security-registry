#!/usr/bin/env python

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
Carve deleted nk/vk record candidates from the free cells of a hive.

This is an explicit forensic scan mode, separate from the normal
active-tree traversal. The hive is opened read-only and never modified.
Every finding is printed with the absolute offset of its evidence bytes,
its verifiable associations, and the parts that could not be determined.

Usage: python find_deleted.py <hive file>
"""

from __future__ import print_function

import sys

from Registry.RegistryCarve import CandidateStatus, DeletedRecordScanner


def print_candidate(cand):
    name = cand.name if cand.name is not None else "(undetermined)"
    print("[%s] %s record, name=%r" % (cand.status.value.upper(),
                                       cand.record_type, name))
    print("  evidence offset: 0x%x (%d bytes, in free cell at 0x%x)" %
          (cand.offset, cand.length, cand.cell_offset))
    for ref in cand.verified_references():
        print("  verified association: %s @0x%x -> cell 0x%x (%s)" %
              (ref.field, ref.field_offset, ref.target_offset, ref.detail))
    for (source, ref) in cand.referenced_by:
        print("  referenced by: %s record at 0x%x (via %s @0x%x)" %
              (source.record_type, source.offset, ref.field,
               ref.field_offset))
    for unknown in cand.unresolved():
        print("  undetermined: %s" % (unknown,))
    print("  raw evidence:")
    for line in cand.hexdump().splitlines():
        print("    %s" % (line,))


def main(path):
    report = DeletedRecordScanner.from_file(path).scan()

    for warning in report.warnings:
        print("warning: %s" % (warning,))

    for status in (CandidateStatus.RELIABLE, CandidateStatus.PARTIAL,
                   CandidateStatus.ORPHAN):
        group = report.with_status(status)
        print("")
        print("=" * 60)
        print("%s candidates: %d" % (status.value.upper(), len(group)))
        print("=" * 60)
        for cand in group:
            print_candidate(cand)
            print("")

    print("=" * 60)
    print("REJECTED signature coincidences: %d" % (len(report.rejections),))
    print("=" * 60)
    for rej in report.rejections:
        print("  %r at 0x%x (cell 0x%x): %s" %
              (rej.signature, rej.offset, rej.cell_offset,
               "; ".join(rej.reasons)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
