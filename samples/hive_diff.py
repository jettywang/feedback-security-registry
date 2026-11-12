#!/usr/bin/python

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
#
#   Conservative snapshot diff for two copies of the same registry hive.
#   Keys and values are matched by logical path/name, never by cell offset,
#   so cell reuse cannot mask adds/deletes and pure relocation is not a
#   content change.  Timestamps are never interpreted.
#
#   python hive_diff.py <old hive> <new hive> [root path]
from __future__ import print_function

import sys

from Registry import Registry
from Registry.diff import diff_hives


def _hex(data):
    return " ".join("%02x" % b for b in data[:32]) + ("..." if len(data) > 32 else "")


def main():
    if len(sys.argv) < 3:
        print("usage: %s <old hive> <new hive> [root path]" % sys.argv[0])
        sys.exit(-1)

    root_path = sys.argv[3] if len(sys.argv) > 3 else None
    result = diff_hives(Registry.Registry(sys.argv[1]),
                        Registry.Registry(sys.argv[2]),
                        root_path=root_path)

    for key in result.added_keys:
        print("KEY ADDED   %s (NK 0x%x)" % (key.path, key.nk_offset))
    for key in result.removed_keys:
        print("KEY REMOVED %s (NK 0x%x)" % (key.path, key.nk_offset))

    for change in result.added_values:
        value = change.new
        print("VALUE ADDED   %s : %s (%s)" %
              (change.key_path, value.name, value.data_type_str))
    for change in result.removed_values:
        value = change.old
        print("VALUE REMOVED %s : %s (%s)" %
              (change.key_path, value.name, value.data_type_str))
    for change in result.changed_values:
        aspects = []
        if change.type_changed:
            aspects.append("type %s -> %s" %
                           (change.old.data_type_str, change.new.data_type_str))
        if change.data_changed:
            aspects.append("data %s -> %s" %
                           (_hex(change.old.raw_data), _hex(change.new.raw_data)))
        print("VALUE CHANGED %s : %s [%s]" %
              (change.key_path, change.name, "; ".join(aspects)))

    for note in result.uncertainties:
        print("UNCERTAIN [%s] %s" % (note.code, note.message))

    if result.is_empty() and not result.uncertainties:
        print("No provable differences.")


if __name__ == "__main__":
    main()
