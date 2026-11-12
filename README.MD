
python-registry
===============

Introduction
------------
python-registry is a pure Python library that provides read-only
access to Windows NT Registry files.
These include NTUSER.DAT, userdiff, and SAM. The interface is two-fold:
a high-level interface suitable for most tasks, and a low level
set of parsing objects and methods which may be used for advanced
study of the Windows NT Registry. This library is compatible with
Windows,Linux, and MacOS, making it accessible and functional
across all major operating systems.

Usage
-----

Most users will find the `Registry.Registry` module most appropriate.
The module exposes three classes: the `Registry`, the `RegistryKey`,
and the `RegistryValue`. The `Registry` organizes parsing and access
to the Windows Registry file. The `RegistryKey` is a convenient
interface into the tree-like structure of the Windows NT Registry.
A `RegistryKey` may have children `RegistryKeys`, and may also have
values associated with it. A `RegistryValue` can be thought of as
the tuple (name, datatype, value) associated with a `RegistryKey`.
python-registry supports all major datatypes, such as `RegSZ`,
`RegDWord`, and `RegBin`.

To open a Windows Registry file, its this easy:


    import sys
    from Registry import Registry
    
    reg = Registry.Registry(sys.argv[1])


Print all keys in a Registry


    def rec(key, depth=0):
        print "\t" * depth + key.path()
    
        for subkey in key.subkeys():
            rec(subkey, depth + 1)
    
    rec(reg.root())


Find a key and print all string values


    try:
        key = reg.open("SOFTWARE\\Microsoft\\Windows\\Current Version\\Run")
    except Registry.RegistryKeyNotFoundException:
        print "Couldn't find Run key. Exiting..."
        sys.exit(-1)
    
    for value in [v for v in key.values() \
                       if v.value_type() == Registry.RegSZ or \
                          v.value_type() == Registry.RegExpandSZ]:
        print "%s: %s" % (value.name(), value.value())


Advanced users who wish to study the structure of the Windows
Registry may find the `Registry.RegistryParse` module useful.
This module implements all known structures of the Windows Registry.


Bounded traversal of damaged hives
----------------------------------

The regular `RegistryKey.subkeys()` interface assumes a well formed,
tree shaped hive. A damaged hive can chain its subkey index (`lf`,
`lh`, `li`, `ri`) cells into a loop, point at free or out of bounds
cells, or contain parent pointers that disagree with the subkey
tables. Walking such a hive the normal way can raise out of the walk
or recurse forever.

The `Registry.Traversal` module provides `BoundedTraversal`, an
iterative, forensics-oriented walker. It always terminates (every
descent is limited by a node budget and a depth budget), keeps the
keys and values it could confirm separate from the ranges it could
not finish, and records each structural problem as a structured
`TraversalIssue` instead of swallowing it. Every confirmed key reports
its actual cell offset together with the reference path (the chain of
cell offsets) that led to it.

A node referenced from more than one place is a shared node, not a
cycle. It is visited once, every additional reference is reported as a
`duplicate_reference`, and path rendering stays bounded.

    from Registry import Registry

    reg = Registry.Registry("ntuser.dat")
    report = reg.bounded_traversal(max_nodes=100000, max_depth=256)

    print("completed:", report.completed)      # False if a budget was hit
    for node in report.nodes:                  # confirmed keys only
        print(hex(node.cell_offset), node.key_path(),
              [value.name() for value in node.values])
    for issue in report.issues:                # nothing is silently lost
        print(issue.kind, issue.message,
              Traversal.render_reference_path(issue.reference_path))

The same walker is available directly as
`Traversal.BoundedTraversal(reg).traverse(start_key)`, where
`start_key` may be a `RegistryKey`, an `NKRecord`, or omitted to start
at the hive root.

Wanted
------
  - Bug reports.
  - Feedback.

python-registry was originally developed to scratch one of
the author's itches.  Now he hopes it can be of use to
someone outside of his lonely NYC apartment.


License
-------
As of version 0.2.0, python-registry is released under the Apache 2.0 license.
Before that, python-registry was released under the GPLv3.


Sources
-------
Nearly all structure definitions used in python-registry
came from one of two sources:
1) WinReg.txt, by B.H., which may be accessed at:
   http://pogostick.net/~pnh/ntpasswd/WinReg.txt
2) The Windows NT Registry File Format version 0.4, by
   Timothy D. Morgan, which may be accessed at:
   https://docs.google.com/viewer?url=http%3A%2F%2Fsentinelchicken.com%2Fdata%2FTheWindowsNTRegistryFileFormat.pdf
Copies of these resources are included in the
`documentation/` directory of the python-registry source.


The source directory for python-registry contains a `sample/`
subdirectory that contains small programs that use python-registry.
For example, `regview.py` is a read-only clone of Microsoft Window's
Regedit, implemented in a few hundred lines.
