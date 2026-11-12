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
Bounded, forensics-oriented traversal of a registry hive.

The regular :class:`Registry.Registry` / :class:`Registry.RegistryKey`
interface assumes a well formed, tree shaped hive.  A damaged hive may
chain its subkey index (lf / lh / li / ri) cells into a loop, point at
free or out of bounds cells, or contain parent pointers that disagree
with the subkey tables.  Walking such a hive with the regular interface
either raises out of the traversal or recurses forever, losing every key
that had already been confirmed.

This module provides :class:`BoundedTraversal`, an iterative walker that:

* always terminates, even when cells reference each other in a cycle,
  because every descent is limited by a node budget and a depth budget;
* keeps confirmed keys and values separate from the ranges that could not
  be finished, so partial results remain usable as evidence;
* records every structural problem it encounters as a
  :class:`TraversalIssue` instead of swallowing it or aborting the walk;
* reports the actual cell offset of every key together with the reference
  path (the chain of cell offsets) that led to it.

A shared node (one cell legitimately referenced from more than one place)
is not a cycle.  It is visited once, reported through each reference path
that reaches it, and every additional reference is recorded as a
``duplicate_reference`` issue so that paths can never grow without bound.
"""
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import struct
from collections import namedtuple

from . import RegistryParse


# Issue severity levels.
SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_LIMIT = "limit"

# Reference hop kinds.  Every hop names the cell being left and the cell
# being entered, which is enough to reconstruct a concrete reference chain.
HOP_ROOT = "root"
HOP_SUBKEY_LIST = "subkey_list"
HOP_INDEX_ENTRY = "index_entry"
HOP_RI_ENTRY = "ri_entry"
HOP_VALUES_LIST = "values_list"
HOP_VALUE_ENTRY = "value_entry"


class TraversalException(RegistryParse.RegistryException):
    """Base class for errors raised while setting up a bounded traversal."""


class ReferenceHop(namedtuple("ReferenceHop", ["kind", "from_cell", "to_cell", "detail"])):
    """
    One step of a reference path.

    - `kind`: one of the HOP_* constants.
    - `from_cell`: absolute offset of the cell holding the reference, or
      None for the root hop.
    - `to_cell`: absolute offset of the referenced cell, or None when the
      reference could not even be resolved to an offset.
    - `detail`: human readable detail (entry index, list type, ...).
    """
    __slots__ = ()

    def __str__(self):
        source = "none" if self.from_cell is None else "0x%x" % self.from_cell
        target = "none" if self.to_cell is None else "0x%x" % self.to_cell
        return "%s %s -> %s (%s)" % (self.kind, source, target, self.detail)


class TraversalIssue(namedtuple("TraversalIssue",
                                ["kind", "severity", "message", "reference_path", "cell_offset"])):
    """
    A structural problem encountered during the traversal.

    - `kind`: stable machine readable identifier, see the TraversalReport
      docstring for the full list.
    - `severity`: one of the SEVERITY_* constants.
    - `message`: human readable description.
    - `reference_path`: tuple of :class:`ReferenceHop` leading to the problem.
    - `cell_offset`: absolute offset of the offending cell, or None.
    """
    __slots__ = ()

    def __str__(self):
        return "%s (%s): %s" % (self.kind, self.severity, self.message)


class TraversalValue(namedtuple("TraversalValue", ["name", "value_type", "raw_data", "cell_offset"])):
    """
    A value that could be confirmed on a key.

    Only the raw bytes are exposed: decoding a value can itself fail on a
    damaged hive, and a forensic consumer should be able to inspect the
    bytes regardless.  `cell_offset` is the offset of the VK cell.
    """
    __slots__ = ()


class TraversalNode(namedtuple("TraversalNode",
                               ["cell_offset", "name", "depth", "reference_path",
                                "values", "is_root", "shared"])):
    """
    A confirmed key (NK cell).

    - `cell_offset`: absolute offset of the NK cell (the cell header, four
      bytes before the ``nk`` signature).
    - `name`: key name, decoded best effort.
    - `depth`: number of edges below the traversal start (the root is 0).
    - `reference_path`: tuple of :class:`ReferenceHop` from the start to
      this exact reference of the cell.
    - `values`: tuple of :class:`TraversalValue` confirmed for this key.
    - `is_root`: True for the key the traversal started at.
    - `shared`: True when this cell was also reached through another
      reference path; only the first visit carries the key's contents.
    """
    __slots__ = ()

    def path(self):
        """Render the reference path as a compact string of cell offsets."""
        return render_reference_path(self.reference_path)

    def key_path(self):
        """
        Render the registry style path of names along this reference path.

        Only NK cells carry names, so the rendered path joins the names of
        every NK cell on the reference chain.  It is bounded by the
        traversal depth budget and therefore never recurses forever.
        """
        names = []
        for hop in self.reference_path:
            if hop.kind in (HOP_ROOT, HOP_INDEX_ENTRY) and \
                    hop.detail and hop.detail.startswith("nk "):
                names.append(hop.detail[3:])
        return "\\".join(names)


def render_reference_path(reference_path):
    """
    Render a reference path (tuple of ReferenceHop) as a string.

    The string lists each hop as ``kind:0xfrom->0xto`` so that a forensic
    report can point at the exact chain of cell references involved in,
    for example, a cycle.
    """
    parts = []
    for hop in reference_path:
        source = "none" if hop.from_cell is None else "0x%x" % hop.from_cell
        target = "none" if hop.to_cell is None else "0x%x" % hop.to_cell
        parts.append("%s:%s->%s" % (hop.kind, source, target))
    return " | ".join(parts)


class TraversalReport(object):
    """
    Result of a bounded traversal.

    Confirmed results and unfinished ranges are kept strictly separate:

    - `nodes`: tuple of :class:`TraversalNode`, one per confirmed NK cell,
      in first visit order.  Every node here was actually parsed.
    - `issues`: tuple of :class:`TraversalIssue` for every structural
      problem or budget limit hit.  Nothing is silently swallowed.
    - `completed`: True only when the walk finished without hitting a
      node or depth budget.  When False, at least one reachable range was
      not explored; inspect the ``node_budget`` / ``depth_budget`` issues.
    - `truncated`: convenience flag, the inverse of `completed`.

    Issue `kind` values:

    =========================== ============================================
    kind                        meaning
    =========================== ============================================
    ``out_of_bounds_cell``      a reference points outside the hbins.
    ``misaligned_cell``         a reference is not cell aligned / readable.
    ``free_cell``               a referenced cell is marked free.
    ``invalid_signature``       a cell does not hold the expected record.
    ``unsupported_subkey_list`` unknown subkey index signature.
    ``index_structure_error``   malformed lf/lh/li/ri cell.
    ``index_cycle``             an index chain re-enters itself (ri loop).
    ``key_cycle``               a subkey table points back to an ancestor.
    ``duplicate_reference``     a cell is reached through a second path.
    ``parent_mismatch``         NK parent pointer disagrees with the table.
    ``value_structure_error``   malformed values list or VK cell.
    ``node_budget``             the node budget was exhausted.
    ``depth_budget``            the depth budget was exhausted.
    ``traversal_error``         any other parse failure, kept for safety.
    =========================== ============================================
    """

    def __init__(self):
        self._nodes = []
        self._issues = []
        self.completed = True

    @property
    def truncated(self):
        return not self.completed

    @property
    def nodes(self):
        return tuple(self._nodes)

    @property
    def issues(self):
        return tuple(self._issues)

    def node_offsets(self):
        """Set of confirmed NK cell offsets."""
        return set(node.cell_offset for node in self._nodes)

    def issues_of_kind(self, kind):
        """Tuple of issues with the given kind."""
        return tuple(issue for issue in self._issues if issue.kind == kind)

    def has_issue(self, kind):
        """True if at least one issue with the given kind was recorded."""
        return any(issue.kind == kind for issue in self._issues)

    def _add_issue(self, kind, severity, message, reference_path, cell_offset=None):
        self._issues.append(TraversalIssue(kind, severity, message,
                                           tuple(reference_path), cell_offset))

    def _add_node(self, node):
        self._nodes.append(node)

    def _truncate(self):
        self.completed = False


class _CellSpace(object):
    """
    Bounds checked access to the hive's cell area.

    All registry cell references are offsets relative to the start of the
    first HBIN.  This resolver converts them to absolute offsets and proves
    that the referenced bytes actually exist before a parser touches them.
    """

    def __init__(self, regf):
        self._buf = regf._buf
        self._first_hbin = regf.first_hbin_offset()
        self._end = self._first_hbin + regf.hbins_size()
        # RegistryParse resolves hbin-relative offsets by walking the parent
        # chain, so every block needs the first HBIN as its ancestor.
        self._hbin = RegistryParse.HBINBlock(self._buf, self._first_hbin, regf)

    def resolve(self, relative_offset):
        """Convert a hbin-relative offset to an absolute cell offset."""
        return self._first_hbin + relative_offset

    def check_cell(self, absolute_offset, length=4):
        """
        Validate that a cell at `absolute_offset` is in bounds and readable.

        Raises CellReferenceException (a RegistryException subclass) with a
        descriptive kind when the reference cannot be trusted.
        """
        if absolute_offset < self._first_hbin or absolute_offset + length > self._end:
            raise CellReferenceException(
                "out_of_bounds_cell",
                "cell reference 0x%x is outside the hbin area [0x%x, 0x%x)"
                % (absolute_offset, self._first_hbin, self._end),
                absolute_offset)
        if (absolute_offset - self._first_hbin) % 4 != 0:
            raise CellReferenceException(
                "misaligned_cell",
                "cell reference 0x%x is not 4 byte aligned" % absolute_offset,
                absolute_offset)

    def open_cell(self, absolute_offset):
        """
        Return an HBINCell at `absolute_offset`, proving it is in bounds and
        allocated.  Raises CellReferenceException otherwise.
        """
        self.check_cell(absolute_offset, 4)
        cell = RegistryParse.HBINCell(self._buf, absolute_offset, self._hbin)
        if cell.size() <= 0 or cell.data_offset() + cell.size() > self._end:
            raise CellReferenceException(
                "misaligned_cell",
                "cell at 0x%x has an invalid size 0x%x"
                % (absolute_offset, cell.size()),
                absolute_offset)
        if cell.is_free():
            raise CellReferenceException(
                "free_cell",
                "cell at 0x%x is marked free" % absolute_offset,
                absolute_offset)
        return cell

    def nk_record(self, cell):
        """Construct the NKRecord for an already validated NK cell."""
        return RegistryParse.NKRecord(self._buf, cell.data_offset(), self._hbin)

    def vk_record(self, cell):
        """Construct the VKRecord for an already validated VK cell."""
        return RegistryParse.VKRecord(self._buf, cell.data_offset(), self._hbin)

    def signature(self, cell):
        """Read the two byte record signature of an allocated cell."""
        return self._buf[cell.data_offset():cell.data_offset() + 2]


class CellReferenceException(RegistryParse.RegistryException):
    """
    Raised internally when a cell reference cannot be resolved.

    `kind` matches one of the TraversalIssue kinds so callers can record a
    structured issue rather than a generic parse failure.
    """

    def __init__(self, kind, value, cell_offset=None):
        super(CellReferenceException, self).__init__(value)
        self.kind = kind
        self.cell_offset = cell_offset

    def __str__(self):
        return "Cell Reference Exception (%s): %s" % (self.kind, self._value)


# Subkey index signatures and the byte stride of their entries.
_DIRECT_LISTS = {b"lf": 8, b"lh": 8, b"li": 4}
_LIST_SIGNATURES = (b"lf", b"lh", b"li", b"ri")


class BoundedTraversal(object):
    """
    Bounded, exception tolerant traversal of the key structure of a hive.

    Arguments:
    - `registry`: a :class:`Registry.Registry` opened on the hive to walk.
    - `max_nodes`: maximum number of distinct NK cells that may be
      confirmed.  None means unlimited (the cycle guard still applies).
    - `max_depth`: maximum descent depth below the start key.  None means
      unlimited (the cycle guard still applies).
    - `max_index_depth`: maximum nesting depth of ri index cells while
      expanding a single subkey list.
    """

    def __init__(self, registry, max_nodes=100000, max_depth=256, max_index_depth=64):
        if max_nodes is not None and max_nodes < 1:
            raise TraversalException("max_nodes must be positive or None")
        if max_depth is not None and max_depth < 0:
            raise TraversalException("max_depth must be non-negative or None")
        if max_index_depth is not None and max_index_depth < 1:
            raise TraversalException("max_index_depth must be positive or None")
        self._registry = registry
        self._max_nodes = max_nodes
        self._max_depth = max_depth
        self._max_index_depth = max_index_depth

    def traverse(self, start_key=None):
        """
        Walk the hive and return a :class:`TraversalReport`.

        `start_key` may be a :class:`Registry.RegistryKey`, an
        :class:`RegistryParse.NKRecord`, or None (in which case the hive
        root is used).
        """
        report = TraversalReport()
        space = _CellSpace(self._registry._regf)

        root_cell = self._root_cell_offset(start_key, report)
        if root_cell is None:
            return report

        root_name = self._root_name(space, root_cell, report)
        root_path = (ReferenceHop(HOP_ROOT, None, root_cell,
                                  "nk %s" % root_name),)
        # discovered: every cell already scheduled or confirmed, so a shared
        # node is never enqueued twice regardless of DFS ordering.
        discovered = set([root_cell])
        # shared: cells reached through a second reference path.
        shared = set()
        # Stack items: (nk_cell, ref_path, depth, is_root, parent_nk_or_none).
        stack = [(root_cell, root_path, 0, True, None)]

        while stack:
            cell_offset, ref_path, depth, is_root, parent_nk = stack.pop()

            if parent_nk is not None:
                self._verify_parent(space, parent_nk, cell_offset,
                                    ref_path, report)

            try:
                cell = space.open_cell(cell_offset)
                if space.signature(cell) != b"nk":
                    raise CellReferenceException(
                        "invalid_signature",
                        "cell at 0x%x is not an NK record" % cell_offset,
                        cell_offset)
                nk = space.nk_record(cell)
                name = self._safe_name(nk, report, ref_path, cell_offset)
                values = self._read_values(space, nk, ref_path, report)
            except CellReferenceException as exc:
                self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                             ref_path, exc.cell_offset)
                continue
            except RegistryParse.ParseException as exc:
                self._record(report, "invalid_signature", SEVERITY_ERROR, str(exc),
                             ref_path, cell_offset)
                continue
            except (struct.error, IndexError, UnicodeError) as exc:
                self._record(report, "traversal_error", SEVERITY_ERROR, str(exc),
                             ref_path, cell_offset)
                continue

            shared_flag = cell_offset in shared
            report._add_node(TraversalNode(cell_offset, name, depth, tuple(ref_path),
                                           tuple(values), is_root, shared_flag))

            children = self._enumerate_subkeys(space, cell, nk, ref_path, report)
            for child_cell, child_path in reversed(children):
                self._schedule_child(child_cell, child_path, depth + 1,
                                     discovered, shared, stack, report,
                                     space, nk)

        return report

    # ------------------------------------------------------------------ #
    # traversal setup
    # ------------------------------------------------------------------ #
    def _root_cell_offset(self, start_key, report):
        regf = self._registry._regf
        if start_key is None:
            try:
                nk = regf.first_key()
                return nk.offset() - 4
            except (RegistryParse.RegistryException, struct.error, IndexError) as exc:
                report._add_issue(
                    "traversal_error", SEVERITY_ERROR,
                    "cannot locate hive root: %s" % exc, ())
                report._truncate()
                return None
        else:
            nkrecord = getattr(start_key, "_nkrecord", start_key)
            if not isinstance(nkrecord, RegistryParse.NKRecord):
                raise TraversalException("start_key must be a RegistryKey or NKRecord")
            return nkrecord.offset() - 4

    def _root_name(self, space, root_cell, report):
        root_path = (ReferenceHop(HOP_ROOT, None, root_cell, "root"),)
        try:
            cell = space.open_cell(root_cell)
            if space.signature(cell) != b"nk":
                raise CellReferenceException(
                    "invalid_signature",
                    "root cell at 0x%x is not an NK record" % root_cell,
                    root_cell)
            return space.nk_record(cell).name()
        except CellReferenceException as exc:
            self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                         root_path, exc.cell_offset)
        except (RegistryParse.ParseException, struct.error, IndexError,
                UnicodeError) as exc:
            self._record(report, "traversal_error", SEVERITY_ERROR, str(exc),
                         root_path, root_cell)
        return "<unknown:0x%x>" % root_cell

    # ------------------------------------------------------------------ #
    # child scheduling and the cycle / budget guards
    # ------------------------------------------------------------------ #
    def _schedule_child(self, child_cell, child_path, depth, discovered,
                        shared, stack, report, space, parent_nk):
        # A cell already on the current reference path is a genuine cycle.
        on_path = any(hop.to_cell == child_cell for hop in child_path[:-1])
        if on_path:
            cycle_kind = "key_cycle" if child_path[-1].kind == HOP_INDEX_ENTRY \
                else "index_cycle"
            self._record(report, cycle_kind, SEVERITY_ERROR,
                         "reference at 0x%x closes a cycle back to 0x%x"
                         % (child_path[-1].from_cell, child_cell),
                         child_path, child_cell)
            report._truncate()
            return

        # Shared node: valid structure, but the cell was already scheduled
        # through another reference path, so it is never enqueued again.
        if child_cell in discovered:
            shared.add(child_cell)
            self._record(report, "duplicate_reference", SEVERITY_WARNING,
                         "NK cell 0x%x is referenced again; already scheduled"
                         % child_cell,
                         child_path, child_cell)
            # The node may already have been confirmed on its first path, so
            # flip the shared flag on the stored node as well.
            for index, existing in enumerate(report._nodes):
                if existing.cell_offset == child_cell:
                    report._nodes[index] = existing._replace(shared=True)
            # Still validate the second parent pointer against this route.
            self._verify_parent(space, parent_nk, child_cell,
                                child_path, report)
            return

        if self._max_depth is not None and depth > self._max_depth:
            self._record(report, "depth_budget", SEVERITY_LIMIT,
                         "depth budget of %d exhausted at cell 0x%x"
                         % (self._max_depth, child_cell),
                         child_path, child_cell)
            report._truncate()
            return

        if self._max_nodes is not None and len(discovered) >= self._max_nodes:
            if not report.has_issue("node_budget"):
                self._record(report, "node_budget", SEVERITY_LIMIT,
                             "node budget of %d exhausted; cell 0x%x not explored"
                             % (self._max_nodes, child_cell),
                             child_path, child_cell)
            report._truncate()
            return

        discovered.add(child_cell)
        stack.append((child_cell, child_path, depth, False, parent_nk))

    def _verify_parent(self, space, parent_nk, child_cell, child_path, report):
        try:
            cell = space.open_cell(child_cell)
            if space.signature(cell) != b"nk":
                return
            child_nk = space.nk_record(cell)
            if child_nk.is_root():
                return
            relative_parent = child_nk.unpack_dword(0x10)
            actual_parent = space.resolve(relative_parent)
            expected_parent = parent_nk.offset() - 4
            if actual_parent != expected_parent:
                self._record(report, "parent_mismatch", SEVERITY_WARNING,
                             "NK cell 0x%x names parent 0x%x but is listed by 0x%x"
                             % (child_cell, actual_parent, expected_parent),
                             child_path, child_cell)
        except CellReferenceException as exc:
            self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                         child_path, exc.cell_offset)
        except (RegistryParse.ParseException, struct.error, IndexError) as exc:
            self._record(report, "traversal_error", SEVERITY_ERROR, str(exc),
                         child_path, child_cell)

    # ------------------------------------------------------------------ #
    # subkey index expansion (lf / lh / li / ri, including nested ri)
    # ------------------------------------------------------------------ #
    def _enumerate_subkeys(self, space, nk_cell, nk, ref_path, report):
        if nk.subkey_number() == 0:
            return []

        try:
            relative_list = nk.unpack_dword(0x1C)
            list_cell_offset = space.resolve(relative_list)
            list_cell = space.open_cell(list_cell_offset)
            list_sig = space.signature(list_cell)
        except CellReferenceException as exc:
            self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                         ref_path, exc.cell_offset)
            return []
        except (struct.error, IndexError) as exc:
            self._record(report, "index_structure_error", SEVERITY_ERROR, str(exc),
                         ref_path, nk_cell.offset())
            return []

        list_hop = ReferenceHop(HOP_SUBKEY_LIST, nk_cell.offset(),
                                list_cell_offset, list_sig.decode("ascii", "replace"))
        list_path = ref_path + (list_hop,)

        if list_sig not in _LIST_SIGNATURES:
            self._record(report, "unsupported_subkey_list", SEVERITY_ERROR,
                         "subkey list at 0x%x has unsupported signature %r"
                         % (list_cell_offset, list_sig),
                         list_path, list_cell_offset)
            return []

        try:
            count = struct.unpack_from("<H", space._buf, list_cell.data_offset() + 2)[0]
        except (struct.error, IndexError) as exc:
            self._record(report, "index_structure_error", SEVERITY_ERROR, str(exc),
                         list_path, list_cell_offset)
            return []

        # A corrupt count must never drive an unbounded loop: the entries
        # have to physically fit inside the cell that declares them.
        stride = 4 if list_sig == b"ri" else _DIRECT_LISTS[list_sig]
        if not self._count_fits(space, list_cell, count, stride,
                                list_path, report):
            return []

        if list_sig == b"ri":
            return self._expand_ri(space, list_cell, list_path, report, 0)
        return self._expand_direct(space, list_cell, list_sig, count, list_path, report)

    def _count_fits(self, space, list_cell, count, stride, list_path, report):
        """Prove a declared entry count physically fits in its index cell."""
        capacity = (list_cell.size() - 4 - 2) // stride
        if count > capacity:
            self._record(report, "index_structure_error", SEVERITY_ERROR,
                         "subkey list at 0x%x declares %d entries but holds at "
                         "most %d" % (list_cell.offset(), count, capacity),
                         list_path, list_cell.offset())
            report._truncate()
            return False
        return True

    def _expand_direct(self, space, list_cell, signature, count, list_path, report):
        stride = _DIRECT_LISTS[signature]
        data_start = list_cell.data_offset()
        results = []
        for index in range(count):
            entry_position = data_start + 4 + index * stride
            hop = ReferenceHop(HOP_INDEX_ENTRY, list_cell.offset(), None,
                               "%s[%d]" % (signature.decode("ascii"), index))
            entry_path = list_path + (hop,)
            try:
                space.check_cell(entry_position, 4)
                relative_target = struct.unpack_from("<I", space._buf, entry_position)[0]
                target = space.resolve(relative_target)
                target_cell = space.open_cell(target)
                name = self._peek_nk_name(space, target_cell)
            except CellReferenceException as exc:
                self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                             entry_path, exc.cell_offset)
                continue
            except (struct.error, IndexError, UnicodeError) as exc:
                self._record(report, "index_structure_error", SEVERITY_ERROR, str(exc),
                             entry_path, list_cell.offset())
                continue
            entry_hop = ReferenceHop(HOP_INDEX_ENTRY, list_cell.offset(),
                                     target, "nk %s" % name)
            results.append((target, list_path + (entry_hop,)))
        return results

    def _expand_ri(self, space, ri_cell, ri_path, report, index_depth):
        if self._max_index_depth is not None and index_depth >= self._max_index_depth:
            self._record(report, "index_structure_error", SEVERITY_LIMIT,
                         "ri nesting budget of %d exhausted at cell 0x%x"
                         % (self._max_index_depth, ri_cell.offset()),
                         ri_path, ri_cell.offset())
            report._truncate()
            return []

        try:
            count = struct.unpack_from("<H", space._buf, ri_cell.data_offset() + 2)[0]
        except (struct.error, IndexError) as exc:
            self._record(report, "index_structure_error", SEVERITY_ERROR, str(exc),
                         ri_path, ri_cell.offset())
            return []

        if not self._count_fits(space, ri_cell, count, 4, ri_path, report):
            return []

        results = []
        # Frames hold (ri_cell, path, next_entry, count, depth).  The
        # on_stack set detects an ri chain that loops back into itself.
        frames = [(ri_cell, ri_path, 0, count, index_depth)]
        on_stack = set([ri_cell.offset()])

        while frames:
            current, current_path, entry, entry_count, depth = frames[-1]
            if entry >= entry_count:
                on_stack.discard(current.offset())
                frames.pop()
                continue
            frames[-1] = (current, current_path, entry + 1, entry_count, depth)

            entry_position = current.data_offset() + 4 + entry * 4
            hop = ReferenceHop(HOP_RI_ENTRY, current.offset(), None,
                               "ri[%d]" % entry)
            entry_path = current_path + (hop,)
            try:
                space.check_cell(entry_position, 4)
                relative_target = struct.unpack_from("<I", space._buf, entry_position)[0]
                target = space.resolve(relative_target)
                target_cell = space.open_cell(target)
                target_sig = space.signature(target_cell)
            except CellReferenceException as exc:
                self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                             entry_path, exc.cell_offset)
                continue
            except (struct.error, IndexError) as exc:
                self._record(report, "index_structure_error", SEVERITY_ERROR, str(exc),
                             entry_path, current.offset())
                continue

            resolved_hop = ReferenceHop(HOP_RI_ENTRY, current.offset(),
                                        target, target_sig.decode("ascii", "replace"))
            target_path = current_path + (resolved_hop,)

            if target_sig == b"ri":
                if target in on_stack:
                    self._record(report, "index_cycle", SEVERITY_ERROR,
                                 "ri cell 0x%x references ri cell 0x%x already "
                                 "in its index chain" % (current.offset(), target),
                                 target_path, target)
                    report._truncate()
                    continue
                if self._max_index_depth is not None and \
                        depth + 1 >= self._max_index_depth:
                    self._record(report, "index_structure_error", SEVERITY_LIMIT,
                                 "ri nesting budget of %d exhausted at cell 0x%x"
                                 % (self._max_index_depth, target),
                                 target_path, target)
                    report._truncate()
                    continue
                try:
                    nested_count = struct.unpack_from(
                        "<H", space._buf, target_cell.data_offset() + 2)[0]
                except (struct.error, IndexError) as exc:
                    self._record(report, "index_structure_error", SEVERITY_ERROR,
                                 str(exc), target_path, target)
                    continue
                if not self._count_fits(space, target_cell, nested_count, 4,
                                        target_path, report):
                    continue
                on_stack.add(target)
                frames.append((target_cell, target_path, 0, nested_count,
                               depth + 1))
            elif target_sig in _DIRECT_LISTS:
                nested_stride = _DIRECT_LISTS[target_sig]
                try:
                    nested_count = struct.unpack_from(
                        "<H", space._buf, target_cell.data_offset() + 2)[0]
                except (struct.error, IndexError) as exc:
                    self._record(report, "index_structure_error", SEVERITY_ERROR,
                                 str(exc), target_path, target)
                    continue
                if not self._count_fits(space, target_cell, nested_count,
                                        nested_stride, target_path, report):
                    continue
                results.extend(self._expand_direct(
                    space, target_cell, target_sig, nested_count, target_path, report))
            else:
                self._record(report, "unsupported_subkey_list", SEVERITY_ERROR,
                             "ri entry at 0x%x points to non-index cell %r at 0x%x"
                             % (current.offset(), target_sig, target),
                             target_path, target)
        return results

    def _peek_nk_name(self, space, nk_cell):
        if space.signature(nk_cell) != b"nk":
            raise CellReferenceException(
                "invalid_signature",
                "subkey cell at 0x%x is not an NK record" % nk_cell.offset(),
                nk_cell.offset())
        nk = space.nk_record(nk_cell)
        return nk.name()

    # ------------------------------------------------------------------ #
    # values
    # ------------------------------------------------------------------ #
    def _read_values(self, space, nk, ref_path, report):
        if nk.values_number() == 0:
            return []

        try:
            relative_list = nk.unpack_dword(0x28)
            list_offset = space.resolve(relative_list)
            list_cell = space.open_cell(list_offset)
        except CellReferenceException as exc:
            self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                         ref_path, exc.cell_offset)
            return []
        except (struct.error, IndexError) as exc:
            self._record(report, "value_structure_error", SEVERITY_ERROR, str(exc),
                         ref_path, nk.offset() - 4)
            return []

        list_hop = ReferenceHop(HOP_VALUES_LIST, nk.offset() - 4,
                                list_offset, "values")
        list_path = ref_path + (list_hop,)
        values = []
        number = nk.values_number()

        for index in range(number):
            entry_position = list_cell.data_offset() + index * 4
            entry_path = list_path + (ReferenceHop(
                HOP_VALUE_ENTRY, list_cell.offset(), None, "vk[%d]" % index),)
            try:
                space.check_cell(entry_position, 4)
                relative_vk = struct.unpack_from("<I", space._buf, entry_position)[0]
                vk_offset = space.resolve(relative_vk)
                vk_cell = space.open_cell(vk_offset)
                if space.signature(vk_cell) != b"vk":
                    raise CellReferenceException(
                        "invalid_signature",
                        "value cell at 0x%x is not a VK record" % vk_offset,
                        vk_offset)
                vk = space.vk_record(vk_cell)
                name = vk.name() if vk.has_name() else "(default)"
                self._validate_value_data(space, vk, vk_offset, entry_path)
                raw = vk.raw_data()
            except CellReferenceException as exc:
                self._record(report, exc.kind, SEVERITY_ERROR, str(exc),
                             entry_path, exc.cell_offset)
                continue
            except (RegistryParse.ParseException, RegistryParse.UnknownTypeException,
                    struct.error, IndexError, UnicodeError) as exc:
                self._record(report, "value_structure_error", SEVERITY_ERROR,
                             str(exc), entry_path, list_cell.offset())
                continue

            values.append(TraversalValue(name, vk.data_type(), bytes(raw), vk_offset))
        return values

    def _validate_value_data(self, space, vk, vk_cell_offset, entry_path):
        """
        Prove the data cell a VK points at is in bounds and allocated.

        Inline values (the high bit set on the data length, or fewer than
        five bytes) live inside the VK record itself and need no lookup.
        Everything else dereferences the data offset, which a damaged hive
        may aim at a free or out of bounds cell.
        """
        raw_length = vk.raw_data_length()
        if raw_length >= 0x80000000 or raw_length < 5:
            return
        data_cell_offset = vk.data_offset()
        space.open_cell(data_cell_offset)

    # ------------------------------------------------------------------ #
    # small helpers
    # ------------------------------------------------------------------ #
    def _safe_name(self, nk, report, ref_path, cell_offset):
        try:
            return nk.name()
        except (UnicodeError, struct.error, IndexError) as exc:
            self._record(report, "traversal_error", SEVERITY_WARNING,
                         "could not decode name of NK at 0x%x: %s"
                         % (cell_offset, exc),
                         ref_path, cell_offset)
            return "<undecodable:0x%x>" % cell_offset

    def _record(self, report, kind, severity, message, reference_path, cell_offset=None):
        report._add_issue(kind, severity, message, tuple(reference_path), cell_offset)
