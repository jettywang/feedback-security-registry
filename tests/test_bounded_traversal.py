#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Tests for the bounded, forensics-oriented hive traversal.

Three hand built structures drive the proof required for damaged hives:

1. a normal tree (including nested ri indexes and values) - every key must
   be found and the walk must finish cleanly;
2. a diamond reference graph - the same subkey is reached through more than
   one path.  This is sharing, not a cycle: the walk must terminate, keep
   the shared key and flag every extra reference;
3. a real loop - both an nk back edge and an ri index that points at
   itself.  The walk must terminate and the issue must name the exact chain
   of cell references that closes the loop.

Additional cases cover out of bounds / free cells, parent pointer
mismatches and the node/depth budgets.
"""
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import os
import struct
import unittest
from io import BytesIO

from Registry import Registry
from Registry import Traversal
from Registry.RegistryParse import RegSZ

from hive_builder import HiveBuilder


def load(builder, root_cell):
    return Registry.Registry(BytesIO(builder.build(root_cell)))


def names(report):
    return [node.name for node in report.nodes]


class NormalTreeTests(unittest.TestCase):
    def setUp(self):
        self.builder = HiveBuilder()
        b = self.builder

        # Tree:
        # ROOT
        #   Alpha
        #     Gamma (value)
        #     Delta
        #   Beta
        #     Epsilon
        root = b.add_nk("ROOT", None, root=True)
        alpha = b.add_nk("Alpha", root)
        beta = b.add_nk("Beta", root)
        gamma = b.add_nk("Gamma", alpha)
        delta = b.add_nk("Delta", alpha)
        epsilon = b.add_nk("Epsilon", beta)

        # Alpha's children are reached through an ri that points at two
        # direct lists, exercising nested ri index handling.
        gamma_li = b.add_index("li", [b.relative(gamma)])
        delta_lh = b.add_index("lh", [b.relative(delta)])
        alpha_ri = b.add_index("ri", [b.relative(gamma_li),
                                      b.relative(delta_lh)])
        b.patch_nk_field(alpha, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(alpha_ri))
        b.patch_nk_field(alpha, HiveBuilder.NK_SUBKEY_COUNT, 2)

        beta_lf = b.add_index("lf", [b.relative(epsilon)])
        b.patch_nk_field(beta, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(beta_lf))
        b.patch_nk_field(beta, HiveBuilder.NK_SUBKEY_COUNT, 1)

        root_li = b.add_index("li", [b.relative(alpha), b.relative(beta)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(root_li))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 2)

        # A value stored in an external data cell (length >= 5).
        payload = u"hello".encode("utf-16le") + b"\x00\x00"
        vk = b.add_vk("Setting", RegSZ, payload)
        values_list = b.add_values_list([vk])
        b.patch_nk_field(gamma, HiveBuilder.NK_VALUES_LIST,
                         b.relative(values_list))
        b.patch_nk_field(gamma, HiveBuilder.NK_VALUES_COUNT, 1)

        self.root = root
        self.cells = {"root": root, "alpha": alpha, "beta": beta,
                      "gamma": gamma, "delta": delta, "epsilon": epsilon,
                      "alpha_ri": alpha_ri}

    def test_high_level_api_matches(self):
        reg = load(self.builder, self.root)
        self.assertEqual(reg.root().name(), "ROOT")
        self.assertEqual(sorted(k.name() for k in reg.root().subkeys()),
                         ["Alpha", "Beta"])
        gamma = reg.open("Alpha\\Gamma")
        self.assertEqual(gamma.value("Setting").value(), "hello")
    def test_traversal_is_complete_and_clean(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()

        self.assertTrue(report.completed)
        self.assertFalse(report.truncated)
        self.assertEqual(len(report.issues), 0, report.issues)

        found = set(names(report))
        self.assertEqual(found,
                         {"ROOT", "Alpha", "Beta", "Gamma", "Delta",
                          "Epsilon"})

    def test_reports_actual_cell_offsets(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()
        offsets = report.node_offsets()
        for key in ("root", "alpha", "beta", "gamma", "delta", "epsilon"):
            self.assertIn(self.cells[key], offsets)

    def test_depths_and_reference_paths(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()
        by_name = dict((node.name, node) for node in report.nodes)

        self.assertEqual(by_name["ROOT"].depth, 0)
        self.assertEqual(by_name["Alpha"].depth, 1)
        self.assertEqual(by_name["Gamma"].depth, 2)

        # The reference path of Gamma must walk root -> ri -> li -> nk and
        # mention every intermediate cell offset.
        gamma_path = by_name["Gamma"].path()
        self.assertIn("0x%x" % self.cells["alpha_ri"], gamma_path)
        self.assertEqual(by_name["Gamma"].key_path(),
                         "ROOT\\Alpha\\Gamma")
        # Path rendering is bounded and never follows parent pointers.
        self.assertEqual(by_name["ROOT"].key_path(), "ROOT")

    def test_value_is_confirmed_with_raw_bytes(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()
        gamma = [n for n in report.nodes if n.name == "Gamma"][0]
        self.assertEqual(len(gamma.values), 1)
        value = gamma.values[0]
        self.assertEqual(value.name, "Setting")
        self.assertEqual(value.value_type, RegSZ)
        self.assertEqual(value.raw_data, u"hello".encode("utf-16le") + b"\x00\x00")
        # The VK cell lives in the hive's cell area, distinct from NK cells.
        self.assertGreaterEqual(value.cell_offset, 0x1020)
        self.assertNotIn(value.cell_offset, report.node_offsets())


class DiamondReferenceTests(unittest.TestCase):
    def setUp(self):
        self.builder = HiveBuilder()
        b = self.builder

        # ROOT lists Left and Right.  Both Left and Right list the SAME
        # Shared nk cell.  Shared therefore has two parents but only one
        # cell on disk.
        self.root = b.add_nk("ROOT", None, root=True)
        self.left = b.add_nk("Left", self.root)
        self.right = b.add_nk("Right", self.root)
        self.shared = b.add_nk("Shared", self.left)

        left_li = b.add_index("li", [b.relative(self.shared)])
        b.patch_nk_field(self.left, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(left_li))
        b.patch_nk_field(self.left, HiveBuilder.NK_SUBKEY_COUNT, 1)

        right_li = b.add_index("li", [b.relative(self.shared)])
        b.patch_nk_field(self.right, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(right_li))
        b.patch_nk_field(self.right, HiveBuilder.NK_SUBKEY_COUNT, 1)

        root_li = b.add_index("li",
                              [b.relative(self.left), b.relative(self.right)])
        b.patch_nk_field(self.root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(root_li))
        b.patch_nk_field(self.root, HiveBuilder.NK_SUBKEY_COUNT, 2)

    def test_terminates_and_keeps_shared_node(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()

        self.assertTrue(report.completed, report.issues)
        found = names(report)
        # The shared cell is a single confirmed node, not expanded forever.
        self.assertEqual(found.count("Shared"), 1)
        self.assertEqual(set(found), {"ROOT", "Left", "Right", "Shared"})

    def test_duplicate_reference_is_flagged_not_called_a_cycle(self):
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()

        self.assertFalse(report.has_issue("key_cycle"))
        self.assertFalse(report.has_issue("index_cycle"))
        duplicates = report.issues_of_kind("duplicate_reference")
        self.assertEqual(len(duplicates), 1)
        issue = duplicates[0]
        self.assertEqual(issue.cell_offset, self.shared)
        # The reference path identifies Right -> Shared as the second route.
        chain = Traversal.render_reference_path(issue.reference_path)
        self.assertIn("0x%x" % self.right, chain)
        self.assertIn("0x%x" % self.shared, chain)

        shared = [n for n in report.nodes if n.name == "Shared"][0]
        self.assertTrue(shared.shared)

    def test_parent_mismatch_is_reported(self):
        # Shared names Left as parent, but Right also lists it.
        reg = load(self.builder, self.root)
        report = reg.bounded_traversal()
        mismatches = report.issues_of_kind("parent_mismatch")
        self.assertTrue(mismatches)
        issue = mismatches[0]
        self.assertEqual(issue.cell_offset, self.shared)
        self.assertIn("0x%x" % self.right, issue.message)


class DuplicateEntryTests(unittest.TestCase):
    def test_same_subkey_listed_twice_in_one_index(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        child = b.add_nk("Child", root)
        # The same cell appears twice in the root's index.
        index = b.add_index("li", [b.relative(child), b.relative(child)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 2)

        report = load(b, root).bounded_traversal()
        self.assertTrue(report.completed)
        self.assertEqual(names(report).count("Child"), 1)
        self.assertTrue(report.has_issue("duplicate_reference"))
        self.assertFalse(report.has_issue("key_cycle"))


class CycleTests(unittest.TestCase):
    def _build_key_cycle(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        outer = b.add_nk("Outer", root)
        inner = b.add_nk("Inner", outer)

        # Inner points back to its own ancestor Outer, closing a loop.
        inner_li = b.add_index("li", [b.relative(outer)])
        b.patch_nk_field(inner, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(inner_li))
        b.patch_nk_field(inner, HiveBuilder.NK_SUBKEY_COUNT, 1)

        outer_li = b.add_index("li", [b.relative(inner)])
        b.patch_nk_field(outer, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(outer_li))
        b.patch_nk_field(outer, HiveBuilder.NK_SUBKEY_COUNT, 1)

        root_li = b.add_index("li", [b.relative(outer)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(root_li))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)
        return b, root, outer, inner, inner_li

    def test_key_back_edge_terminates_and_references_chain(self):
        b, root, outer, inner, inner_li = self._build_key_cycle()
        report = load(b, root).bounded_traversal()

        # All reachable, non-cyclic keys are still confirmed.
        self.assertEqual(set(names(report)), {"ROOT", "Outer", "Inner"})
        cycles = report.issues_of_kind("key_cycle")
        self.assertEqual(len(cycles), 1)
        issue = cycles[0]
        # The loop lands back on the Outer cell.
        self.assertEqual(issue.cell_offset, outer)
        chain = Traversal.render_reference_path(issue.reference_path)
        for cell in (root, outer, inner, inner_li, outer):
            self.assertIn("0x%x" % cell, chain)

    def test_traversal_always_terminates_under_repetition(self):
        # Running repeatedly must yield identical, finite results.
        b, root, _, _, _ = self._build_key_cycle()
        first = load(b, root).bounded_traversal()
        for _ in range(5):
            again = load(b, root).bounded_traversal()
            self.assertEqual(names(again), names(first))
            self.assertEqual(len(again.issues), len(first.issues))

    def test_ri_index_self_loop(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        # Reserve the ri cell offset, then make it reference itself.
        ri = b.add_index("ri", [0])
        b.patch_dword(ri + 4 + 0x4, b.relative(ri))  # first ri entry (data+4)
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST, b.relative(ri))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)

        report = load(b, root).bounded_traversal()
        self.assertEqual(names(report), ["ROOT"])
        cycles = report.issues_of_kind("index_cycle")
        self.assertEqual(len(cycles), 1)
        chain = Traversal.render_reference_path(cycles[0].reference_path)
        self.assertIn("0x%x" % ri, chain)

    def test_ri_nesting_budget_stops_deep_chain(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        # A chain of ri cells each pointing at the next one.
        first = b.add_index("ri", [0])
        previous = first
        for _ in range(10):
            nxt = b.add_index("ri", [0])
            b.patch_dword(previous + 4 + 4, b.relative(nxt))
            previous = nxt
        # Terminate the chain in a direct list with one key.
        child = b.add_nk("Child", root)
        direct = b.add_index("li", [b.relative(child)])
        b.patch_dword(previous + 4 + 4, b.relative(direct))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(first))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)

        reg = load(b, root)
        report = reg.bounded_traversal(max_index_depth=4)
        self.assertTrue(report.truncated)
        self.assertTrue(report.has_issue("index_structure_error"))
        self.assertNotIn("Child", names(report))


class BadCellTests(unittest.TestCase):
    def test_out_of_bounds_reference_is_reported_not_raised(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        good = b.add_nk("Good", root)
        index = b.add_index("li", [b.relative(good), 0x000FFFFF])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 2)

        report = load(b, root).bounded_traversal()
        self.assertIn("Good", names(report))
        oob = report.issues_of_kind("out_of_bounds_cell")
        self.assertEqual(len(oob), 1)
        self.assertIsNotNone(oob[0].reference_path)

    def test_free_cell_reference_is_reported(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        victim = b.add_nk("Victim", root)
        sibling = b.add_nk("Sibling", root)
        index = b.add_index("li",
                            [b.relative(victim), b.relative(sibling)])
        b.mark_free(victim)
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 2)

        report = load(b, root).bounded_traversal()
        # The healthy sibling must not be lost because of the free cell.
        self.assertIn("Sibling", names(report))
        self.assertNotIn("Victim", names(report))
        self.assertTrue(report.has_issue("free_cell"))

    def test_invalid_signature_reference_is_reported(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        decoy = b._write_cell(b"xx", b"\x00" * 8)
        index = b.add_index("li", [b.relative(decoy)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)

        report = load(b, root).bounded_traversal()
        self.assertTrue(report.has_issue("invalid_signature"))

    def test_bad_value_does_not_lose_the_key(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        # A bin value with an external data cell (length >= 5).
        vk = b.add_vk("Broken", Registry.RegBin, b"\x01\x02\x03\x04\x05")
        # Repoint the VK data offset at a free cell; reading the value must
        # be reported as an issue without losing the surrounding key.
        free_cell = b._write_cell(b"", b"\x00" * 16)
        b.mark_free(free_cell)
        # VK data-offset field is at data + 0x8 (cell header adds 4).
        b.patch_dword(vk + 4 + 0x8, b.relative(free_cell))
        values_list = b.add_values_list([vk])
        b.patch_nk_field(root, HiveBuilder.NK_VALUES_LIST,
                         b.relative(values_list))
        b.patch_nk_field(root, HiveBuilder.NK_VALUES_COUNT, 1)

        report = load(b, root).bounded_traversal()
        self.assertIn("ROOT", names(report))
        # The free data cell is reported and the value is not confirmed.
        self.assertTrue(report.has_issue("free_cell"))
        self.assertEqual(report.nodes[0].values, ())


class BudgetTests(unittest.TestCase):
    def _build_chain(self, length):
        b = HiveBuilder()
        root = b.add_nk("k0", None, root=True)
        previous = root
        cells = [root]
        for index in range(1, length):
            current = b.add_nk("k%d" % index, previous)
            index_cell = b.add_index("li", [b.relative(current)])
            b.patch_nk_field(previous, HiveBuilder.NK_SUBKEY_LIST,
                             b.relative(index_cell))
            b.patch_nk_field(previous, HiveBuilder.NK_SUBKEY_COUNT, 1)
            previous = current
            cells.append(current)
        return b, root, cells

    def test_node_budget_separates_confirmed_from_unfinished(self):
        b, root, cells = self._build_chain(10)
        report = load(b, root).bounded_traversal(max_nodes=4)

        self.assertTrue(report.truncated)
        self.assertFalse(report.completed)
        self.assertEqual(len(report.nodes), 4)
        self.assertTrue(report.has_issue("node_budget"))
        # Confirmed nodes are the first four along the chain.
        self.assertEqual(names(report), ["k0", "k1", "k2", "k3"])

    def test_depth_budget_separates_confirmed_from_unfinished(self):
        b, root, cells = self._build_chain(10)
        report = load(b, root).bounded_traversal(max_depth=2)

        self.assertTrue(report.truncated)
        self.assertEqual(names(report), ["k0", "k1", "k2"])
        self.assertTrue(report.has_issue("depth_budget"))

    def test_unlimited_budgets_still_terminate_on_cycle(self):
        b, root, _, _, _ = CycleTests()._build_key_cycle()
        report = load(b, root).bounded_traversal(
            max_nodes=None, max_depth=None)
        self.assertEqual(set(names(report)), {"ROOT", "Outer", "Inner"})
        self.assertTrue(report.has_issue("key_cycle"))


class ParentMismatchTests(unittest.TestCase):
    def test_corrupted_parent_pointer_is_flagged(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        child = b.add_nk("Child", root)
        # Corrupt the child's parent pointer to an unrelated hbin offset.
        b.patch_nk_field(child, HiveBuilder.NK_PARENT, 0x40)
        index = b.add_index("li", [b.relative(child)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)

        report = load(b, root).bounded_traversal()
        mismatches = report.issues_of_kind("parent_mismatch")
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0].cell_offset, child)
        # The named parent (0x1020) differs from the listing root cell.
        self.assertIn("0x%x" % (0x1000 + 0x40), mismatches[0].message)
        # The key itself remains a confirmed result.
        self.assertIn("Child", names(report))


class SubtreeTraversalTests(unittest.TestCase):
    def test_can_start_at_a_specific_key(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        branch = b.add_nk("Branch", root)
        leaf = b.add_nk("Leaf", branch)
        branch_index = b.add_index("li", [b.relative(leaf)])
        b.patch_nk_field(branch, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(branch_index))
        b.patch_nk_field(branch, HiveBuilder.NK_SUBKEY_COUNT, 1)
        root_index = b.add_index("li", [b.relative(branch)])
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_LIST,
                         b.relative(root_index))
        b.patch_nk_field(root, HiveBuilder.NK_SUBKEY_COUNT, 1)

        reg = load(b, root)
        start = reg.open("Branch")

        # Starting from a high level RegistryKey only walks its subtree.
        report = Traversal.BoundedTraversal(reg).traverse(start)
        self.assertEqual(names(report), ["Branch", "Leaf"])
        self.assertTrue(report.completed)
        self.assertEqual(report.nodes[0].depth, 0)

        # The convenience method accepts the same starting key.
        report2 = reg.bounded_traversal(start_key=start)
        self.assertEqual(names(report2), ["Branch", "Leaf"])

    def test_invalid_start_key_raises(self):
        b = HiveBuilder()
        root = b.add_nk("ROOT", None, root=True)
        reg = load(b, root)
        with self.assertRaises(Traversal.TraversalException):
            Traversal.BoundedTraversal(reg).traverse(12345)


class RealHiveSmokeTests(unittest.TestCase):
    def test_known_good_hive_traverses_without_issues(self):
        path = os.path.join(os.path.dirname(__file__),
                            "reg_samples", "issue22.hive")
        reg = Registry.Registry(path)
        report = reg.bounded_traversal()
        self.assertTrue(report.completed, report.issues)
        self.assertEqual(len(report.issues), 0, report.issues)
        self.assertTrue(len(report.nodes) >= 1)
        # Every confirmed node reports a real cell offset and bounded path.
        for node in report.nodes:
            self.assertGreater(node.cell_offset, 0x1000)
            self.assertTrue(node.key_path())


if __name__ == "__main__":
    unittest.main(verbosity=2)
