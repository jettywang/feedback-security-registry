import io

from Registry import Registry
from Registry.diff import (
    collect_snapshot,
    diff_hives,
)
from Registry.RegistryParse import RegSZ, RegDWord, RegBin

from tests.synthetic_hive import (
    SKey,
    SValue,
    SyntheticHiveBuilder,
)


def _hive(root):
    return Registry.Registry(io.BytesIO(SyntheticHiveBuilder(root).build()))


def _paths(records):
    return sorted(r.path for r in records)


def _by_name(changes):
    return {c.name: c for c in changes}


def test_identical_snapshots_have_no_changes():
    root = SKey("CMI", subkeys=[
        SKey("Policy", values=[SValue("Level", RegDWord, b"\x01\x00\x00\x00")])
    ])
    diff = diff_hives(_hive(root), _hive(root))
    assert diff.is_empty()
    assert diff.uncertainties == []


def test_added_and_removed_values_are_detected():
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Keep", RegDWord, b"\x01\x00\x00\x00"),
        SValue("Gone", RegSZ, "x".encode("utf-16le")),
    ])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Keep", RegDWord, b"\x01\x00\x00\x00"),
        SValue("Added", RegDWord, b"\x02\x00\x00\x00"),
    ])])
    diff = diff_hives(_hive(old), _hive(new))

    assert [c.name for c in diff.removed_values] == ["Gone"]
    assert [c.name for c in diff.added_values] == ["Added"]
    assert diff.changed_values == []
    assert diff.added_keys == [] and diff.removed_keys == []


def test_data_and_type_changes_are_distinguished_and_raw_based():
    # Same displayed text "1": one is a REG_SZ, the other a REG_DWORD.  The
    # diff must report both a type change and a raw data change rather than
    # treating the rendered values as equal.
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Setting", RegSZ, "1".encode("utf-16le")),
    ])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Setting", RegDWord, b"\x01\x00\x00\x00"),
    ])])
    diff = diff_hives(_hive(old), _hive(new))

    assert len(diff.changed_values) == 1
    change = diff.changed_values[0]
    assert change.name == "Setting"
    assert change.type_changed is True
    assert change.data_changed is True
    assert change.old.data_type == RegSZ
    assert change.new.data_type == RegDWord
    assert change.old.raw_data != change.new.raw_data


def test_type_change_alone_with_equal_text_is_still_reported():
    # REG_SZ "ab" versus REG_EXPAND_SZ "ab": identical rendered text and
    # identical raw bytes, but the security-relevant type differs.
    from Registry.RegistryParse import RegExpandSZ
    raw = "ab".encode("utf-16le")
    old = SKey("CMI", subkeys=[SKey("Policy", values=[SValue("P", RegSZ, raw)])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[SValue("P", RegExpandSZ, raw)])])
    diff = diff_hives(_hive(old), _hive(new))
    change = diff.changed_values[0]
    assert change.type_changed is True
    assert change.data_changed is False


def test_default_value_and_empty_name_are_handled_explicitly():
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("", RegSZ, "off".encode("utf-16le"), default=True),
    ])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("", RegSZ, "on".encode("utf-16le"), default=True),
    ])])
    diff = diff_hives(_hive(old), _hive(new))
    change = diff.changed_values[0]
    assert change.is_default is True
    assert change.name == "(default)"
    assert change.old.raw_name == b""
    assert change.old.name_encoding == "empty"
    assert change.old.raw_data != change.new.raw_data


def test_same_offset_different_key_reuse_does_not_mask_add_remove():
    # Pin the leaf NK cell to one fixed offset.  Snapshot A places
    # OldPolicy there; snapshot B reuses the very same cell for NewPolicy and
    # adds a second key.  Path-based identity must still show a removal and
    # additions, and the reuse must be surfaced as an uncertainty.
    fixed = 0x800  # HBIN-relative cell offset for the pinned leaf cell
    old_root = SKey("CMI", subkeys=[
        SKey("OldPolicy", fixed_cell_rel=fixed, values=[
            SValue("Flag", RegDWord, b"\x01\x00\x00\x00"),
        ]),
    ])
    new_root = SKey("CMI", subkeys=[
        SKey("NewPolicy", fixed_cell_rel=fixed, values=[
            SValue("Flag", RegDWord, b"\x01\x00\x00\x00"),
        ]),
        SKey("ExtraPolicy"),
    ])

    old_hive = _hive(old_root)
    new_hive = _hive(new_root)

    old_keys, old_offsets, _ = collect_snapshot(old_hive)
    new_keys, new_offsets, _ = collect_snapshot(new_hive)

    old_leaf = old_keys["cmi\\oldpolicy"]
    new_leaf = new_keys["cmi\\newpolicy"]
    assert old_leaf.nk_offset == new_leaf.nk_offset  # the cell was reused

    diff = diff_hives(old_hive, new_hive)
    assert _paths(diff.removed_keys) == ["CMI\\OldPolicy"]
    assert _paths(diff.added_keys) == ["CMI\\ExtraPolicy", "CMI\\NewPolicy"]

    reuse_notes = [u for u in diff.uncertainties if u.code == "cell_reused"]
    assert len(reuse_notes) == 1
    note = reuse_notes[0]
    assert note.old_path == "CMI\\OldPolicy"
    assert note.new_path == "CMI\\NewPolicy"
    assert note.old_offset == note.new_offset == old_leaf.nk_offset


def test_relocation_to_new_cell_is_not_reported_as_value_change():
    # The same logical key/value moves to a different cell because another
    # key was inserted ahead of it.  Nothing about the security value may
    # appear as a change; only a relocation uncertainty is allowed.
    common_leaf = lambda: SKey("Audit", values=[
        SValue("Level", RegDWord, b"\x03\x00\x00\x00"),
        SValue("Note", RegBin, b"\xaa\xbb\xcc", force_external=True),
    ])
    old_root = SKey("CMI", subkeys=[common_leaf()])
    new_root = SKey("CMI", subkeys=[SKey("InsertedBefore"), common_leaf()])

    old_hive = _hive(old_root)
    new_hive = _hive(new_root)

    old_keys, _, _ = collect_snapshot(old_hive)
    new_keys, _, _ = collect_snapshot(new_hive)
    assert old_keys["cmi\\audit"].nk_offset != new_keys["cmi\\audit"].nk_offset

    diff = diff_hives(old_hive, new_hive)
    # The only structural finding is the genuinely new key; no value-level
    # changes and no add/remove for the relocated Audit key.
    assert diff.changed_values == []
    assert diff.added_values == [] and diff.removed_values == []
    assert _paths(diff.removed_keys) == []
    assert _paths(diff.added_keys) == ["CMI\\InsertedBefore"]
    audit_notes = [u for u in diff.uncertainties if u.code == "key_relocated"
                   and u.old_path == "CMI\\Audit"]
    assert len(audit_notes) == 1
    assert audit_notes[0].old_offset != audit_notes[0].new_offset

    # No value-level finding may reference the relocated key.
    for change in (diff.changed_values + diff.added_values + diff.removed_values):
        assert change.key_path != "CMI\\Audit"


def test_possible_rename_is_uncertain_not_asserted():
    # A removed key and an added key with byte-identical values look like a
    # rename, but the snapshots cannot prove it.  It must remain an add/remove
    # pair plus a single possible_rename uncertainty.
    values = [SValue("Flag", RegDWord, b"\x07\x00\x00\x00")]
    old_root = SKey("CMI", subkeys=[SKey("OldName", values=values)])
    new_root = SKey("CMI", subkeys=[SKey("NewName",
                                         values=[SValue("Flag", RegDWord,
                                                         b"\x07\x00\x00\x00")])])
    diff = diff_hives(_hive(old_root), _hive(new_root))
    assert _paths(diff.removed_keys) == ["CMI\\OldName"]
    assert _paths(diff.added_keys) == ["CMI\\NewName"]
    notes = [u for u in diff.uncertainties if u.code == "possible_rename"]
    assert len(notes) == 1
    assert notes[0].old_path == "CMI\\OldName"
    assert notes[0].new_path == "CMI\\NewName"


def test_offsets_are_provenance_only_and_preserved_on_records():
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Blob", RegBin, bytes(range(8)), force_external=True),
    ])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Blob", RegBin, bytes(range(8)), force_external=True),
        SValue("More", RegBin, b"\x01\x02\x03\x04\x05", force_external=True),
    ])])
    diff = diff_hives(_hive(old), _hive(new))
    added = diff.added_values[0]
    assert added.new.vk_offset > 0
    assert added.new.data_offset > 0
    assert added.new.data_inline is False

    # Inline storage (a four-byte DWORD) is flagged explicitly as well.
    inline_hive = _hive(SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Dword", RegDWord, b"\x01\x00\x00\x00"),
    ])]))
    keys, _, _ = collect_snapshot(inline_hive)
    inline_value = keys["cmi\\policy"].values[0]
    assert inline_value.data_inline is True

    # A key record keeps the raw bytes of every path component and name.
    keys, _, _ = collect_snapshot(_hive(SKey("CMI", subkeys=[SKey("Policy")])))
    record = keys["cmi\\policy"]
    assert record.raw_path_parts == ("CMI".encode("utf-16le"),
                                     "Policy".encode("utf-16le"))
    assert record.name_encodings == ("utf-16le", "utf-16le")


def test_root_path_scoping_limits_comparison():
    old = SKey("CMI", subkeys=[
        SKey("Security", subkeys=[SKey("A", values=[
            SValue("V", RegDWord, b"\x01\x00\x00\x00")])]),
        SKey("Other", subkeys=[SKey("B")]),
    ])
    new = SKey("CMI", subkeys=[
        SKey("Security", subkeys=[SKey("A", values=[
            SValue("V", RegDWord, b"\x02\x00\x00\x00")])]),
        SKey("Other", subkeys=[SKey("B"), SKey("C")]),
    ])
    diff = diff_hives(_hive(old), _hive(new), root_path="CMI\\Security")
    assert len(diff.changed_values) == 1
    assert diff.added_keys == [] and diff.removed_keys == []


def test_duplicate_value_names_are_flagged_uncertain():
    # Two values sharing one name are legal at the storage level.  Matching is
    # positional and the ambiguity must be surfaced rather than guessed.
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Dup", RegDWord, b"\x01\x00\x00\x00"),
        SValue("Dup", RegDWord, b"\x02\x00\x00\x00"),
    ])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("Dup", RegDWord, b"\x01\x00\x00\x00"),
        SValue("Dup", RegDWord, b"\x09\x00\x00\x00"),
    ])])
    diff = diff_hives(_hive(old), _hive(new))
    notes = [u for u in diff.uncertainties if u.code == "duplicate_value_name"]
    assert len(notes) == 1
    # The positional second pair still reports its raw difference honestly.
    assert any(c.name == "Dup" and c.data_changed for c in diff.changed_values)


def test_raw_key_name_bytes_are_preserved_for_ascii_and_utf16():
    root = SKey("CMI", subkeys=[
        SKey("AsciiKey", ascii_name=True),
        SKey("Unicodeé"),
    ])
    keys, _, _ = collect_snapshot(_hive(root))
    ascii_record = keys["cmi\\asciikey"]
    unicode_record = keys["cmi\\unicodeé"]
    assert ascii_record.name_encodings == ("utf-16le", "ascii")
    assert ascii_record.raw_path_parts[1] == b"AsciiKey"
    assert unicode_record.raw_path_parts[1] == "Unicodeé".encode("utf-16le")


def test_timestamps_are_not_part_of_identity_or_findings():
    # The builder always writes zero timestamps; even so, the diff module
    # must expose no timestamp-derived field on changes or uncertainties.
    old = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("V", RegDWord, b"\x01\x00\x00\x00")])])
    new = SKey("CMI", subkeys=[SKey("Policy", values=[
        SValue("V", RegDWord, b"\x02\x00\x00\x00")])])
    diff = diff_hives(_hive(old), _hive(new))
    change = diff.changed_values[0]
    assert not hasattr(change, "timestamp")
    for uncertainty in diff.uncertainties:
        assert not hasattr(uncertainty, "timestamp")
