#    This file is part of python-registry.
#
#   Conservative difference interface for comparing two snapshots (hive files)
#   of the same Windows Registry hive.
#
#   The comparison identifies keys and values by their logical path and value
#   name, never by cell offset.  Offsets are recorded as provenance only, so a
#   cell that was reused by a different key cannot mask an add/delete, and a
#   pure relocation of storage cannot be reported as a content change.
#
#   Only facts directly provable from the two snapshots are reported.  Last
#   write timestamps are never inspected, so nothing here implies a user, an
#   execution order, or a wall-clock sequence.
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import Registry
from . import RegistryParse


@dataclass(frozen=True)
class ValueRecord:
    """
    One value of a key, captured with its raw bytes.

    `name` is the decoded value name; the default value (an empty on-disk
    name) is reported with `is_default` True and name "(default)".
    `raw_name` preserves the exact bytes stored for the name, while
    `name_encoding` records whether they were stored as ASCII or UTF-16LE.
    `raw_data` are the exact value bytes; `data_type` is the numeric registry
    type.  `vk_offset` / `data_offset` are provenance (cell locations), never
    identity.
    """
    name: str
    is_default: bool
    raw_name: bytes
    name_encoding: str
    data_type: int
    data_type_str: str
    raw_data: bytes
    vk_offset: int
    data_offset: int
    data_inline: bool


@dataclass(frozen=True)
class KeyRecord:
    """
    One key of a hive, captured with the raw bytes of its name and values.

    `path` joins the raw names with backslashes using the on-disk decoding;
    `path_parts` keeps each name separately so the original encoded name of
    every component is available in `raw_path_parts`.  `nk_offset` is the
    absolute offset of the NK cell (provenance only, never identity).
    """
    path: str
    path_parts: Tuple[str, ...]
    raw_path_parts: Tuple[bytes, ...]
    name_encodings: Tuple[str, ...]
    nk_offset: int
    values: Tuple[ValueRecord, ...]


@dataclass(frozen=True)
class ValueChange:
    kind: str = "value_changed"
    key_path: str = ""
    name: str = ""
    is_default: bool = False
    old: Optional[ValueRecord] = None
    new: Optional[ValueRecord] = None
    type_changed: bool = False
    data_changed: bool = False


@dataclass(frozen=True)
class Uncertainty:
    """
    A finding that cannot be resolved unambiguously from the two snapshots.
    `code` is a stable machine-readable identifier; `message` states only what
    the snapshots can actually support.
    """
    code: str
    message: str
    old_offset: Optional[int] = None
    new_offset: Optional[int] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None


@dataclass
class HiveDiff:
    added_keys: List[KeyRecord] = field(default_factory=list)
    removed_keys: List[KeyRecord] = field(default_factory=list)
    added_values: List[ValueChange] = field(default_factory=list)
    removed_values: List[ValueChange] = field(default_factory=list)
    changed_values: List[ValueChange] = field(default_factory=list)
    uncertainties: List[Uncertainty] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.added_keys or self.removed_keys or
                    self.added_values or self.removed_values or
                    self.changed_values)


def _raw_key_name(nk: RegistryParse.NKRecord) -> Tuple[bytes, str]:
    name_length = nk.unpack_word(0x48)
    raw = nk.unpack_string(0x4C, name_length)
    if nk.has_ascii_name():
        return raw, "ascii"
    return raw, "utf-16le"


def _raw_value_name(vk: RegistryParse.VKRecord) -> Tuple[bytes, str, str, bool]:
    if not vk.has_name():
        # The default value has an empty on-disk name; there are no raw bytes.
        return b"", "(default)", "empty", True
    name_length = vk.unpack_word(0x2)
    raw = vk.unpack_string(0x14, name_length)
    if vk.has_ascii_name():
        return raw, raw.decode("windows-1252"), "ascii", False
    return raw, raw.decode("utf-16le"), "utf-16le", False


def _is_inline(vk: RegistryParse.VKRecord) -> bool:
    # VKRecord.data_offset returns the offset *inside* the record when the
    # data fits in the data-offset field (length < 5 or the 0x80000000 bit).
    return vk.raw_data_length() < 5 or vk.raw_data_length() >= 0x80000000


def _make_value(vk: RegistryParse.VKRecord) -> ValueRecord:
    raw_name, name, encoding, is_default = _raw_value_name(vk)
    return ValueRecord(
        name=name,
        is_default=is_default,
        raw_name=raw_name,
        name_encoding=encoding,
        data_type=vk.data_type(),
        data_type_str=vk.data_type_str(),
        raw_data=vk.raw_data(),
        vk_offset=vk.offset(),
        data_offset=vk.data_offset(),
        data_inline=_is_inline(vk),
    )


def collect_snapshot(reg: Registry.Registry
                     ) -> Tuple[Dict[str, KeyRecord],
                                Dict[int, List[str]],
                                Dict[str, List[str]]]:
    """
    Walk every key reachable from the root and return:
      - a mapping of logical path (compared case-insensitively) to KeyRecord
      - a mapping of NK cell offset to the paths occupying that cell
      - a mapping of the lower-cased path to every actual path spelling seen

    The second mapping underpins cell-reuse detection across snapshots; the
    third makes case-only path collisions visible instead of silently folded
    together.  A structural cycle is broken by tracking visited NK offsets.
    """
    keys: Dict[str, KeyRecord] = {}
    offset_paths: Dict[int, List[str]] = {}
    path_spellings: Dict[str, List[str]] = {}
    visited: set = set()

    def walk(nk: RegistryParse.NKRecord,
             parts: Tuple[str, ...],
             raw_parts: Tuple[bytes, ...],
             encodings: Tuple[str, ...]) -> None:
        offset = nk.offset()
        if offset in visited:
            # Structural cycle; the same NK cell cannot define two logical keys.
            return
        visited.add(offset)

        raw_name, encoding = _raw_key_name(nk)
        name = nk.name()
        cur_parts = parts + (name,)
        cur_raw = raw_parts + (raw_name,)
        cur_enc = encodings + (encoding,)
        path = "\\".join(cur_parts)

        values: List[ValueRecord] = []
        try:
            for vk in nk.values_list().values():
                try:
                    values.append(_make_value(vk))
                except RegistryParse.RegistryException:
                    # An unparsable value must not silently disappear from the
                    # comparison.  Keep the cell offset as provenance even when
                    # its contents cannot be decoded.
                    try:
                        bad_offset = vk.offset()
                    except RegistryParse.RegistryException:
                        bad_offset = -1
                    values.append(ValueRecord(
                        name="<unparsable at 0x%x>" % bad_offset,
                        is_default=False,
                        raw_name=b"",
                        name_encoding="unknown",
                        data_type=-1,
                        data_type_str="Unparsable",
                        raw_data=b"",
                        vk_offset=bad_offset,
                        data_offset=-1,
                        data_inline=False,
                    ))
        except RegistryParse.RegistryStructureDoesNotExist:
            pass

        record = KeyRecord(
            path=path,
            path_parts=cur_parts,
            raw_path_parts=cur_raw,
            name_encodings=cur_enc,
            nk_offset=offset,
            values=tuple(values),
        )
        lower_path = path.lower()
        if lower_path not in keys:
            keys[lower_path] = record
        path_spellings.setdefault(lower_path, [])
        if path not in path_spellings[lower_path]:
            path_spellings[lower_path].append(path)
        offset_paths.setdefault(offset, []).append(path)

        try:
            subkeys = list(nk.subkey_list().keys())
        except RegistryParse.RegistryStructureDoesNotExist:
            subkeys = []
        for child in subkeys:
            walk(child, cur_parts, cur_raw, cur_enc)

    root = reg.root()._nkrecord
    walk(root, (), (), ())
    return keys, offset_paths, path_spellings


def _value_index(values: Iterable[ValueRecord]) -> Dict[str, List[ValueRecord]]:
    index: Dict[str, List[ValueRecord]] = {}
    for value in values:
        index.setdefault(value.name.lower(), []).append(value)
    return index


def _match_values(old_values: Tuple[ValueRecord, ...],
                  new_values: Tuple[ValueRecord, ...]
                  ) -> Tuple[List[Tuple[ValueRecord, ValueRecord]],
                             List[ValueRecord],
                             List[ValueRecord],
                             List[Uncertainty]]:
    """
    Match values by name (the only stable identity).  Duplicate names, which
    are legal at the storage level, are paired positionally and flagged as
    uncertain rather than guessed about.
    """
    old_index = _value_index(old_values)
    new_index = _value_index(new_values)
    pairs: List[Tuple[ValueRecord, ValueRecord]] = []
    only_old: List[ValueRecord] = []
    only_new: List[ValueRecord] = []
    uncertainties: List[Uncertainty] = []

    for key in sorted(set(old_index) | set(new_index)):
        old_group = old_index.get(key, [])
        new_group = new_index.get(key, [])
        if len(old_group) > 1 or len(new_group) > 1:
            uncertainties.append(Uncertainty(
                code="duplicate_value_name",
                message=("value name %r occurs %d time(s) in the old snapshot "
                         "and %d time(s) in the new snapshot; pairs are matched "
                         "positionally and may not be the same stored value"
                         % (key, len(old_group), len(new_group))),
            ))
        common = min(len(old_group), len(new_group))
        pairs.extend(zip(old_group[:common], new_group[:common]))
        only_old.extend(old_group[common:])
        only_new.extend(new_group[common:])
    return pairs, only_old, only_new, uncertainties


def diff_hives(old: Any, new: Any, root_path: Optional[str] = None) -> HiveDiff:
    """
    Compare two registry snapshots.

    `old` and `new` are either `Registry.Registry` instances or hive file
    paths.  If `root_path` is given, only keys at or below that path (matched
    case-insensitively, backslash separated, relative to the hive root) are
    compared; this is useful for restricting the report to a security subtree.

    Identity is the logical key path plus the value name.  Cell offsets are
    retained on every record but never used to match records.  Timestamps are
    not read, so the result makes no claim about who changed what or in which
    order.
    """
    old_reg = old if isinstance(old, Registry.Registry) else Registry.Registry(old)
    new_reg = new if isinstance(new, Registry.Registry) else Registry.Registry(new)

    old_keys, old_offsets, old_spellings = collect_snapshot(old_reg)
    new_keys, new_offsets, new_spellings = collect_snapshot(new_reg)

    if root_path is not None:
        prefix = root_path.strip("\\").lower()
        def _under(path_key: str) -> bool:
            return path_key == prefix or path_key.startswith(prefix + "\\")
        old_keys = {k: v for k, v in old_keys.items() if _under(k)}
        new_keys = {k: v for k, v in new_keys.items() if _under(k)}
        old_spellings = {k: v for k, v in old_spellings.items() if _under(k)}
        new_spellings = {k: v for k, v in new_spellings.items() if _under(k)}
        old_offsets = {
            off: [p for p in paths if _under(p.lower())]
            for off, paths in old_offsets.items()
        }
        new_offsets = {
            off: [p for p in paths if _under(p.lower())]
            for off, paths in new_offsets.items()
        }
        old_offsets = {k: v for k, v in old_offsets.items() if v}
        new_offsets = {k: v for k, v in new_offsets.items() if v}

    result = HiveDiff()

    old_paths = set(old_keys)
    new_paths = set(new_keys)

    for path_key in sorted(new_paths - old_paths):
        result.added_keys.append(new_keys[path_key])
    for path_key in sorted(old_paths - new_paths):
        result.removed_keys.append(old_keys[path_key])

    # Cell-reuse evidence: the same absolute cell offset now backs a different
    # logical path.  Recorded as uncertainty; it never changes add/remove sets,
    # because offsets are not identity.
    for offset, old_paths_here in sorted(old_offsets.items()):
        new_paths_here = new_offsets.get(offset)
        if not new_paths_here:
            continue
        if set(old_paths_here) != set(new_paths_here):
            result.uncertainties.append(Uncertainty(
                code="cell_reused",
                message=("NK cell at offset 0x%x backs %r in the old snapshot "
                         "but %r in the new snapshot; the cell was reused, so "
                         "offset-based matching would confuse distinct keys"
                         % (offset, old_paths_here, new_paths_here)),
                old_offset=offset,
                new_offset=offset,
                old_path=";".join(old_paths_here),
                new_path=";".join(new_paths_here),
            ))

    # Relocation evidence: a shared logical path moved to a different NK cell.
    # Provenance only; never a value/security change by itself.
    for path_key in sorted(old_paths & new_paths):
        old_record = old_keys[path_key]
        new_record = new_keys[path_key]
        if old_record.nk_offset != new_record.nk_offset:
            result.uncertainties.append(Uncertainty(
                code="key_relocated",
                message=("key %r moved from NK cell 0x%x to 0x%x without a "
                         "path change; this is a storage relocation, not a "
                         "configuration change"
                         % (old_record.path, old_record.nk_offset,
                            new_record.nk_offset)),
                old_offset=old_record.nk_offset,
                new_offset=new_record.nk_offset,
                old_path=old_record.path,
                new_path=new_record.path,
            ))

    # Possible rename evidence: one removed key and one added key whose value
    # sets are identical in raw bytes and types.  Stated as a possibility.
    for removed in result.removed_keys:
        removed_sig = _value_signature(removed)
        for added in result.added_keys:
            if removed_sig and removed_sig == _value_signature(added):
                result.uncertainties.append(Uncertainty(
                    code="possible_rename",
                    message=("removed key %r and added key %r hold the same "
                             "value names, types and raw bytes; this is "
                             "consistent with a rename, but the snapshots "
                             "cannot prove it"
                             % (removed.path, added.path)),
                    old_path=removed.path,
                    new_path=added.path,
                ))

    # Value-level comparison for keys present in both snapshots.
    for path_key in sorted(old_paths & new_paths):
        old_record = old_keys[path_key]
        new_record = new_keys[path_key]
        pairs, only_old, only_new, dup_notes = _match_values(old_record.values,
                                                             new_record.values)
        result.uncertainties.extend(dup_notes)

        for old_value, new_value in pairs:
            type_changed = old_value.data_type != new_value.data_type
            data_changed = old_value.raw_data != new_value.raw_data
            if type_changed or data_changed:
                result.changed_values.append(ValueChange(
                    key_path=old_record.path,
                    name=old_value.name,
                    is_default=old_value.is_default,
                    old=old_value,
                    new=new_value,
                    type_changed=type_changed,
                    data_changed=data_changed,
                ))

        for value in only_old:
            result.removed_values.append(ValueChange(
                key_path=old_record.path,
                name=value.name,
                is_default=value.is_default,
                old=value,
                new=None,
            ))
        for value in only_new:
            result.added_values.append(ValueChange(
                key_path=new_record.path,
                name=value.name,
                is_default=value.is_default,
                old=None,
                new=value,
            ))

    # Case-only path collisions (distinct raw names that compare equal) cannot
    # be represented unambiguously in the case-insensitive path index.
    _note_case_collisions(old_spellings, result, "old")
    _note_case_collisions(new_spellings, result, "new")

    return result


def _value_signature(key_record: KeyRecord) -> Tuple[Tuple[Any, ...], ...]:
    return tuple(sorted(
        (v.name.lower(), v.is_default, v.data_type, v.raw_data)
        for v in key_record.values
    ))


def _note_case_collisions(spellings: Dict[str, List[str]],
                          result: HiveDiff, label: str) -> None:
    for lower_path, paths in spellings.items():
        if len(paths) > 1:
            result.uncertainties.append(Uncertainty(
                code="case_insensitive_path_collision",
                message=("the %s snapshot contains %d keys whose paths differ "
                         "only in case (%r); they share a comparison key and "
                         "should be reviewed manually"
                         % (label, len(paths), sorted(paths))),
                old_path=lower_path if label == "old" else None,
                new_path=lower_path if label == "new" else None,
            ))
