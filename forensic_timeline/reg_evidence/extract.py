"""Backend extraction of registry time evidence.

Design rule: every time source is reported independently. The module never
fuses REGF header times, NK last-written times, log sequence numbers or value
timestamps into one "event time". Each record carries the raw integer, the
exact byte location, a best-effort interpretation and an explicit uncertainty
classification so an analyst can separate observed bytes from inference.
"""
from __future__ import annotations

import datetime as _dt
import struct
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp

EPOCH_1601 = _dt.datetime(1601, 1, 1)
# Windows FILETIME is meaningful roughly between the 1601 epoch and year 9999.
FILETIME_MIN = 0
FILETIME_MAX_DATETIME = 2650467743999999999  # largest value datetime can render
# Forensic plausibility floor: the Windows registry did not exist before 1980.
# A value that decodes earlier is structurally parseable but not trustworthy as
# a real write time (clock rollback, corruption, an unset field, tampering).
PLAUSIBLE_FLOOR = 119600064000000000        # 1980-01-01 00:00:00 UTC
PLAUSIBLE_CEIL = FILETIME_MAX_DATETIME


@dataclass
class TimeInterpretation:
    raw_uint64: int
    raw_hex: str
    interpreted_utc: Optional[str]
    interpretation_kind: str          # valid | zero_epoch | implausible | unrenderable
    uncertainty_reasons: list[str] = field(default_factory=list)

    def is_wallclock_reliable(self) -> bool:
        return self.interpretation_kind == "valid" and not self.uncertainty_reasons


def interpret_filetime(raw: int) -> TimeInterpretation:
    """Interpret a raw FILETIME without raising; never hide the raw integer."""
    reasons: list[str] = []
    kind = "valid"
    interpreted: Optional[str] = None

    if raw == 0:
        kind = "zero_epoch"
        interpreted = EPOCH_1601.isoformat() + "Z"
        reasons.append("raw value is 0; library renders 1601-01-01 but this usually means 'never written' / unset, not a real event")
    elif raw > FILETIME_MAX_DATETIME:
        kind = "unrenderable"
        reasons.append("value exceeds datetime range; parse_windows_timestamp() raises OverflowError, no UTC time exists")
    else:
        interpreted_dt = parse_windows_timestamp(raw)
        interpreted = interpreted_dt.isoformat() + "Z"
        if raw < PLAUSIBLE_FLOOR:
            kind = "implausible"
            reasons.append("decodes before 1980; structurally parseable FILETIME but not a trustworthy Windows write time (clock rollback / skew / corruption / tampering); keep the raw value, do not treat the decoded date as an observed event")

    return TimeInterpretation(
        raw_uint64=raw,
        raw_hex="0x%016X" % raw,
        interpreted_utc=interpreted,
        interpretation_kind=kind,
        uncertainty_reasons=reasons,
    )


def _read_qword(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def _read_dword(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def regf_header_evidence(buf: bytes, source_label: str, is_log: bool = False) -> dict[str, Any]:
    """REGF base block fields with exact byte offsets.

    Header semantics (do not over-claim):
      0x0C modification timestamp = last flush of this hive image to disk.
      0xA8 reorganized timestamp  = only meaningful on Win8+; garbage earlier.
      0x04/0x08 sequence numbers  = transaction counters, NOT wall-clock times.
    """
    seq1 = _read_dword(buf, 0x04)
    seq2 = _read_dword(buf, 0x08)
    mod_raw = _read_qword(buf, 0x0C)
    reorg_raw = _read_qword(buf, 0xA8)

    seq_reasons = []
    if seq1 != seq2:
        seq_reasons.append("seq1 != seq2: hive was mid-update; on-disk data predates an incomplete transaction, apply logs before trusting key state")
    if is_log:
        seq_reasons.append("sequence numbers in a LOG file order HvLE entries only; they carry no wall-clock component and cannot be converted to a time")

    return {
        "evidence_source": "regf_header",
        "source_file": source_label,
        "file_kind": "transaction_log" if is_log else "primary_hive",
        "fields": [
            {
                "field": "hive_sequence1",
                "byte_offset": "0x04",
                "raw_uint32": seq1,
                "meaning": "incremented before a primary-file write; transaction counter, not a timestamp",
            },
            {
                "field": "hive_sequence2",
                "byte_offset": "0x08",
                "raw_uint32": seq2,
                "meaning": "set equal to sequence1 once a primary-file write completes; transaction counter, not a timestamp",
            },
            {
                "field": "modification_timestamp",
                "byte_offset": "0x0C",
                **asdict(interpret_filetime(mod_raw)),
                "meaning": "last time this hive image was flushed to disk; a single header value for the whole file, not per-key",
                "limitations": [
                    "not updated by RegistryLog recovery in python-registry (only seq/hbins_size/flags/checksum are rewritten)",
                    "transaction log REGF headers snapshot the primary header and frequently repeat an identical stale FILETIME",
                ],
            },
            {
                "field": "reorganized_timestamp",
                "byte_offset": "0xA8",
                **asdict(interpret_filetime(reorg_raw)),
                "meaning": "last hive reorganization (defragmentation) time; used from Windows 8 onward",
                "limitations": ["library docs state the value is garbage on pre-Windows-8 hives"],
            },
        ],
        "sequence_state": {
            "seq1": seq1,
            "seq2": seq2,
            "consistent": seq1 == seq2,
            "uncertainty_reasons": seq_reasons,
            "wallclock_inference": None,
            "wallclock_inference_note": "sequence numbers establish ordering only; this tool intentionally refuses to derive a wall-clock time from them",
        },
    }


def nk_key_evidence(registry: Registry, source_label: str) -> list[dict[str, Any]]:
    """Walk every NK record; report last-written FILETIME with its byte offset."""
    out: list[dict[str, Any]] = []

    def visit(key: "Registry.RegistryKey") -> None:
        nk = key._nkrecord
        record_abs = nk.offset()                 # absolute file offset of the NK record ('nk')
        filetime_abs = record_abs + 0x4
        raw = _read_qword(registry._buf, filetime_abs)
        interpretation = interpret_filetime(raw)
        values_info = []
        for value in key.values():
            vk = value._vkrecord
            values_info.append({
                "name": value.name(),
                "type": value.value_type_str(),
                "vk_record_offset": hex(vk.offset()),
                "has_value_timestamp": vk.has_timestamp(),
                "value_timestamp": _safe_value_timestamp(value),
            })
        out.append({
            "evidence_source": "nk_last_written",
            "source_file": source_label,
            "key_path": key.path(),
            "nk_record_offset": hex(record_abs),
            "filetime_field_offset": hex(filetime_abs),
            **asdict(interpretation),
            "meaning": "NK last-written time: updated when the key, its values or its security descriptor are created/modified/written by the Configuration Manager",
            "limitations": [
                "granularity is per key; there is no per-value timestamp in standard hives",
                "a value-only modification updates the parent key time but does not identify which value changed",
                "subject to the host clock; rollback/skew/tampering is not detectable from this field alone",
            ],
            "values": values_info,
        })
        for subkey in key.subkeys():
            visit(subkey)

    visit(registry.root())
    return out


def _safe_value_timestamp(value: "Registry.RegistryValue") -> Optional[dict[str, Any]]:
    """Probe the value-level timestamp interface without assuming it exists."""
    vk = value._vkrecord
    if not vk.has_timestamp():
        return {
            "available": False,
            "reason": "VK data type lacks the 0x100 AppContainer composite flag; RegistryValue.timestamp() would raise ValueError",
        }
    raw = struct.unpack_from("<Q", vk.raw_data()[-8:])[0]
    return {
        "available": True,
        "byte_location": "final 8 bytes of the VK value data (settings.dat composite value only)",
        **asdict(interpret_filetime(raw)),
        "scope_note": "only populated in AppContainer settings.dat hives; absent from SYSTEM/SOFTWARE/NTUSER.DAT and most standard hives",
    }


def extract_all(hive_path: str, source_label: Optional[str] = None) -> dict[str, Any]:
    """Parse a primary hive and return the full separated-evidence document."""
    label = source_label or hive_path
    with open(hive_path, "rb") as handle:
        buf = handle.read()
    registry = Registry.Registry(hive_path)
    regf = registry._regf
    return {
        "schema_version": "1.0",
        "source_file": label,
        "hive_name": registry.hive_name(),
        "integrity": {
            "checksum_valid": regf.validate_checksum(),
            "sequence_consistent": regf.validate_sequence_numbers(),
            "recovery_required": {
                "recover_header": regf.recovery_required().recover_header,
                "recover_data": regf.recovery_required().recover_data,
            },
        },
        "header_evidence": regf_header_evidence(buf, label, is_log=False),
        "key_evidence": nk_key_evidence(registry, label),
        "fusion_policy": "sources are kept separate; no single event_time is produced and no wall-clock time is derived from sequence numbers",
    }
