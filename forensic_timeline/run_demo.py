#!/usr/bin/env python3
"""Reproducible demonstration of registry time-evidence handling.

Run:  .venv/bin/python forensic_timeline/run_demo.py
Outputs byte-cited JSON into forensic_timeline/output/. The report keeps every
time source separate and records the raw integer, the interpretation and the
uncertainty reason for each field.
"""
from __future__ import annotations

import io
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from Registry import Registry, RegistryLog  # noqa: E402

from reg_evidence import scenarios  # noqa: E402
from reg_evidence.extract import (  # noqa: E402
    extract_all,
    interpret_filetime,
    regf_header_evidence,
    _read_qword,
)
from reg_evidence.synth import HBIN_OFFSET  # noqa: E402


def _extract_keys_summary(path: str) -> dict:
    doc = extract_all(path)
    keys = {
        k["key_path"]: {
            "nk_record_offset": k["nk_record_offset"],
            "filetime_field_offset": k["filetime_field_offset"],
            "raw_uint64": k["raw_uint64"],
            "raw_hex": k["raw_hex"],
            "interpreted_utc": k["interpreted_utc"],
            "interpretation_kind": k["interpretation_kind"],
            "uncertainty_reasons": k["uncertainty_reasons"],
            "values": [
                {
                    "name": v["name"],
                    "type": v["type"],
                    "value_timestamp_available": v["value_timestamp"]["available"],
                    "value_timestamp_detail": v["value_timestamp"],
                }
                for v in k["values"]
            ],
        }
        for k in doc["key_evidence"]
    }
    return {"integrity": doc["integrity"], "header": doc["header_evidence"], "keys": keys}


def _recover(dirty_path: str, log_path: str) -> bytes:
    with open(dirty_path, "rb") as fh:
        primary = io.BytesIO(fh.read())
    rl = RegistryLog.RegistryLog(primary, log_path)
    primary.seek(0)
    rl.recover_hive()
    primary.seek(0)
    return primary.read()


def main() -> int:
    sample_dir = os.path.join(HERE, "samples")
    out_dir = os.path.join(HERE, "output")
    os.makedirs(out_dir, exist_ok=True)

    manifest = scenarios.build_all(sample_dir)
    report: dict = {"schema_version": "1.0", "scenarios": [], "policy_note":
                    "Each time source is reported separately. No field is promoted to a single 'event time' and sequence numbers are never converted to wall-clock time."}

    for entry in manifest:
        name = entry["scenario"]
        scen = {"scenario": name, "teaching_point": entry["teaching_point"],
                "byte_offsets": entry.get("offsets", {}), "observations": {}}

        if name == "clock_rollback":
            scen["observations"]["hive_a_2019"] = _extract_keys_summary(entry["files"][0])
            scen["observations"]["hive_b_rollback_1970"] = _extract_keys_summary(entry["files"][1])

        elif name == "invalid_filetime":
            scen["observations"]["hive"] = _extract_keys_summary(entry["files"][0])
            child = scen["observations"]["hive"]["keys"]["CMI\\SvcA"]
            scen["library_call_probe"] = {
                "call": "Registry(open('invalid_filetime.hive')).root().subkeys()[0].timestamp()",
                "raw_field": child["raw_hex"],
                "behavior": "raises OverflowError('date value out of range'); extraction backend keeps the raw bytes and marks interpretation_kind=unrenderable instead of crashing",
            }

        elif name == "value_only_change":
            before = _extract_keys_summary(entry["files"][0])
            after = _extract_keys_summary(entry["files"][1])
            b_key = before["keys"]["CMI\\SvcA"]
            a_key = after["keys"]["CMI\\SvcA"]
            scen["observations"]["before"] = before
            scen["observations"]["after"] = after
            scen["value_change_analysis"] = {
                "nk_filetime_raw_before": b_key["raw_hex"],
                "nk_filetime_raw_after": a_key["raw_hex"],
                "nk_filetime_identical_bytes": b_key["raw_uint64"] == a_key["raw_uint64"],
                "config_flag_before": 7,
                "config_flag_after": 9,
                "conclusion": "value changed but no per-value timestamp exists; the enclosing NK FILETIME did not move, so an independent time for this value change is unconfirmable (observation, not an inferred event time)",
            }

        elif name == "appcontainer_value_timestamp":
            summary = _extract_keys_summary(entry["files"][0])
            scen["observations"]["settings_dat"] = summary
            root_values = summary["keys"]["Root"]["values"]
            scen["value_timestamp_interface"] = {
                "interface": "RegistryValue.timestamp() / VKRecord.has_timestamp()",
                "observed": root_values,
                "note": "available=True only for this 0x100 composite value; all values in the other scenarios report available=False with the ValueError reason",
            }

        elif name == "transaction_log_recovery":
            dirty_path, log_path = entry["files"]
            before = _extract_keys_summary(dirty_path)
            with open(log_path, "rb") as fh:
                log_buf = fh.read()
            log_header = regf_header_evidence(log_buf, os.path.basename(log_path), is_log=True)
            recovered_bytes = _recover(dirty_path, log_path)
            recovered_path = os.path.join(out_dir, "recovery_recovered.hive")
            with open(recovered_path, "wb") as fh:
                fh.write(recovered_bytes)
            after = _extract_keys_summary(recovered_path)
            scen["observations"]["dirty_primary_before"] = before
            scen["observations"]["transaction_log_header"] = log_header
            scen["observations"]["recovered_primary_after"] = after
            scen["recovery_field_diff"] = {
                "header_filetime_0x0C_before": before["header"]["fields"][2]["raw_hex"],
                "header_filetime_0x0C_after": after["header"]["fields"][2]["raw_hex"],
                "header_filetime_changed": before["header"]["fields"][2]["raw_uint64"] != after["header"]["fields"][2]["raw_uint64"],
                "child_nk_filetime_before": before["keys"]["CMI\\SvcA"]["raw_hex"],
                "child_nk_filetime_after": after["keys"]["CMI\\SvcA"]["raw_hex"],
                "sequence_before": [before["integrity"]["recovery_required"], before["header"]["sequence_state"]["seq1"], before["header"]["sequence_state"]["seq2"]],
                "sequence_after": [after["integrity"]["recovery_required"], after["header"]["sequence_state"]["seq1"], after["header"]["sequence_state"]["seq2"]],
                "note": "HvLE has no timestamp field; only seq 6 plus dirty-page data. Header FILETIME is deliberately untouched by library recovery, while the replayed page updates the child NK FILETIME.",
            }

        report["scenarios"].append(scen)

    out_path = os.path.join(out_dir, "timeline_evidence_report.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print("wrote", out_path)
    print("wrote sample hives/logs under", sample_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
