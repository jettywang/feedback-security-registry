#!/usr/bin/env python
"""
Forensic recovery entry point: rebuild a Windows Registry hive from its
primary file and transaction logs into a *derived copy*, leaving the
original evidence untouched and read-only.

Usage:
    python recover_hive.py --primary SYSTEM --log SYSTEM.LOG1 --log SYSTEM.LOG2 \
        --output-dir OUTDIR [--plan-only]

The tool first prints the recovery plan (log selection and ordering by
sequence number, plus the page-overwrite plan), then writes:

    <output-dir>/<name>.recovered   derived hive, only when recovery is complete
    <output-dir>/<name>.partial     clearly-marked partial copy (gaps/skips)
    <output-dir>/<name>.manifest.json   plan, provenance, hashes, verdict

Exit codes: 0 = complete / not required, 1 = partial, 2 = failed, 3 = usage.
"""
from __future__ import print_function

import argparse
import json
import os
import sys

from Registry import RegistryRecovery


def _read_evidence(path):
    """Read an evidence file in binary read-only mode; never opened for writing."""
    with open(path, "rb") as f:
        return f.read()


def _print_plan(plan):
    print("=== Recovery plan ===")
    print("primary sha256:      %s" % plan.primary_sha256)
    print("primary sequences:   %s / %s (checksum valid: %s)" %
          (plan.primary_sequence1, plan.primary_sequence2,
           plan.primary_checksum_valid))
    print("recovery required:   header=%s data=%s" %
          (plan.recover_header, plan.recover_data))
    if plan.header_source_log:
        print("header restored from: %s" % plan.header_source_log)
    print("--- log selection (ordered by sequence numbers, not file names) ---")
    for log in plan.logs:
        line = "  %-8s %s" % (log["role"], os.path.basename(log["name"]))
        if log["rejected_reason"]:
            line += "  (%s)" % log["rejected_reason"]
        elif log["entry_sequences"]:
            seqs = log["entry_sequences"]
            line += "  entries %d..%d (%d valid)" % (seqs[0], seqs[-1], len(seqs))
        print(line)
    print("--- page overwrite plan (%d pages, writable limit 0x%x) ---" %
          (len(plan.pages), plan.hbins_limit or 0))
    for p in plan.pages[:20]:
        print("  seq=%-12d log=%s page=%d offset=0x%x size=0x%x" %
              (p.entry_sequence, os.path.basename(p.log_name), p.page_index,
               p.target_offset, p.size))
    if len(plan.pages) > 20:
        print("  ... and %d more pages" % (len(plan.pages) - 20))
    for gap in plan.gaps:
        print("GAP: sequence chain breaks at %d" % gap)
    for warning in plan.warnings:
        print("WARNING: %s" % warning)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Recover a registry hive from transaction logs into a derived copy.")
    parser.add_argument("--primary", required=True, help="primary hive file (read-only)")
    parser.add_argument("--log", action="append", default=[],
                        help="transaction log file (repeatable)")
    parser.add_argument("--output-dir", required=True,
                        help="directory for the derived hive and manifest")
    parser.add_argument("--plan-only", action="store_true",
                        help="print the recovery plan without writing anything")
    args = parser.parse_args(argv)

    if not args.log:
        print("error: at least one --log is required", file=sys.stderr)
        return 3

    primary_path = os.path.abspath(args.primary)
    primary_data = _read_evidence(primary_path)
    logs = [(os.path.abspath(p), _read_evidence(p)) for p in args.log]

    # Evidence hashes before recovery; re-checked afterwards to prove the
    # originals were never modified.
    before = {primary_path: RegistryRecovery.sha256_hex(primary_data)}
    before.update({name: RegistryRecovery.sha256_hex(data) for name, data in logs})

    candidates = [RegistryRecovery.LogCandidate(name, data) for name, data in logs]
    plan = RegistryRecovery.plan_recovery(primary_data, candidates)
    _print_plan(plan)

    if args.plan_only:
        return 0

    result = RegistryRecovery.execute_plan(primary_data, plan)
    print("=== Recovery result: %s ===" % result.status.upper())

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.basename(primary_path)

    if result.derived_data is not None:
        if result.status in (RegistryRecovery.STATUS_COMPLETE,
                             RegistryRecovery.STATUS_NOT_REQUIRED):
            out_name = base + ".recovered"
        else:
            # Partial or unverifiable copies are clearly marked and never
            # presented as a successful recovery.
            out_name = base + ".partial"
        out_path = os.path.join(args.output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(result.derived_data)
        print("derived hive: %s (sha256 %s)" % (out_path, result.derived_sha256))
    else:
        print("no derived hive written; diagnostics only")

    manifest = result.to_manifest()
    manifest["evidence_sha256_before"] = before

    # Prove the originals are untouched.
    after = {p: RegistryRecovery.sha256_hex(_read_evidence(p))
             for p in [primary_path] + [name for name, _ in logs]}
    manifest["evidence_sha256_after"] = after
    manifest["evidence_unmodified"] = (before == after)
    if not manifest["evidence_unmodified"]:
        print("FATAL: original evidence changed during recovery", file=sys.stderr)
        return 2

    manifest_path = os.path.join(args.output_dir, base + ".manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    print("manifest: %s" % manifest_path)

    for page in result.provenance[:20]:
        print("  page offset=0x%x size=0x%x <- %s seq=%d page=%d [%s]" %
              (page.target_offset, page.size, os.path.basename(page.log_name),
               page.entry_sequence, page.page_index, page.status))

    if result.status in (RegistryRecovery.STATUS_COMPLETE,
                         RegistryRecovery.STATUS_NOT_REQUIRED):
        return 0
    if result.status == RegistryRecovery.STATUS_PARTIAL:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
