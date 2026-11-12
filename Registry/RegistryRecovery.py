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
Forensic transaction-log recovery for Windows Registry hives.

This module builds on Registry.RegistryParse to produce a *recovered copy*
of a primary hive from its transaction log files, without ever modifying
the original evidence. Recovery is split into two explicit phases:

1. plan_recovery()  - inspects the primary hive and the candidate logs,
   selects and orders the logs by sequence numbers (never by file name),
   and produces a page-overwrite plan.
2. execute_plan()   - applies the plan to an in-memory copy and returns
   the derived hive together with per-page provenance.

Every modified range of the derived hive is traceable to a concrete log
file, log entry sequence number, and dirty-page index.
"""
from __future__ import absolute_import

import hashlib
from ctypes import c_uint32, c_int32
from struct import pack

from Registry import RegistryParse

# Recovery outcomes.
STATUS_COMPLETE = "complete"            # every required log entry applied and verified
STATUS_PARTIAL = "partial"              # a consistent prefix was applied; gaps/skips remain
STATUS_FAILED = "failed"                # no usable recovery could be performed
STATUS_NOT_REQUIRED = "not_required"    # the primary hive was already clean

# Page-action outcomes.
PAGE_APPLIED = "applied"
PAGE_SKIPPED_OUT_OF_BOUNDS = "skipped_out_of_bounds"

UINT32_MOD = 0x100000000


def sha256_hex(data):
    """Return the hex SHA-256 of a bytes-like object."""
    return hashlib.sha256(bytes(data)).hexdigest()


def _seq_delta(newer, older):
    """
    Signed 32-bit distance from `older` to `newer` sequence numbers.
    Positive means `newer` follows `older`; correct across wraparound.
    """
    return c_int32(c_uint32(newer - older).value).value


def _seq_next(seq):
    """The sequence number following `seq`, with 32-bit wraparound."""
    return c_uint32(seq + 1).value


class LogCandidate(object):
    """
    A parsed transaction log offered for recovery.
    Parsing is best-effort: unusable files are kept with a rejection reason
    so the plan can report them instead of crashing.
    """
    def __init__(self, name, data):
        self.name = name
        self.data = bytes(data)
        self.sha256 = sha256_hex(self.data)
        self.regf = None
        self.rejected_reason = None
        self.truncated = False
        self.entries = []  # valid HvLE entries, in file order

        try:
            regf = RegistryParse.REGFBlock(self.data, 0, False)
        except Exception as e:
            self.rejected_reason = "unparseable REGF block: %s" % (e,)
            return

        if regf.is_old_transaction_log_file():
            self.rejected_reason = "old transaction log format is not supported"
            return
        if regf.is_primary_file():
            self.rejected_reason = "primary file supplied as a transaction log"
            return
        if not regf.is_new_transaction_log_file():
            self.rejected_reason = "unknown file type"
            return
        if regf.clustering_factor() != 1:
            self.rejected_reason = "clustering factor not equal to 1 is not supported"
            return

        recover = regf.recovery_required()
        if recover.recover_header or recover.recover_data:
            self.rejected_reason = "transaction log requires self-healing"
            return

        self.regf = regf
        try:
            self.entries = list(regf.log_entries())
        except Exception as e:
            self.rejected_reason = "log entries could not be enumerated: %s" % (e,)
            self.entries = []

        # A corrupt entry (e.g. bad Marvin32 checksum) ends the valid chain
        # inside the log. Non-zero data beyond the last valid entry means
        # updates were lost; record it so the copy is not marked complete.
        self.truncated = False
        if self.rejected_reason is None:
            if self.entries:
                end = self.entries[-1]._offset_next_hvle
                trailing = self.data[end:]
            else:
                trailing = self.data[0x200:]
            if trailing.strip(b"\x00"):
                self.truncated = True

    def first_log_sequence(self):
        """The first log sequence number (hive_sequence2 of the log header)."""
        if self.regf is None:
            return None
        return self.regf.hive_sequence2()


class PageAction(object):
    """One planned or applied dirty-page overwrite, with provenance."""
    def __init__(self, log_name, log_sha256, entry_sequence, page_index,
                 target_offset, size):
        self.log_name = log_name
        self.log_sha256 = log_sha256
        self.entry_sequence = entry_sequence
        self.page_index = page_index
        self.target_offset = target_offset
        self.size = size
        self.status = "planned"
        self.data_sha256 = None

    def to_dict(self):
        return {
            "log_name": self.log_name,
            "log_sha256": self.log_sha256,
            "entry_sequence": self.entry_sequence,
            "page_index": self.page_index,
            "target_offset": self.target_offset,
            "size": self.size,
            "status": self.status,
            "data_sha256": self.data_sha256,
        }


class RecoveryPlan(object):
    """
    The result of plan_recovery(): log selection, ordering, the sequence
    chain to replay, the page-overwrite plan, and any gaps or warnings.
    """
    def __init__(self, primary_sha256):
        self.primary_sha256 = primary_sha256
        self.primary_sequence1 = None
        self.primary_sequence2 = None
        self.primary_checksum_valid = None
        self.primary_hbins_size = None
        self.recover_header = False
        self.recover_data = False
        self.header_source_log = None
        self.logs = []            # list of dicts describing each candidate log
        self.chain = []           # list of (sequence, LogCandidate, HvLEBlock)
        self.pages = []           # list of PageAction, in application order
        self.gaps = []            # sequence numbers where the chain broke
        self.warnings = []
        self.hbins_limit = None   # derived hives may not be written past this offset

    def to_dict(self):
        return {
            "primary_sha256": self.primary_sha256,
            "primary_sequence1": self.primary_sequence1,
            "primary_sequence2": self.primary_sequence2,
            "primary_checksum_valid": self.primary_checksum_valid,
            "primary_hbins_size": self.primary_hbins_size,
            "recover_header": self.recover_header,
            "recover_data": self.recover_data,
            "header_source_log": self.header_source_log,
            "logs": self.logs,
            "chain": [{"sequence": seq, "log_name": log.name}
                      for seq, log, _entry in self.chain],
            "pages": [p.to_dict() for p in self.pages],
            "gaps": self.gaps,
            "warnings": self.warnings,
            "hbins_limit": self.hbins_limit,
        }


class RecoveryResult(object):
    """The outcome of execute_plan()."""
    def __init__(self, plan):
        self.plan = plan
        self.status = STATUS_FAILED
        self.derived_data = None        # bytes of the recovered copy (or None)
        self.derived_sha256 = None
        self.diagnostic_only = True     # False only when the copy is complete
        self.final_sequence = None
        self.final_hbins_size = None
        self.verification = {}
        self.provenance = []            # PageAction list, after execution

    def to_manifest(self):
        return {
            "status": self.status,
            "diagnostic_only": self.diagnostic_only,
            "primary_sha256": self.plan.primary_sha256,
            "derived_sha256": self.derived_sha256,
            "final_sequence": self.final_sequence,
            "final_hbins_size": self.final_hbins_size,
            "verification": self.verification,
            "plan": self.plan.to_dict(),
            "provenance": [p.to_dict() for p in self.provenance],
        }


def _describe_log(candidate, role):
    return {
        "name": candidate.name,
        "sha256": candidate.sha256,
        "role": role,
        "first_log_sequence": candidate.first_log_sequence(),
        "valid_entry_count": len(candidate.entries),
        "entry_sequences": [e.sequence() for e in candidate.entries],
        "truncated": candidate.truncated,
        "rejected_reason": candidate.rejected_reason,
    }


def plan_recovery(primary_data, log_candidates):
    """
    Build a RecoveryPlan for a primary hive and its transaction logs.

    Arguments:
    - `primary_data`: bytes of the primary hive (never modified).
    - `log_candidates`: list of LogCandidate (or (name, bytes) tuples).

    Logs are selected and ordered purely by sequence numbers; file names
    and the order in which logs are supplied are irrelevant.
    """
    candidates = [c if isinstance(c, LogCandidate) else LogCandidate(c[0], c[1])
                  for c in log_candidates]
    plan = RecoveryPlan(sha256_hex(primary_data))

    try:
        primary_regf = RegistryParse.REGFBlock(primary_data, 0, False)
    except Exception as e:
        plan.warnings.append("primary hive REGF block is unparseable: %s" % (e,))
        for c in candidates:
            plan.logs.append(_describe_log(c, "unusable"))
        return plan

    plan.primary_sequence1 = primary_regf.hive_sequence1()
    plan.primary_sequence2 = primary_regf.hive_sequence2()
    plan.primary_checksum_valid = primary_regf.validate_checksum()
    plan.primary_hbins_size = primary_regf.hbins_size()

    recover = primary_regf.recovery_required()
    plan.recover_header = recover.recover_header
    plan.recover_data = recover.recover_data

    if not recover.recover_header and not recover.recover_data:
        for c in candidates:
            plan.logs.append(_describe_log(c, "not_needed"))
        plan.hbins_limit = primary_regf.first_hbin_offset() + plan.primary_hbins_size
        return plan

    # Eligibility: a log may continue the primary when its first sequence
    # number is not older than the primary's second sequence number
    # (wraparound-aware). When the primary header checksum is invalid the
    # header cannot be trusted, so every parseable log is eligible.
    eligible = []
    for c in candidates:
        if c.rejected_reason is not None:
            plan.logs.append(_describe_log(c, "rejected"))
            continue
        if plan.primary_checksum_valid and \
                _seq_delta(c.first_log_sequence(), plan.primary_sequence2) < 0:
            plan.logs.append(_describe_log(c, "stale"))
            continue
        eligible.append(c)

    # Merge valid entries from all eligible logs into one map keyed by
    # sequence number. Overlapping entries are duplicates: the first log
    # (in sequence-sorted order) wins, the rest are recorded as redundant.
    entries_by_seq = {}
    contributing = set()
    for c in eligible:
        for entry in c.entries:
            entries_by_seq.setdefault(entry.sequence(), (c, entry))

    # Chain start: when the header is invalid we cannot trust the primary
    # sequence numbers; start from the lowest sequence any log offers and
    # restore the header from that log. Otherwise continue from sequence2.
    if plan.recover_header:
        if not entries_by_seq:
            plan.warnings.append("header recovery required but no log offers usable entries")
            for c in eligible:
                plan.logs.append(_describe_log(c, "eligible"))
            return plan
        # The lowest sequence under wraparound is the one no other
        # available sequence precedes.
        seqs = sorted(entries_by_seq.keys())
        start_seq = seqs[0]
        for s in seqs[1:]:
            if _seq_delta(s, start_seq) < 0:
                start_seq = s
        plan.header_source_log = entries_by_seq[start_seq][0].name
    else:
        start_seq = plan.primary_sequence2

    # Walk the chain from start_seq, following contiguous sequence numbers
    # with 32-bit wraparound, until a gap stops the replay.
    expected = start_seq
    while expected in entries_by_seq:
        c, entry = entries_by_seq[expected]
        plan.chain.append((expected, c, entry))
        contributing.add(c.name)
        expected = _seq_next(expected)

    if plan.recover_data and not plan.chain:
        plan.warnings.append(
            "data recovery required but no log entry continues sequence %d" % (start_seq,))

    if plan.chain:
        # A gap exists where the chain broke but some eligible log still
        # offers a later entry that can no longer be reached contiguously.
        chain_seqs = {s for s, _, _ in plan.chain}
        for c in eligible:
            for entry in c.entries:
                if entry.sequence() not in chain_seqs and \
                        _seq_delta(entry.sequence(), expected) >= 0:
                    plan.gaps.append(expected)
                    break
        plan.gaps = sorted(set(plan.gaps))

    for c in eligible:
        if c.name in contributing:
            role = "applied"
            if c.truncated:
                plan.warnings.append(
                    "log %s has unparseable trailing data; later entries may be lost" %
                    (c.name,))
        else:
            role = "redundant"  # fully overlapped by other logs
        plan.logs.append(_describe_log(c, role))

    # Page-overwrite plan with bounds checking. The writable region is the
    # hbin area [0x1000, 0x1000 + hbins_limit_size); the limit accounts for
    # hive growth announced by the log entries themselves.
    hbins_limit_size = plan.primary_hbins_size or 0
    for _seq, _c, entry in plan.chain:
        hbins_limit_size = max(hbins_limit_size, entry.hbins_size())
    first_hbin = primary_regf.first_hbin_offset()
    plan.hbins_limit = first_hbin + hbins_limit_size

    for seq, c, entry in plan.chain:
        for page_index, (ref, page) in enumerate(entry.dirty_pages_with_references()):
            target = first_hbin + ref.offset()
            plan.pages.append(PageAction(c.name, c.sha256, seq, page_index,
                                         target, ref.size()))
    return plan


def execute_plan(primary_data, plan):
    """
    Execute a RecoveryPlan against an in-memory copy of the primary hive.
    The primary bytes are never modified; the recovered copy is returned
    inside the RecoveryResult.
    """
    result = RecoveryResult(plan)
    primary_data = bytes(primary_data)

    if not plan.recover_header and not plan.recover_data:
        result.status = STATUS_NOT_REQUIRED
        result.derived_data = primary_data
        result.derived_sha256 = sha256_hex(primary_data)
        result.diagnostic_only = False
        result.final_sequence = plan.primary_sequence2
        result.final_hbins_size = plan.primary_hbins_size
        result.verification = {"checksum_valid": plan.primary_checksum_valid,
                               "sequence_numbers_equal": True}
        return result

    if not plan.chain:
        # Nothing could be replayed; keep only diagnostic material.
        result.status = STATUS_FAILED
        result.derived_data = None
        result.diagnostic_only = True
        result.verification = {"reason": "no applicable log entries"}
        return result

    derived = bytearray(primary_data)

    # Phase 1: restore the REGF header from the starting log, if needed.
    if plan.recover_header:
        source = None
        for _seq, c, _entry in plan.chain:
            if c.name == plan.header_source_log:
                source = c
                break
        if source is None or len(source.data) < 512:
            result.status = STATUS_FAILED
            result.diagnostic_only = True
            result.verification = {"reason": "header source log unavailable"}
            return result
        derived[0:512] = source.data[0:512]

    # Phase 2: replay dirty pages in chain order, skipping out-of-bounds
    # pages instead of writing past the derived hive's hbin area.
    hbins_limit = plan.hbins_limit
    if len(derived) < hbins_limit:
        derived.extend(b"\x00" * (hbins_limit - len(derived)))

    last_entry = None
    for page_action, (seq, candidate, entry) in zip(plan.pages, _expand_pages(plan)):
        ref_offset = page_action.target_offset
        size = page_action.size
        if size == 0 or ref_offset < 0x1000 or ref_offset + size > hbins_limit:
            page_action.status = PAGE_SKIPPED_OUT_OF_BOUNDS
            plan.warnings.append(
                "dirty page out of bounds: log=%s seq=%d page=%d offset=0x%x size=0x%x" %
                (candidate.name, seq, page_action.page_index, ref_offset, size))
            continue
        data = _page_data(entry, page_action.page_index)
        derived[ref_offset:ref_offset + size] = data
        page_action.status = PAGE_APPLIED
        page_action.data_sha256 = sha256_hex(data)
        last_entry = entry

    result.provenance = list(plan.pages)

    # Phase 3: finalize the REGF header of the derived hive.
    if last_entry is None:
        # Every page was rejected; the copy is just the (possibly
        # header-restored) primary and must not be presented as recovered.
        result.status = STATUS_FAILED
        result.derived_data = bytes(derived)
        result.derived_sha256 = sha256_hex(derived)
        result.diagnostic_only = True
        result.verification = {"reason": "all dirty pages were out of bounds"}
        return result

    final_seq = plan.chain[-1][0]
    _finalize_regf(derived, final_seq, last_entry.hbins_size(),
                   last_entry.hive_flags())
    result.final_sequence = final_seq
    result.final_hbins_size = last_entry.hbins_size()

    # Phase 4: verify the derived hive before marking it complete.
    verification = {}
    try:
        regf = RegistryParse.REGFBlock(bytes(derived), 0, False)
        verification["checksum_valid"] = regf.validate_checksum()
        verification["sequence_numbers_equal"] = regf.validate_sequence_numbers()
        verification["hive_sequence1"] = regf.hive_sequence1()
        verification["hive_sequence2"] = regf.hive_sequence2()
    except Exception as e:
        verification["checksum_valid"] = False
        verification["sequence_numbers_equal"] = False
        verification["error"] = str(e)
    result.verification = verification

    result.derived_data = bytes(derived)
    result.derived_sha256 = sha256_hex(derived)

    verified = verification.get("checksum_valid") and \
        verification.get("sequence_numbers_equal")
    skipped = any(p.status == PAGE_SKIPPED_OUT_OF_BOUNDS for p in result.provenance)
    truncated = any(l["role"] == "applied" and l.get("truncated")
                    for l in plan.logs)

    if not verified:
        result.status = STATUS_FAILED
        result.diagnostic_only = True
    elif plan.gaps or skipped or truncated:
        result.status = STATUS_PARTIAL
        result.diagnostic_only = True
    else:
        result.status = STATUS_COMPLETE
        result.diagnostic_only = False
    return result


def _expand_pages(plan):
    """Yield (sequence, candidate, entry) once per planned page, in order."""
    for seq, candidate, entry in plan.chain:
        for _ in entry.dirty_pages_with_references():
            yield (seq, candidate, entry)


def _page_data(entry, page_index):
    """Return the raw bytes of the page_index-th dirty page of an entry."""
    for i, (_ref, page) in enumerate(entry.dirty_pages_with_references()):
        if i == page_index:
            return page.data()
    raise IndexError("dirty page index out of range")


def _finalize_regf(derived, hive_sequence, hbins_size, hive_flags):
    """Update sequence numbers, hbins size, flags, and checksum in-place."""
    def pack_dword(num):
        return pack(str("<I"), num)

    seqnum = pack_dword(hive_sequence)
    derived[0x4:0x8] = seqnum   # hive_sequence1
    derived[0x8:0xC] = seqnum   # hive_sequence2
    derived[0x28:0x2C] = pack_dword(hbins_size)
    derived[0x90:0x94] = pack_dword(hive_flags)

    regf = RegistryParse.REGFBlock(bytes(derived[:512]), 0, False)
    derived[0x1FC:0x200] = pack_dword(regf.calculate_checksum())


def recover_hive(primary_data, log_candidates):
    """
    One-call recovery: plan, then execute. Returns a RecoveryResult.
    Original inputs are treated as read-only throughout.
    """
    plan = plan_recovery(primary_data, log_candidates)
    return execute_plan(primary_data, plan)
