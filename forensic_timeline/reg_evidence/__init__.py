"""Forensic time-evidence extraction built on python-registry.

Each time *source* is kept separate. This package never merges REGF header
timestamps, NK last-written times, transaction sequence numbers or value-level
timestamps into a single "event time".
"""
