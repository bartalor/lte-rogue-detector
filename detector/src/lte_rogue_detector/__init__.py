"""Detection engine for LTE rogue base stations.

Reads NAS/S1AP events written by the C++ sniffer into SQLite, groups them
into per-UE sessions, applies pluggable detection rules, and writes alerts
back to the same database.
"""
