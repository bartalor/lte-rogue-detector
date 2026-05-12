# CLAUDE.md — LTE Rogue Base Station Detector

Durable context for this project. Read this before doing anything. Do not duplicate ephemeral state here (todo lists, in-progress notes) — those belong in the conversation.

## What this project is

A passive detector for IMSI catchers and rogue eNodeBs that observes LTE signaling (S1AP / NAS) between a UE and the network during attach, authentication, security mode, and TAU procedures, and flags behavior characteristic of fake base stations.

## Priorities

Things that matter:

- Correctness and clarity of the protocol reasoning
- Quality of the C++ (modularity, build hygiene, tests)
- Quality of the Python (structure, pluggability, tests)
- Whether the SQL schema is real (indexes used, queries make sense)
- Whether the demo reproduces cleanly without standing up srsRAN

Things that don't:

- A pretty UI
- Exhaustive coverage of every S1AP/NAS message
- Future-proofing or speculative abstractions

## Architecture (locked)

Three components + a storage layer:

1. **`sniffer/`** — C++ binary. Ingests S1AP/NAS from pcap (and optionally live SCTP). Decodes only the message types the rules need. Extracts the IEs the rules care about. Writes structured events to SQLite. Modular CMake build with decoder/extractor/emitter separation. GoogleTest unit tests. Defensive against malformed input.

2. **`detector/`** — Python package. Reads events from SQLite, groups them into per-UE sessions, applies pluggable detection rules, writes alerts back. CLI for historical runs and watch mode for live processing. Pytest tests.

3. **`scenarios/`** — Bash + Python orchestration. Runs a scenario end-to-end (feed pcap → sniffer → detector → print verdict). Reproducible, self-contained.

4. **`schema/`** — Versioned SQLite schema with migration script. Tables: `cells`, `sessions`, `messages`, `alerts`. Foreign keys enforced. Indexes on the columns the detection queries actually use (subscriber IDs, cell IDs, timestamps). `EXPLAIN QUERY PLAN` must show indexes being used.

5. **`sample_pcaps/`** — Committed captures so the detector can be run without standing anything up.

6. **`docs/`** — README + per-rule walkthrough + threat model.

## Detection rules (pick 3, do them well)

The project commits to at least three. Three done well beats six done badly.

1. **IMSI requested in cleartext during initial attach when a valid GUTI was available** — strong IMSI catcher signature.
2. **AKA skipped or failed** — legitimate networks always run mutual authentication.
3. **Null ciphering / null integrity (EEA0 / EIA0) selected in Security Mode Command when UE advertised stronger algorithms** — downgrade attack signature.
4. **TAU reject with abnormal cause codes that force IMSI re-disclosure**.

Each rule produces an alert with: severity score, offending message reference, affected subscriber identifier, and the cell that exhibited the behavior. Rules are independent and composable.

## Decisions already made

- **No live srsRAN / Open5GS stack in the committed demo.** The detector is validated against (a) real published srsRAN attach pcaps for the legitimate baseline, and (b) crafted attack pcaps for the rogue scenarios. The scenario runner is structured so a live srsRAN ZMQ stack could be wired in later, but the committed demo runs from pcaps for reproducibility. This is framed as a *feature* (runs without setup), not a hedge. **Open option if time allows: build a local srsRAN + Open5GS ZMQ testbed and capture our own attack pcaps.**
- **Crafted pcaps use `pycrate`** (3GPP ASN.1 library) for wire-correct S1AP / NAS encoding. The project's contribution is the detector, not yet-another-S1AP-encoder.
- **SQLite, not Postgres.** Single-file, embeddable from both C++ and Python, sufficient for the data volumes involved.
- **Alembic for migrations.** Standard tool. Migrations are hand-written SQL via `op.execute()` / `op.create_table()`; no SQLAlchemy ORM models — the C++ sniffer writes the same DB directly via `sqlite3.h`, so an ORM would only be dead weight.
- **C++17, CMake, GoogleTest.** Python 3.13 in the active pyenv venv. Pytest.

## Cross-cutting features

Two cross-cutting features beyond the detection rules:

- **Latency / throughput analysis** — a timing layer on top of the message store: per-session inter-message latencies (Attach-Request → Authentication-Request → Security-Mode-Command → Attach-Complete), a session timing report (median, p95), and one analytical SQL query that exercises the `(session_id, ts)` index. Lives alongside the detection alerts, not as a separate component.
- **Linux network-namespace scenario runner** — uses `ip netns` to isolate the "rogue eNB" / "legitimate eNB" / "core" into separate network namespaces, `ip link` veth pairs to wire them, `ss` to verify the SCTP listener before injecting, and `iptables` for one scenario that simulates a filtered path. The runner *demonstrates* Linux networking, not just orchestrates files.

## Honest limitations (acknowledge, don't hide)

- No real RF measurement. PHY metrics (RSRP, SINR, CQI) that srsRAN reports are exposed and logged if available, but no spectrum is sampled. The README states this plainly.
- The "rogue eNB" is simulated via crafted captures, not a patched srsRAN binary.

## Environment

- Linux (Ubuntu 24.04 family, kernel 6.8).
- Python 3.13 in pyenv venv `myvirt`. Pytest 9 already present. `scapy` installed (kept for low-level packet ops; S1AP/NAS encoding goes through `pycrate`).
- gcc 13, cmake 3.28, sqlite3 3.45.
- `tshark` is **not** installed and is not assumed for the demo. Useful for development; the runner does not depend on it.

## Build / test invariants

- `cmake -S sniffer -B sniffer/build && cmake --build sniffer/build` must succeed clean (no warnings at `-Wall -Wextra -Wpedantic`).
- `pytest detector/` must pass.
- `ctest --test-dir sniffer/build` must pass.
- The demo command (single command, name TBD) runs the IMSI catcher scenario end-to-end and prints the alerts to stdout.
