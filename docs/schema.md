# Schema and wire invariants

The C++ sniffer and the Python detector both write to the same SQLite file.
These contracts cross the language boundary; both sides must hold them.

## Timestamps

Every `ts` / `started_at` / `ended_at` / `created_at` column is ISO 8601 UTC
with exactly 6 microsecond digits and a trailing `Z`:

    2020-03-11T20:25:08.951979Z

Plain string comparison sorts correctly and round-trips between writers.

- C++ writer: `sniffer/src/db.cpp::format_ts`
- Python writer: `detector/src/lte_rogue_detector/sessionize.py::_format_ts`

## Direction

`messages.direction` is `'UL'` or `'DL'`. Inferred from the S1AP procedure
code (12 InitialUEMessage, 13 UplinkNASTransport -> UL; 11 DownlinkNASTransport
-> DL). Rows with no S1AP procedure code are dropped at the sniffer before
insert.

## eNB-UE-S1AP-ID

The sniffer writes `messages.enb_ue_s1ap_id` whenever S1AP carried it.
The sessionizer keys sessions on it; rows without it are skipped
(counted in `SessionizeStats.messages_skipped_no_enb_id`).
