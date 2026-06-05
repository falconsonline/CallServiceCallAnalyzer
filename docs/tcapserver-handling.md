# TcapServer Handling — Design & Implementation Reference

TcapServer sits between the signalling network (SmartSTP) and CallService. Its logs record every TCAP message received from and sent to both sides. This document covers how `extract-callservice-logs.py` extracts, correlates, and classifies TcapServer log blocks for a given FSMId.

---

## Overview

TcapServer extraction runs after the main CallService log pass. It uses TCAP Transaction IDs (TIDs) found in the CallService output to locate matching thread-blocks in TcapServer logs.

```
CallService log output
        │
        ▼
   extract_tids()          ← scan output for 8-hex-char TIDs
        │
        ▼
 process_tcap_pcap()       ← convert DK/SS7 hex dumps → PCAP (optional)
        │
        ▼
 process_tcap_logs()       ← Phase 1: TID match → Phase 2: dialog_id expansion
        │
        ▼
   flow_records[]          ← one dict per thread-block; written to output file
        │
        ▼
 process_tcap_events()     ← optional TcapServerEvent log search
```

---

## CLI Arguments

| Argument | Description |
|---|---|
| `-t / --tcap PATTERN` | Glob pattern for TcapServer log files (e.g. `"applogs/TcapServer-0*.log*"`) |
| `-te / --tcap-event PATTERN` | Glob pattern for TcapServerEvent log files |

TcapServer extraction only runs when `-t` is provided. PCAP conversion only runs when TIDs are found.

---

## Log Format

TcapServer logs are **pipe-delimited**. Key structural properties:

```
<date>|<time>|<level>|<component>|<thread_id_hex8>|<message>
```

- Field 4 (0-indexed): **8-hex-char thread ID** (e.g. `3f2a1b00`) — used to group lines into blocks
- Blocks delimited by anchor lines: `Received from n/w` or `Received from App`
- Each block belongs to one thread handling one TCAP message exchange

### Block anchor lines (regex constants)

| Regex constant | Pattern matched | Meaning |
|---|---|---|
| `_TCAP_NW_RE` | `Received from n/w` | Start of a network-originated block |
| `_TCAP_APP_RE` | `Received from App` | Start of an app-originated (outbound) block |
| `_TCAP_SEND_NW_RE` | `Sending to n/w` | Block sent a response/message to network |
| `_TCAP_SEND_APP_RE` | `Sending to App` | Block forwarded to CallService |
| `_TCAP_READY_RE` | `ProcessMessage RWTcap Decode Successful` | TCAP decode OK |
| `_TCAP_DIALOG_RE` | `Dialog\s*\[(\d+)` | Extracts decimal dialog_id from log text |
| `_TCAP_THREAD_ID_RE` | `^[0-9A-Fa-f]{8}$` | Validates thread ID field |
| `_TCAP_BRACKET_TID_RE`| `\[([0-9A-Fa-f]{8})[\]:]` | Extracts TID from `[deadbeef]` notation |
| `_TCAP_HEX_RE` | `^[\s0-9a-fA-F]+$` | Identifies DK/SS7 hex dump lines |
| `_TCAP_TS_RE` | `HH:MM:SS[.,]mmm` | Extracts timestamp from block lines |
| `_TCAP_APP_NAME_RE` | `application id: <hex> (name: <str>)` | Extracts CallService app name |

---

## TID Extraction — `extract_tids()`

Scans the CallService output file for TCAP Transaction IDs using `TID_RE`:

```python
TID_RE = re.compile(r'\b([0-9A-Fa-f]{8})\b')
```

Returns a list of unique 8-hex-char TID strings (e.g. `['2e277b40', 'deadbeef']`). These are used as the seed for both PCAP filtering and TcapServer block matching.

---

## PCAP Conversion — `process_tcap_pcap()`

**Purpose:** TcapServer logs may contain raw DK/SS7 hex dumps embedded in the log text. This function converts them to a proper PCAP for tshark analysis.

**Pipeline:**

```
For each TcapServer log file matching the pattern:
    hexlog2pcap.convert(file, temp_pcap, parser='dk', decoder='sccp')
        │
        ▼ temp PCAPsmerged via mergecap
        │
        ▼ single tshark filter pass
          filter: tcap.otid == TID1 || tcap.dtid == TID1 || tcap.otid == TID2 ...
        │
        ▼ output: <base>_tcap.pcap
```

The resulting `_tcap.pcap` file is passed to `process_tcap_logs()` for timestamp enrichment and later to `_enrich_flow_records_from_pcap()` for field extraction.

If the output PCAP is missing or ≤ 24 bytes (PCAP header only, no packets), `tcap_pcap_path` is set to `None` and enrichment is skipped gracefully.

---

## Block Extraction — `process_tcap_logs()`

**Signature:**
```python
def process_tcap_logs(file_pattern, tcap_tids, out_handle, tcap_pcap_path=None)
    -> (dialog_ids: set[str], flow_records: list[dict], tid_to_dialog: dict[str, str])
```

### Phase 1 — TID seed match

Scans each TcapServer log file line by line. A thread is **selected** if any line on that thread contains a known TID (from `tcap_tids`). Once selected, all lines for that thread ID are accumulated into a block.

Block boundaries:
- **Start:** line matching `_TCAP_NW_RE` or `_TCAP_APP_RE` on the thread
- **End:** next `Received from` line on the same thread, or EOF

A block is **aborted early** if `dialog_id` changes mid-block (guards against thread reuse).

### Phase 2 — Dialog ID expansion (3 rounds)

After Phase 1, the set of matched `dialog_ids` is used to find additional TcapServer blocks that handle the same dialog but whose lines don't directly contain the seed TIDs. Runs up to **3 expansion rounds** — each round can discover new dialog_ids that feed the next.

This handles multi-block TCAP dialogs where the TID only appears in the first `Begin` block.

### Block classification

For each completed block, two booleans are derived:

| Flag | How detected | Meaning |
|---|---|---|
| `forwarded_to_app` | Any line matches `_TCAP_SEND_APP_RE` | Block forwarded message to CallService |
| `sent_to_nw` | Any line matches `_TCAP_SEND_NW_RE` | Block sent a message to the network |
| `outgoing` | `forwarded_to_app OR sent_to_nw` | Used to set `direction` field |

### Instance name extraction

| Field | Source | Example |
|---|---|---|
| `tcap_instance` | TcapServer log **filename**: `TcapServer-03-xxxx.log` → `TCAP-03` | `TCAP-03` |
| `cs_instance` | Log line content: `instance:#Call-02#scsca2` → `Call-02` | `Call-02` |

Regex: `_TCAP_INSTANCE_RE = re.compile(r'[Tt]cap[Ss]erver-(\w+)', re.IGNORECASE)`
Regex: `_CS_INSTANCE_RE   = re.compile(r'instance:#([^#]+)#')`

---

## flow_record Schema

Each extracted block produces one `flow_record` dict appended to `flow_records`:

| Field | Type | Source | Description |
|---|---|---|---|
| `dialog_id` | `str` | `_TCAP_DIALOG_RE` match in block | Decimal dialog ID |
| `thread_type` | `str` | `'network'` or `'app'` | Whether block started from network or app side |
| `thread_id` | `str` | Field 4 of log line | 8-hex-char thread identifier |
| `timestamp` | `str` | `_TCAP_TS_RE` first match in block | `HH:MM:SS.mmm` of first line |
| `otid` | `str` | Populated by PCAP enrichment | TCAP originating TID (hex) |
| `dtid` | `str` | Populated by PCAP enrichment | TCAP destination TID (hex) |
| `msg_type` | `str` | Populated by PCAP enrichment | TCAP message type |
| `calling` | `str` | Populated by PCAP enrichment | SCCP CgPA digits |
| `called` | `str` | Populated by PCAP enrichment | SCCP CdPA digits |
| `app_name` | `str` | `_TCAP_APP_NAME_RE` match | Application name from TcapServer log |
| `direction` | `str` | `'out'` if outgoing else `'in'` | Derived from `forwarded_to_app` / `sent_to_nw` |
| `forwarded_to_app` | `bool` | `_TCAP_SEND_APP_RE` | Whether block forwarded to CallService |
| `sent_to_nw` | `bool` | `_TCAP_SEND_NW_RE` | Whether block sent to network |
| `tcap_instance` | `str` | Log filename | TcapServer instance name (e.g. `TCAP-03`) |
| `cs_instance` | `str` | Log content | CallService instance name (e.g. `Call-02`) |
| `lines` | `list[str]` | Raw log lines | Full block content for output writing |

---

## Anomaly Classification

Used in `generate_transaction_html()` to detect messages that never reached CallService.

A block is classified as an **anomaly** when ALL of these hold:
1. `thread_type == 'network'` — received from network side
2. `forwarded_to_app == False` — no `Sending to App` line
3. No matching DetailedTrace `direction='in'` record for the same `dialog_id`

| Anomaly type | Additional condition | Meaning |
|---|---|---|
| **DROPPED** | `sent_to_nw == False` | Message received and silently discarded |
| **DIRECT RESPONSE** | `sent_to_nw == True` | TcapServer replied to network directly — CallService not involved |

Both types are highlighted in **red** (`rect rgba(255,80,80,0.15)`) in the HTML sequence diagram. Arrows stop at the `TCAP-03 ⚠` participant; they never reach `Call-02`.

---

## PCAP Enrichment — `_enrich_flow_records_from_pcap()`

After `process_tcap_logs()` returns, flow records are enriched with PCAP data if `tcap_pcap_path` exists.

**Matching logic:**
- For each PCAP frame: extract `tcap.otid` and `tcap.dtid` (hex, normalised)
- Look up `tid_to_dialog` map: `{tid_hex: dialog_id}`
- Adds exactly **one** `source='pcap'` record per unique PCAP frame per `dialog_id` — not one per TcapServer block. An `added_for_did` tracker (`{dialog_id: set of frame indices}`) prevents the same PCAP frame being added more than once regardless of how many TcapServer blocks share the dialog.
- TcapServer blocks remain unchanged in `flow_records`; the pcap-source records are appended after them.

**Direction fix:**
- Initial direction heuristic in enrichment: `'out' if dtid else 'in'` (approximate)
- **Corrected** in `generate_transaction_html()` for **all messages in `all_msgs`** (detail records, pcap-source records, and orphan pcap records alike) after the full message list is assembled. Uses `ip.dst in our_ips` → `'in'`, `ip.src in our_ips` → `'out'`.

---

## TcapServerEvent Logs — `process_tcap_events()`

Optional secondary search (`-te` argument). Searches TcapServerEvent logs for lines matching:
- The FSMId
- Any extracted TID (normalised, colon-stripped)
- Any matched dialog_id

Results are appended to the same output file after the main TcapServer block output.

---

## Output

All extracted TcapServer block lines are written to the main output `.txt` file via `out_handle`. The file contains:

1. CallService main log lines (from `process_main_log()`)
2. TcapServer block lines (from `process_tcap_logs()`)
3. TcapServerEvent lines (from `process_tcap_events()`, if `-te` provided)

Additionally, if PCAP conversion succeeds: `<base>_tcap.pcap` in the output directory.

---

## Sequence in main()

```python
# 1. Extract TIDs from CallService output
tcap_tids = extract_tids(log_output_path)

# 2. Convert DK hex dumps to PCAP (if TIDs found)
if tcap_tids:
    process_tcap_pcap(args.tcap, tcap_tids, tcap_pcap_path)

# 3. Extract TcapServer blocks + build flow_records
dialog_ids, flow_records, tid_to_dialog = process_tcap_logs(
    args.tcap, tcap_tids, out_file, tcap_pcap_path=tcap_pcap_path)

# 4. Optional: TcapServerEvent search
if args.tcap_event:
    process_tcap_events(args.tcap_event, search_terms, out_file)

# 5. HTML generation uses flow_records + tid_to_dialog
if args.html:
    generate_transaction_html(flow_records, html_path, args.id,
                              pcap_path=pcap_output_path,
                              tcap_tids=tcap_tids,
                              tid_to_dialog=tid_to_dialog,
                              detail_records=detail_records_for_html,
                              node_ip_map=node_ip_map)
```

---

## Related Documentation

- [`docs/html-sequence-diagram.md`](html-sequence-diagram.md) — how flow_records are rendered into the mermaid sequence diagram, anomaly visualisation, and PCAP enrichment field reference
