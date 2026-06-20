# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

Extracts and correlates telecom call logs for a specific call identified by its **FSMId** (StateMachineId / CallId). Supports SDS7-based applications: CallService, iCampaign, WSMS. Given FSMId `2e277b400013022`, the tool:
1. Greps SummaryTrace, DetailTrace, WSMSTrace, CampaignTrace, and other trace logs for that ID
2. Runs a 4-pass smart extraction on main application logs (backtrack, thread-follow, ASN.1 block capture)
3. Discovers correlated FSMIds via DNISCallsMap FTN forwarding and extracts them in the same run
4. Extracts TcapServer thread-blocks correlated by TCAP Transaction IDs found in the output
5. Converts DK/SS7 hex dumps in TcapServer logs to PCAP via `hexlog2pcap`
6. Filters real PCAP captures by TCAP TID using tshark → dechunk SCTP → re-filter
7. Optionally generates an HTML mermaid sequence diagram of the TCAP transaction flow

## Running the Tool

```bash
# Typical invocation (from repo root, with input logs in applogs/)
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId> \
  -p "pcaps/stp*.pcap*" \
  -z "+0000" \
  -t "applogs/TcapServer-0*" \
  -te "applogs/TcapServerEvent*" \
  -n "TestCaseName" \
  --html \
  -v
```

Output files land in `logs/` (default) or the directory specified by `-o`.

```bash
# hexlog2pcap standalone (convert DK/SS7 hex log to PCAP)
python3 hexlog2pcap.py <input.log> <output_base> -p dk -d sccp -v

# List available parsers/decoders
python3 hexlog2pcap.py --list
```

## Syntax / Import Checks

```bash
python3 -m py_compile hexlog2pcap.py
python3 -m py_compile extract-sds7-logs.py
```

## External Dependencies

- **scapy** — SCTP dechunking (`pip install scapy`)
- **tshark** / **mergecap** / **text2pcap** — Wireshark CLI tools; must be on `PATH` or in `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`

## Architecture

### `hexlog2pcap.py` — Hex-to-PCAP Framework (library + CLI)

Plugin-style pipeline: `LogParser → ProtocolDecoder → PcapBackend`

| Class | Role |
|---|---|
| `LogParser` (ABC) | Parses a log file, yields `RawPacket` objects |
| `ProtocolDecoder` (ABC) | Decodes `RawPacket` hex → `DecodedPacket`; sets `link_type` (DLT value) |
| `PcapBackend` (ABC) | Writes `DecodedPacket` list to `.pcap`; default impl calls `text2pcap` |
| `Hex2PcapConverter` | Orchestrates the three stages |
| `DKLogParser` | Concrete parser for Dialogic/DK SS7 and DKSS7Interface log formats |
| `SCCPDecoder` | Decodes DK TLV envelope → SCCP wire format (DLT 142) |
| `RawMTPDecoder` | Passes MTP3 hex through as-is (DLT 141) |

Register custom parsers/decoders with `register_parser()` / `register_decoder()`, then call `hexlog2pcap.convert(infile, outfile, parser="name", decoder="name")`.

### `extract-sds7-logs.py` — Main Extraction Orchestrator

Key functions and their roles:

**Trace extraction**

| Function | Role |
|---|---|
| `process_simple_search()` | Greps a trace file group (SummaryTrace, DetailTrace, WSMSTrace, etc.) for an FSMId; writes one output section per call |
| `parse_detail_trace_records()` | Parses DetailTrace lines into structured records for HTML diagram and PCAP correlation |
| `discover_correlated_fsmids()` | Finds forwarded FSMIds via DNISCallsMap FTN entries in the main log; returns correlated + cleanup FSMId lists |

**Main log extraction**

| Function | Role |
|---|---|
| `process_main_log()` | 4-pass extraction: identify FSMId lines → smart backtrack → forward-scan thread context → extract with ASN.1 block capture |

**TCAP / TcapServer**

| Function | Role |
|---|---|
| `process_tcap_logs()` | TcapServer thread-block extraction; 2-phase: hex TID match → dialog ID expansion (3 rounds) |
| `process_tcap_pcap()` | Converts TcapServer DK hex dumps to PCAP via `hexlog2pcap.convert()` then filters by TID |
| `process_tcap_events()` | Extracts TcapServerEvent log entries matching TID search terms |
| `extract_tids()` | Scans extracted log output for 8-hex-char TCAP TIDs using `TID_RE` |
| `extract_tids_from_tcap_for_fsmids()` | Seeds TIDs for cleanup FSMIds directly from TcapServer log bracket patterns |

**PCAP extraction and filtering**

| Function | Role |
|---|---|
| `process_pcap()` | Filters real PCAP captures: per-file tshark → merge → dechunk SCTP → re-filter by TID |
| `process_pcap_from_traces()` | Alternate PCAP extraction path using SummaryTrace/DetailTrace SCCP fields and timestamps when no main log is available |
| `build_trace_based_filter()` | Builds tshark display filter from SummaryTrace SCCP fields + DetailTrace timestamp window |
| `dechunk_sctp_stream()` | Splits SCTP frames containing multiple DATA chunks into one-frame-per-chunk using scapy |

**HTML sequence diagram**

| Function | Role |
|---|---|
| `generate_transaction_html()` | Builds mermaid sequence diagram HTML; uses Union-Find to group TID pairs into transactions |
| `_enrich_flow_records_from_pcap()` | Queries PCAP with tshark field extraction to add msg_type, CgPA, CdPA to flow records |
| `_detect_our_ips()` | Auto-detects local signode IP addresses from PCAP frames by vote-counting; overridden by `--signode` |

### Log Format Assumptions

- Main application logs (CallService, iCampaign, WSMS): pipe-delimited (`|`) with thread name in field matching `Thread-\d+` or `Rule Executor \d+`, FSMId in field 5 before the first colon
- TcapServer logs: pipe-delimited with 8-hex-char thread ID in field 4; blocks delimited by "Received from n/w" / "Received from App" / "Sending to n/w" / "Sending to App" lines
- Trace logs (SummaryTrace, DetailTrace, WSMSTrace, CampaignTrace): grepped directly for FSMId; section header derived from filename prefix via `_extract_trace_prefix()`
- Input files may be `.gz` compressed; `open_file()` handles both

## Directory Layout

```
applogs/        # Input log files (gitignored) - SummaryTrace, DetailTrace, callservice, TcapServer logs
pcaps/          # Input PCAP captures (gitignored)
logs/           # Output directory (gitignored) - extracted .txt, .pcap, .html files
old/            # Old script versions (gitignored)
docs/           # Feature documentation
```

## Feature Documentation

| Document | Topic |
|---|---|
| [`docs/user-guide.md`](docs/user-guide.md) | Installation and user guide — prerequisites, all workflows, CLI reference, troubleshooting, glossary |
| [`docs/html-sequence-diagram.md`](docs/html-sequence-diagram.md) | HTML sequence diagram — node chain, SPC labels, SCCP fields, anomaly detection, tshark field list, dark/light mode, snapshot copy |
| [`docs/tcapserver-handling.md`](docs/tcapserver-handling.md) | TcapServer block extraction — log format, TID seed/dialog expansion, block classification, flow_record schema, anomaly types, PCAP enrichment, output structure |
