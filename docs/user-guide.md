# SDS7 Log Analyzer — User Guide

## Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Key Concepts](#3-key-concepts)
4. [Task: Extract logs for a call](#4-task-extract-logs-for-a-call)
5. [Task: Filter PCAP captures by TCAP TID](#5-task-filter-pcap-captures-by-tcap-tid)
6. [Task: Generate an HTML sequence diagram](#6-task-generate-an-html-sequence-diagram)
7. [Task: Convert hex dumps to PCAP](#7-task-convert-hex-dumps-to-pcap)
8. [Task: Label signalling nodes](#8-task-label-signalling-nodes)
9. [Output files reference](#9-output-files-reference)
10. [CLI reference — extract-sds7-logs.py](#10-cli-reference--extract-sds7-logspy)
11. [CLI reference — hexlog2pcap.py](#11-cli-reference--hexlog2pcappy)
12. [Troubleshooting](#12-troubleshooting)
13. [Glossary](#13-glossary)

---

## 1. Overview

Telecom call problems are reported after the fact. By that time the relevant data is scattered across five or more log files on different hosts. SDS7 Log Analyzer solves this: given the unique identifier of one call (`FSMId`), it collects every log line and every network packet for that call from all sources in one run.

The tool handles SDS7-based applications including **CallService**, **iCampaign**, and **WSMS**. Any application that emits SummaryTrace or DetailTrace logs and uses the TCAP/CAMEL/MAP signalling stack is supported.

**Two scripts:**

| Script | Purpose |
|---|---|
| `extract-sds7-logs.py` | Main orchestrator — extracts logs, filters PCAPs, builds sequence diagrams |
| `hexlog2pcap.py` | Standalone hex-to-PCAP converter — also used internally by the main script |

**Typical workflow:**

1. Collect log files and PCAPs from the system under test into `applogs/` and `pcaps/`
2. Run `extract-sds7-logs.py` with the FSMId and glob patterns pointing at those files
3. Open the output `.txt` file (and optionally `.html` diagram) to investigate the call

---

## 2. Prerequisites

### Python

Python 3.10 or later is required.

```bash
python3 --version
# Should print: Python 3.10.x or higher
```

### Python packages

```bash
pip install scapy
```

`scapy` is used for SCTP dechunking when processing real Sigtran PCAP captures. It is required even if you are not using the `-p` PCAP flag, because the import happens at startup.

### Wireshark CLI tools

`tshark`, `mergecap`, and `text2pcap` must be on your `PATH`. These are only invoked when you use `-p` (PCAP filtering) or `--html` (sequence diagram).

**macOS (Homebrew):**
```bash
brew install wireshark
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install tshark
```

**Verify installation:**
```bash
tshark --version
which mergecap
which text2pcap
```

If `tshark` is installed but not on PATH (common on macOS), the tool searches `/usr/bin`, `/usr/local/bin`, and `/opt/homebrew/bin` automatically.

### Directory layout

The tool expects input files under a directory reachable via glob patterns. The recommended layout:

```
applogs/        # SummaryTrace*, DetailTrace*, callservice-*, TcapServer-0*, etc.
pcaps/          # *.pcap, *.pcap.gz — real Sigtran captures
logs/           # Output directory (created automatically)
```

---

## 3. Key Concepts

These terms appear throughout the tool's flags and output. Read this section before your first run so you know which files to collect.

| Term | Plain-English definition |
|---|---|
| **FSMId / StateMachineId** | Unique hex identifier for one call or session instance (e.g. `2e277b400013022`). This is the primary search key the tool uses across all log sources. |
| **SummaryTrace log** | High-level per-call event log produced by the SDS application. File names typically match `SummaryTrace*`. One line per significant call event. |
| **DetailTrace log** | Detailed per-call protocol trace including CAMEL/MAP operation names and parameters. File names match `DetailTrace*` or `DetailedTrace*`. |
| **WSMSTrace log** | WSMS application trace. File names match `WSMSTrace*`. |
| **CampaignTrace log** | iCampaign application trace. File names match `CampaignTrace*`. |
| **Main application log** | Thread-based application log written by CallService, iCampaign, or WSMS. File names match `callservice-*`, `applog*`, etc. Contains raw protocol decode, ASN.1 dumps, and state machine transitions. |
| **TcapServer log** | SS7 TCAP layer log from the TcapServer process. File names match `TcapServer-0*`. Needed for TCAP TID correlation and the HTML diagram. |
| **TcapServerEvent log** | Optional TCAP event log. File names match `TcapServerEvent*`. |
| **TCAP TID (Transaction ID)** | 4-byte hex identifier (e.g. `042e7fbe`) that ties together all SS7 messages belonging to one TCAP transaction. A single call typically involves 2–6 TIDs. |
| **SPC (Signalling Point Code)** | Network address of an SS7 signalling node. Appears in MTP3 routing headers and in the HTML diagram participant labels. Format: zone-region-sp (e.g. `3-100-1`) plus decimal equivalent. |
| **PCAP** | Network packet capture file (`.pcap` or `.pcap.gz`) containing raw Sigtran (SS7-over-IP) traffic. |
| **SCTP** | Stream Control Transmission Protocol — the transport layer for SS7 over IP (Sigtran). The tool dechunks SCTP frames that carry multiple DATA chunks before filtering. |
| **M2PA / M3UA** | Two Sigtran protocol variants for carrying SS7 MTP3 over IP. Affects which tshark fields are used for SPC extraction. |
| **SmartSTP / signode** | The signalling gateway node that bridges SS7 and IP. Its IP addresses determine message direction in the HTML diagram. |

---

## 4. Task: Extract logs for a call

This is the core workflow. It searches SummaryTrace, DetailTrace, and application logs for the FSMId and writes all matching content to a single output file.

### What you need

- One or more trace log files (SummaryTrace, DetailTrace, WSMSTrace, CampaignTrace, or other applog)
- The FSMId of the call to investigate

### Minimal command (trace logs only)

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -i 2e277b400013022
```

### With application main log

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i 2e277b400013022 \
  -n "MyTestCase"
```

### iCampaign / WSMS

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/WSMSTrace*" \
  -f "applogs/CampaignTrace*" \
  -m "applogs/applog*" \
  -i 2e277b400013022
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-f` / `--trace GLOB` | Yes (repeatable) | Glob pattern for a trace file group. Each `-f` produces its own section in the output. Auto-detects SummaryTrace vs DetailTrace by filename. |
| `-i` / `--id FSMID` | Yes | FSMId / StateMachineId to extract. |
| `-m` / `--main GLOB` | No | Glob for main application log files. Runs a 4-pass smart extraction: identify FSMId lines → backtrack → thread-follow → ASN.1 block capture. |
| `-n` / `--testcase NAME` | No | Prefix for output filenames. Spaces become underscores. |
| `-o` / `--output-dir DIR` | No | Output directory. Default: `logs/`. Created if it does not exist. |
| `-v` / `--debug` | No | Enable verbose debug logging to `logs/extract.log`. |

### Output

One file: `logs/{testcase}-{fsmid}-extract-{YYYYMMDD_HHMMSS}.txt`

Without `-n`: `logs/TestCase-{fsmid}-{YYYYMMDD_HHMMSS}.txt`

The file is divided into sections, one per `-f` pattern and one for the main log, separated by:

```
==================== SECTION: SummaryTrace ====================
```

### Correlated calls (automatic)

If the main log (`-m`) reveals that this call was forwarded via DNISCallsMap FTN to another FSMId, the tool automatically extracts logs for the forwarded call in the same run. A message like:

```
INFO | Extracting 2 FSMId(s): 2e277b400013022, 3f1a9c200024011
```

indicates correlated extraction is active.

---

## 5. Task: Filter PCAP captures by TCAP TID

Use this when you have raw Sigtran PCAP captures and want to isolate the packets for one call.

The tool:
1. Runs the log extraction (as in §4) to discover TCAP TIDs for the call
2. Filters all PCAP files matching the `-p` pattern by those TIDs
3. Dechunks SCTP frames carrying multiple DATA chunks
4. Writes the filtered result to a single output PCAP

### Additional requirement

You must supply the timezone of the system that generated the logs (`-z`). This is used to correlate log timestamps with PCAP packet timestamps.

**Find the timezone offset — run this on the log system:**
```bash
date +"%z"
# Example output: +0400
```

### Command

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i 2e277b400013022 \
  -p "pcaps/stp*.pcap*" \
  -z "+0400"
```

### Additional flags

| Flag | Required | Description |
|---|---|---|
| `-p` / `--pcaps GLOB` | Yes (with `-z`) | Glob for PCAP capture files. Accepts `.pcap` and `.pcap.gz`. |
| `-z` / `--timezone TZ` | Yes (with `-p`) | Timezone of the log system. Accepts IANA names (`America/Mexico_City`) or UTC offsets (`+0400`, `-0500`, `UTC-5`). Use a fixed offset if the system's DST rules differ from IANA. |

### Output

`logs/{base_name}.pcap` — filtered Sigtran PCAP containing only packets matching the call's TCAP TIDs.

---

## 6. Task: Generate an HTML sequence diagram

Use this to get a visual hop-by-hop signalling flow across all nodes for the call.

### Additional requirement

TcapServer log files are mandatory for `--html`. Without them the tool cannot map TCAP TIDs to messages.

### Command

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i 2e277b400013022 \
  -p "pcaps/stp*.pcap*" \
  -z "+0400" \
  -t "applogs/TcapServer-0*" \
  -te "applogs/TcapServerEvent*" \
  -n "MyTestCase" \
  --html
```

### Additional flags

| Flag | Required | Description |
|---|---|---|
| `-t` / `--tcap GLOB` | Yes (with `--html`) | Glob for TcapServer log files. Covers SDS-based apps: CallService, iCampaign, WSMS. |
| `-te` / `--tcap-event GLOB` | No | Glob for TcapServerEvent log files. |
| `--html` | No | Generate the HTML sequence diagram. |

### What the diagram shows

Participants appear left to right in call order:

```
Remote Entity  →  signode(s)  →  TcapServer instance(s)  →  SDS app instance(s)
(SSP/HLR/VLR)   (SmartSTP)      (TCAP-01, TCAP-02, …)    (Call-01, Call-02, …)
```

- Only participants that appear in the extracted logs are shown
- Each arrow represents one TCAP/CAMEL/MAP message
- SPC (Signalling Point Code) is shown once per participant label, not repeated per arrow
- **Dark/light mode toggle** — button in the top-right corner
- **Snapshot copy** — copies a rendered PNG of the current view to the clipboard

### Output

`logs/{base_name}.html` — self-contained HTML file; open in any browser. No server needed.

Also produced when `-t` is given (even without `--html`):

`logs/{base_name}_tcap.pcap` — PCAP converted from TcapServer DK hex dumps, filtered by TID.

---

## 7. Task: Convert hex dumps to PCAP

Use `hexlog2pcap.py` when you have a raw DK/SS7 hex log file and want to convert it to PCAP independently of a call extraction.

### Command

```bash
python3 hexlog2pcap.py input.log output_base -p dk -d sccp -v
```

This reads `input.log`, converts each hex packet using the `dk` parser and `sccp` decoder, and writes `output_base.pcap`.

### List available parsers and decoders

```bash
python3 hexlog2pcap.py --list
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `infile` | Yes | Input log file (positional). |
| `outfile` | Yes | Output base name; `.pcap` is appended (positional). |
| `-p` / `--parser NAME` | No | Log parser. Default: `dk`. |
| `-d` / `--decoder NAME` | No | Protocol decoder. Default: `sccp`. |
| `-v` / `--verbose` | No | Verbose output. |
| `--text2pcap PATH` | No | Explicit path to `text2pcap` binary if not on PATH. |
| `--timeformat FORMAT` | No | Timestamp format for text2pcap. |
| `--list` | No | List registered parsers/decoders and exit. |

### Parsers

| Name | Description |
|---|---|
| `dk` | Dialogic/DK SS7 and DKSS7Interface log format |

### Decoders

| Name | DLT | Description |
|---|---|---|
| `sccp` | 142 | Decodes DK TLV envelope to SCCP wire format |
| `mtp` / `raw` | 141 | Passes MTP3 hex through as-is |

---

## 8. Task: Label signalling nodes

By default, the tool auto-detects which IP addresses belong to your SmartSTP (signalling) nodes by voting on source/destination IPs in the PCAP frames.

Use `--signode` when:
- Auto-detection produces wrong node names or wrong direction arrows in the HTML diagram
- You have multiple SmartSTP nodes with overlapping traffic and need explicit labelling

### Command addition

Add one `--signode` per node:

```bash
python3 extract-sds7-logs.py \
  ... \
  --signode "signode1:172.26.131.18,172.26.131.19" \
  --signode "signode2:172.26.132.18,172.26.132.19"
```

### Flag

| Flag | Required | Description |
|---|---|---|
| `--signode NAME:IP1,IP2` | No (repeatable) | Associates a node name with one or more Sigtran IPs. Overrides auto-detection for those IPs. |

### How to find your node IPs

On the signalling node, look for the `CNSYS` configuration entry:

```
CNSYS:IPADDR=172.26.131.2,IPADDR2=172.26.131.18,PER=0,AUTOACT=N;
```

`IPADDR` and `IPADDR2` are the two IPs (primary and redundant) for that SmartSTP node.

---
