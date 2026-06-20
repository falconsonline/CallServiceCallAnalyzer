# Installation & User Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `README.md` and `docs/user-guide.md` — a task-oriented installation and user guide for `extract-sds7-logs.py` and `hexlog2pcap.py` targeted at new users unfamiliar with the telecom stack.

**Architecture:** Two files. `README.md` is a short entry point (overview, requirements, quick start, link to guide). `docs/user-guide.md` is the full reference: 13 sections from Overview through Glossary, each task section self-contained with prerequisites, exact commands, and output explanations.

**Tech Stack:** Markdown. No code changes. No tests. Verify steps check written content against the actual scripts.

## Global Constraints

- Script name is `extract-sds7-logs.py` — never `extract-callservice-logs.py`
- Python 3.10+ minimum
- All output lands in a single `.txt` file per run (sections separated by `==== SECTION: … ====` headers)
- Output file naming: `{testcase}-{fsmid}-extract-{YYYYMMDD_HHMMSS}.txt` (with `-n`) or `TestCase-{fsmid}-{YYYYMMDD_HHMMSS}.txt` (without `-n`)
- PCAP output suffixes: `_tcap.pcap` (TcapServer), `.pcap` (sigtran), `.html` (diagram)
- Audience: broader/new users — define all telecom terms before using them

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `README.md` | Create | Short overview, requirements, quick start, link to full guide |
| `docs/user-guide.md` | Create | Full 13-section task-oriented reference guide |

---

### Task 1: Write README.md

**Files:**
- Create: `README.md`

**Interfaces:**
- Produces: entry-point doc that links to `docs/user-guide.md`

- [ ] **Step 1: Write README.md**

Write the following content to `README.md` at the project root:

```markdown
# SDS7 Log Analyzer

Extracts and correlates telecom call logs for a specific call identified by its **FSMId** (StateMachineId). Given an FSMId, the tool greps SummaryTrace, DetailTrace, and application logs for that ID, extracts correlated TcapServer blocks, converts DK/SS7 hex dumps to PCAP, filters real Sigtran PCAP captures by TCAP Transaction ID, and optionally generates an HTML mermaid sequence diagram of the full signalling flow.

## Requirements

- Python 3.10 or later
- [scapy](https://scapy.net/) — `pip install scapy`
- Wireshark CLI tools: `tshark`, `mergecap`, `text2pcap`
  - macOS: `brew install wireshark`
  - Linux: `sudo apt install tshark`
  - *(Only needed for PCAP filtering and HTML diagram generation)*

## Quick Start

```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId>
```

Output files are written to `logs/` by default.

## Full Documentation

See [docs/user-guide.md](docs/user-guide.md) for the complete guide: installation, all workflows, CLI reference, troubleshooting, and glossary.
```

- [ ] **Step 2: Verify README.md**

Read `README.md` and confirm:
- Script name is `extract-sds7-logs.py` (not callservice)
- Link to `docs/user-guide.md` is correct relative path
- Three mandatory flags shown in quick start: `-f`, `-f`, `-i`

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add README with quick start and link to user guide"
```

---

### Task 2: Write user-guide.md — sections 1–3 (Overview, Prerequisites, Key Concepts)

**Files:**
- Create: `docs/user-guide.md`

**Interfaces:**
- Produces: user guide file; Tasks 3 and 4 append to it

- [ ] **Step 1: Write docs/user-guide.md with sections 1–3**

Write the following content to `docs/user-guide.md`:

````markdown
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
````

- [ ] **Step 2: Verify sections 1–3**

Read `docs/user-guide.md` and confirm:
- Table of contents has 13 entries with anchor links
- Section 3 key concepts table has all 14 terms
- No reference to `extract-callservice-logs.py`

- [ ] **Step 3: Commit**

```bash
git add docs/user-guide.md
git commit -m "docs: add user guide sections 1-3 (overview, prerequisites, key concepts)"
```

---

### Task 3: Write user-guide.md — sections 4–8 (Task workflows)

**Files:**
- Modify: `docs/user-guide.md` (append sections 4–8)

**Interfaces:**
- Consumes: `docs/user-guide.md` created in Task 2
- Produces: all task workflow sections

- [ ] **Step 1: Append sections 4–8 to docs/user-guide.md**

Append the following content to `docs/user-guide.md`:

````markdown
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
  -f "wsmstrace/WSMSTrace*" \
  -f "campaigntrace/CampaignTrace*" \
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
````

- [ ] **Step 2: Verify sections 4–8**

Read `docs/user-guide.md` from section 4 onwards and confirm:
- All code blocks use `extract-sds7-logs.py`
- Section 5 flag table lists `-p` and `-z` with correct mandatory notes
- Section 6 states TcapServer log is mandatory for `--html`
- Section 7 hexlog2pcap flags match `hexlog2pcap.py --help` output (verify by running: `python3 hexlog2pcap.py --help`)
- Section 8 explains how to find node IPs from `CNSYS` config

- [ ] **Step 3: Commit**

```bash
git add docs/user-guide.md
git commit -m "docs: add user guide sections 4-8 (task workflows)"
```

---

### Task 4: Write user-guide.md — sections 9–13 (Reference, Troubleshooting, Glossary)

**Files:**
- Modify: `docs/user-guide.md` (append sections 9–13)

**Interfaces:**
- Consumes: `docs/user-guide.md` with sections 1–8
- Produces: complete user guide

- [ ] **Step 1: Append sections 9–13 to docs/user-guide.md**

Append the following content to `docs/user-guide.md`:

````markdown
## 9. Output files reference

All files are written to the directory specified by `-o` (default: `logs/`).

The base filename is determined by:
- **With `-n MyTestCase`:** `MyTestCase-{fsmid}-extract-{YYYYMMDD_HHMMSS}`
- **Without `-n`:** `TestCase-{fsmid}-{YYYYMMDD_HHMMSS}`

| File | When produced | Contents |
|---|---|---|
| `{base}.txt` | Always | All extracted content: one section per `-f` trace group, one section for main log (`-m`), one section for TcapServer (`-t`). Sections are separated by `==== SECTION: … ====` headers. |
| `{base}_tcap.pcap` | When `-t` is given and TIDs are found | PCAP converted from TcapServer DK hex dumps, filtered by TCAP TID. |
| `{base}.pcap` | When `-p` is given | Filtered real Sigtran PCAP containing only packets matching the call's TCAP TIDs. |
| `{base}.html` | When `--html` is given | Self-contained HTML mermaid sequence diagram. Open in any browser. |
| `logs/extract.log` | Always | Tool run log with INFO/DEBUG messages. Use `-v` for debug detail. |

---

## 10. CLI reference — `extract-sds7-logs.py`

```
python3 extract-sds7-logs.py [options]
```

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `-f` / `--trace GLOB` | string (repeatable) | **Yes** | — | Glob pattern for a trace file group. Each `-f` produces a named section in the output. Files named `SummaryTrace*` and `DetailTrace*`/`DetailedTrace*` are auto-detected for PCAP correlation. |
| `-i` / `--id FSMID` | string | **Yes** | — | FSMId / StateMachineId to extract. |
| `-m` / `--main GLOB` | string | No | — | Glob for main application log files. Omit to skip main-log extraction. |
| `-o` / `--output-dir DIR` | path | No | `logs/` | Output directory. Created automatically. |
| `-p` / `--pcaps GLOB` | string | No¹ | — | Glob for PCAP capture files (`.pcap`, `.pcap.gz`). |
| `-z` / `--timezone TZ` | string | No¹ | — | Timezone of the log system. IANA name or UTC offset (`+0400`, `-0500`). |
| `-t` / `--tcap GLOB` | string | No² | — | Glob for TcapServer log files. |
| `-te` / `--tcap-event GLOB` | string | No | — | Glob for TcapServerEvent log files. |
| `-n` / `--testcase NAME` | string | No | — | Prefix for output filenames. Spaces become underscores. |
| `-v` / `--debug` | flag | No | off | Enable verbose debug logging. |
| `--html` | flag | No² | off | Generate HTML mermaid sequence diagram. |
| `--signode NAME:IP1,IP2` | string (repeatable) | No | — | Map a node name to its Sigtran IPs. Overrides auto-detection. |
| `-s` / `--summary GLOB` | string | — | — | *(Deprecated alias for `-f`. Accepted for backward compatibility, hidden from `--help`.)* |
| `-d` / `--detail GLOB` | string | — | — | *(Deprecated alias for `-f`. Accepted for backward compatibility, hidden from `--help`.)* |

¹ `-p` and `-z` are mutually mandatory: if either is given, both are required.
² `--html` and `-t` are mutually mandatory: if `--html` is given, `-t` is required.

---

## 11. CLI reference — `hexlog2pcap.py`

```
python3 hexlog2pcap.py [infile] [outfile] [options]
```

| Flag | Type | Required | Default | Description |
|---|---|---|---|---|
| `infile` | path (positional) | No³ | — | Input log file. |
| `outfile` | path (positional) | No³ | — | Output base name; `.pcap` is appended. |
| `-p` / `--parser NAME` | string | No | `dk` | Log parser to use. |
| `-d` / `--decoder NAME` | string | No | `sccp` | Protocol decoder to use. |
| `-v` / `--verbose` | flag | No | off | Verbose output. |
| `--text2pcap PATH` | path | No | auto | Explicit path to `text2pcap` binary. |
| `--timeformat FMT` | string | No | auto | `strptime` format for log timestamps. |
| `--list` | flag | No | — | List registered parsers/decoders and exit. |

³ `infile` and `outfile` are positional and required unless `--list` is used.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'scapy'` | scapy not installed | `pip install scapy` |
| `tshark: command not found` | Wireshark CLI not on PATH | Install Wireshark; verify with `which tshark`. Tool also searches `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`. |
| `ERROR: at least one -f/--trace argument is required` | Missing mandatory `-f` flag | Add `-f "applogs/SummaryTrace*"` |
| `ERROR: -z/--timezone is required when -p is used` | `-p` given without `-z` | Run `date +"%z"` on the log system; pass result as `-z "+0400"` |
| `ERROR: -t/--tcap is required when --html is used` | `--html` given without `-t` | Add `-t "applogs/TcapServer-0*"` |
| Output `.txt` file is empty / no sections found | FSMId not present in the log files | Verify the FSMId with: `grep -r <FSMId> applogs/` |
| TcapServer section is blank | TCAP TIDs not found in trace output | Use `-v` to inspect TID search terms in `logs/extract.log`; confirm TIDs appear in the trace with `grep -i "otid\|dtid" logs/<output>.txt` |
| No packets in filtered PCAP | Wrong timezone or TIDs not in PCAP | Verify timezone: `date +"%z"` on log system. Confirm TIDs in PCAP: `tshark -r <file.pcap> -Y "tcap.tid" -T fields -e tcap.tid` |
| HTML diagram is blank or shows only one node | TcapServer log not found or wrong glob | Check glob: `ls applogs/TcapServer-0*`; confirm files are present and readable |
| `mergecap: command not found` | Wireshark CLI partially installed | Ensure `mergecap` is on PATH alongside `tshark` |
| `text2pcap: command not found` | Wireshark CLI partially installed | Ensure `text2pcap` is on PATH, or pass `--text2pcap /path/to/text2pcap` to `hexlog2pcap.py` |

---

## 13. Glossary

| Term | Definition |
|---|---|
| **ASN.1** | Abstract Syntax Notation One — the encoding used for TCAP/CAMEL/MAP protocol messages. The main application log contains ASN.1 decode blocks captured during extraction. |
| **CAMEL** | Customised Applications for Mobile networks Enhanced Logic — the IN (Intelligent Network) protocol used by CallService for prepaid/postpaid call control. Carried over TCAP. |
| **CampaignTrace** | Per-session trace log produced by iCampaign. File names match `CampaignTrace*`. |
| **DetailTrace / DetailedTrace** | Detailed per-call protocol trace log. Contains CAMEL/MAP operation names, parameters, and state transitions. File names match `DetailTrace*` or `DetailedTrace*`. |
| **DK / DKSS7** | Dialogic SS7 board log format. Hex dumps in this format are converted to PCAP by `hexlog2pcap.py`. |
| **DLT** | Data Link Type — the link-layer type stored in a PCAP file header. DLT 141 = MTP3; DLT 142 = SCCP. |
| **FSMId / StateMachineId** | Unique hex identifier for one call or session instance (e.g. `2e277b400013022`). The primary search key for all log extraction. |
| **FTN (Forward-To Number)** | Forwarding destination in a DNISCallsMap entry. If a call is forwarded, the tool auto-discovers and extracts the correlated FSMId. |
| **HLR** | Home Location Register — an SS7 network node that handles MAP queries for subscriber data. Appears as a remote entity in the HTML diagram. |
| **iCampaign** | SDS7 campaign management application. Produces `CampaignTrace*` logs. |
| **M2PA** | MTP2 Peer Adaptation Layer — one Sigtran variant for carrying SS7 MTP3 over IP. |
| **M3UA** | MTP3 User Adaptation Layer — another Sigtran variant. Affects which tshark fields are used to extract SPC values. |
| **MAP** | Mobile Application Part — the SS7 protocol used for HLR queries (send routing info, insert subscriber data, etc.). Carried over TCAP. |
| **MTP3** | Message Transfer Part 3 — the SS7 network layer. Contains OPC/DPC (originating/destination SPC). |
| **PCAP** | Packet capture file format (libpcap). Used for Sigtran (SS7-over-IP) traffic captures. Files may be `.pcap` or `.pcap.gz`. |
| **SCCP** | Signalling Connection Control Part — SS7 transport layer above MTP3. Contains Called/Calling Party Address (CdPA/CgPA). |
| **SCTP** | Stream Control Transmission Protocol — the IP transport for Sigtran. Frames may carry multiple DATA chunks; the tool dechunks these before filtering. |
| **Sigtran** | Protocol family for carrying SS7 signalling over IP networks. Includes M2PA and M3UA variants. |
| **SmartSTP** | Signalling Transfer Point — the signalling gateway node bridging SS7 and Sigtran IP. Also called "signode" in this tool. |
| **SPC (Signalling Point Code)** | Network address of an SS7 node. Displayed as zone-region-sp (e.g. `3-100-1`) and decimal (e.g. `24577`). Distinguishes Physical SPC from Alias SPC in the HTML diagram. |
| **SS7** | Signalling System No. 7 — the global telephone signalling standard. |
| **SSP** | Service Switching Point — the switch that initiates CAMEL IN calls (the calling network node). Appears as a remote entity in the HTML diagram. |
| **SummaryTrace** | High-level per-call event log. One line per significant event. File names match `SummaryTrace*`. |
| **TCAP** | Transaction Capabilities Application Part — the SS7 application layer that multiplexes CAMEL/MAP dialogs. Each dialog identified by a Transaction ID (TID). |
| **TID (Transaction ID)** | 4-byte hex value (e.g. `042e7fbe`) identifying one TCAP transaction. A call may span several TIDs (begin/continue/end across multiple nodes). |
| **TcapServer** | SDS7 TCAP layer process. Produces `TcapServer-0*` logs. |
| **VLR** | Visitor Location Register — an SS7 node that handles MAP queries for roaming subscribers. |
| **WSMS** | SDS7 wireless messaging application. Produces `WSMSTrace*` logs. |
````

- [ ] **Step 2: Verify sections 9–13**

Read `docs/user-guide.md` from section 9 onwards and confirm:
- Output files table matches actual script behavior: one `.txt` file, `_tcap.pcap`, `.pcap`, `.html`
- CLI table for `extract-sds7-logs.py` has all 14 flags (including deprecated `-s`/`-d`)
- CLI table for `hexlog2pcap.py` has all 8 flags including `--timeformat`
- Glossary has entries for all terms used in the guide (spot-check: TCAP, SPC, M2PA, FTN, DLT)
- Troubleshooting covers: scapy import, tshark not found, missing `-z`, missing `-t`, empty output, empty TcapServer, no PCAP packets, blank HTML diagram, missing mergecap, missing text2pcap

- [ ] **Step 3: Run a final sanity check on both files**

```bash
# Confirm no extract-callservice-logs.py references remain
grep -n "extract-callservice-logs" docs/user-guide.md README.md
# Expected: no output

# Confirm section count
grep -c "^## [0-9]" docs/user-guide.md
# Expected: 13

# Confirm README links correctly
grep "user-guide.md" README.md
# Expected: one line with the link
```

- [ ] **Step 4: Commit**

```bash
git add docs/user-guide.md
git commit -m "docs: add user guide sections 9-13 (reference, troubleshooting, glossary)"
```
````
