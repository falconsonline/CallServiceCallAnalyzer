# Installation & User Guide — Design Spec

**Date:** 2026-06-20
**Audience:** Broader/new users unfamiliar with the telecom stack
**Scope:** Full reference — installation, all workflows, CLI reference, troubleshooting, glossary

---

## Goal

Produce two documents:

1. **`README.md`** at the project root — short overview, requirements summary, quick-start command, link to full guide
2. **`docs/user-guide.md`** — comprehensive task-oriented guide covering every workflow the tool supports

Neither file exists today. Both will be created from scratch.

---

## Approach

**Task-oriented structure.** Content is organised around what the user wants to do (extract logs, generate a diagram, convert hex dumps) rather than around flag names or internal architecture. Each task section states prerequisites, gives the exact command, and explains the output. A full CLI reference and glossary appear as appendices.

---

## `README.md` — Structure

| Section | Content |
|---|---|
| Title + badge line | Project name; one-line description |
| What it does | 2–3 sentences: FSMId-based extraction, log correlation, PCAP filtering, HTML diagram |
| Requirements | Python 3.10+, scapy, Wireshark CLI tools (tshark / mergecap / text2pcap) |
| Quick start | Minimal invocation with the three mandatory flags (-f, -i, -m); output landing in logs/ |
| Full documentation | Link to `docs/user-guide.md` |

---

## `docs/user-guide.md` — Sections

### 1. Overview
- What problem the tool solves: given a single FSMId, gather every relevant log line and network packet across multiple log sources for any SDS7-based application (CallService, iCampaign, WSMS, etc.)
- The two scripts and how they relate: `extract-sds7-logs.py` is the main orchestrator; `hexlog2pcap.py` is a standalone hex-to-PCAP converter also used internally
- Typical use case narrative: engineer has a reported call or campaign failure, needs to correlate SummaryTrace, DetailTrace, application main logs, TcapServer logs, and PCAP captures in one step

### 2. Prerequisites

**Python:**
- Python 3.10 or later
- Verify: `python3 --version`

**Python packages:**
- `scapy` — used for SCTP dechunking
- Install: `pip install scapy`

**Wireshark CLI tools** (must be on PATH):
- `tshark`, `mergecap`, `text2pcap`
- macOS (Homebrew): `brew install wireshark`
- Linux (Debian/Ubuntu): `sudo apt install tshark`
- Verify: `tshark --version`

**Note:** `tshark` is only required when `-p` (PCAP filtering) or `--html` (sequence diagram) is used. The tool works for log-only extraction without it.

### 3. Key Concepts

A brief plain-English glossary of terms a new user needs before running the tool — what to gather and why:

| Term | Plain-English definition |
|---|---|
| FSMId / StateMachineId | Unique identifier for one call instance; the primary search key for all extraction |
| TCAP TID (Transaction ID) | 4-byte hex ID (e.g. `042e7fbe`) linking SS7 messages across the signalling network to the same call |
| SPC (Signalling Point Code) | Network address of a signalling node; shown in MTP3 routing and in the HTML diagram |
| SummaryTrace log | High-level per-call event log; file names match `SummaryTrace*` |
| DetailTrace log | Detailed per-call protocol log; file names match `DetailTrace*` or `DetailedTrace*` |
| WSMSTrace log | WSMS application trace log; file names match `WSMSTrace*` |
| CampaignTrace log | iCampaign application trace log; file names match `CampaignTrace*` |
| Main application log | Thread-based application log; file names match `callservice-*`, `applog*`, etc. |
| TcapServer log | SS7 TCAP layer log; file names match `TcapServer-0*` |
| TcapServerEvent log | TCAP event log (optional); file names match `TcapServerEvent*` |
| PCAP | Network packet capture file (`.pcap` / `.pcap.gz`) containing raw Sigtran traffic |
| M2PA / M3UA | Two variants of Sigtran (SS7-over-IP) associations; affects PCAP direction detection |

### 4. Task: Extract logs for a call

**What you need:**
- One or more trace log files (SummaryTrace, DetailTrace, WSMSTrace, CampaignTrace, or other applog)
- FSMId of the call/session to extract
- (Optional) Main application log files

**Minimal command:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -i <FSMId>
```

**With application main log:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId> \
  -n "TestCaseName"
```

**Additional trace types (iCampaign / WSMS):**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "wsmstrace/WSMSTrace*" \
  -f "campaigntrace/CampaignTrace*" \
  -m "applogs/applog*" \
  -i <FSMId>
```

**Flags used:**
- `-f` / `--trace` — glob pattern for a trace file group (repeatable; auto-detects SummaryTrace vs DetailTrace by filename; supports any trace type)
- `-i` / `--id` — FSMId to extract (mandatory)
- `-m` / `--main` — glob for main application log files (optional)
- `-n` / `--testcase` — prefix for output filenames (optional)
- `-v` / `--debug` — verbose logging (optional)

**Output:** Files written to `logs/` (or `-o <dir>`); one `.txt` file per trace group plus a combined main-log extract.

### 5. Task: Filter PCAP captures by TCAP TID

**When to use:** You have raw Sigtran PCAP captures and want to isolate packets for the specific call.

**Additional requirement:** Know the timezone of the log-generating system.

**Find the timezone offset:**
```bash
# Run this on the system that generated the logs:
date +"%z"
# Example output: +0400
```

**Command:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId> \
  -p "pcaps/stp*.pcap*" \
  -z "+0400"
```

**Additional flags:**
- `-p` / `--pcaps` — glob for PCAP capture file(s); mandatory when `-z` is given
- `-z` / `--timezone` — timezone of the log system; IANA name (`America/Mexico_City`) or UTC offset (`+0400`, `-0500`); mandatory when `-p` is given

**Output:** A filtered `.pcap` file in `logs/` containing only packets matching the call's TCAP TIDs.

### 6. Task: Generate an HTML sequence diagram

**When to use:** You want a visual hop-by-hop signalling flow across all nodes for the call.

**Additional requirement:** TcapServer log files; TCAP log is mandatory for `--html`.

**Command:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId> \
  -p "pcaps/stp*.pcap*" \
  -z "+0400" \
  -t "applogs/TcapServer-0*" \
  -te "applogs/TcapServerEvent*" \
  --html
```

**Additional flags:**
- `-t` / `--tcap` — glob for TcapServer log files; mandatory when `--html` is used; covers SDS-based apps (CallService, iCampaign, WSMS)
- `-te` / `--tcap-event` — glob for TcapServerEvent log files (optional)
- `--html` — generate the HTML sequence diagram

**What the diagram shows:**
- Participants: Remote Entity (SSP/HLR/VLR) → SmartSTP signode(s) → TcapServer instance(s) → SDS application instance(s) (CallService / iCampaign / WSMS)
- Each arrow is one TCAP/CAMEL/MAP message with direction, message type, and TID
- SPC labels on participant headers (not repeated per arrow)
- Dark/light mode toggle; snapshot-copy button

**Output:** A self-contained `.html` file in `logs/` — open in any browser.

### 7. Task: Convert hex dumps to PCAP (standalone)

**When to use:** You have a raw DK/SS7 hex log and want to convert it to PCAP independently of a call extraction.

**Command:**
```bash
python3 hexlog2pcap.py <input.log> <output_base> -p dk -d sccp -v
```

**List available parsers and decoders:**
```bash
python3 hexlog2pcap.py --list
```

**Flags:**
- `infile` — input log file (positional)
- `outfile` — output base name; `.pcap` extension is appended (positional)
- `-p` / `--parser` — log parser to use (default: `dk`)
- `-d` / `--decoder` — protocol decoder to use (default: `sccp`)
- `-v` / `--verbose` — verbose output
- `--text2pcap PATH` — explicit path to `text2pcap` binary (if not on PATH)
- `--list` — list registered parsers/decoders and exit

**Parsers:** `dk` — Dialogic/DK SS7 and DKSS7Interface log format

**Decoders:** `sccp` — decodes DK TLV envelope to SCCP wire format (DLT 142); `raw` / `mtp` — passes MTP3 hex through as-is (DLT 141)

### 8. Task: Label signalling nodes

**When to use:** The tool cannot auto-detect which IP addresses belong to your SmartSTP (signalling) nodes from the PCAP, or the auto-detected labels are wrong.

**Command addition:**
```bash
  --signode "signode1:172.26.131.18,172.26.131.19" \
  --signode "signode2:172.26.132.18,172.26.132.19"
```

**Flag:**
- `--signode NAME:IP1,IP2` — repeatable; associates a node name with one or more Sigtran IPs; overrides auto-detection

**How auto-detection works:** The tool votes on IP addresses found in the PCAP frames; the most-seen local IP pair becomes the signode. Manual `--signode` takes precedence when the auto result is wrong (e.g. multiple SmartSTP nodes with overlapping traffic).

### 9. Output files reference

| File pattern | When produced | Contents |
|---|---|---|
| `<name>_SummaryTrace.txt` | Always | Extracted SummaryTrace lines for the FSMId |
| `<name>_DetailTrace.txt` | Always | Extracted DetailTrace lines for the FSMId |
| `<name>_main.txt` | When `-m` given | Extracted main application thread blocks (CallService / iCampaign / WSMS) |
| `<name>_TcapServer.txt` | When `-t` given | Extracted TcapServer thread blocks by TID |
| `<name>_tcap.pcap` | When `-t` given | PCAP from TcapServer DK hex dumps, filtered by TID |
| `<name>_sigtran.pcap` | When `-p` given | Filtered real PCAP captures by TCAP TID |
| `<name>.html` | When `--html` given | Self-contained HTML mermaid sequence diagram |

### 10. CLI reference — `extract-sds7-logs.py`

Complete flag table with type, mandatory/optional, and description. All flags, including deprecated `-s`/`-d` aliases.

### 11. CLI reference — `hexlog2pcap.py`

Flag table for the standalone converter.

### 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: scapy` | scapy not installed | `pip install scapy` |
| `tshark: command not found` | Wireshark CLI not on PATH | Install Wireshark; verify with `which tshark` |
| `ERROR: -z/--timezone is required` | `-p` given without `-z` | Run `date +"%z"` on the log system and pass result as `-z` |
| `ERROR: -t/--tcap is required` | `--html` given without `-t` | Add `-t "applogs/TcapServer-0*"` |
| Empty TcapServer section | Thread ID mismatch | Use `-v` to inspect TID search terms; check log format |
| No packets in filtered PCAP | Wrong timezone offset or TID not present in PCAP | Verify timezone with `date +"%z"` on log system; confirm TIDs with `tshark -r file.pcap -Y "tcap.tid"` |
| `ERROR: at least one -f/--trace argument is required` | Missing mandatory flag | Add `-f "applogs/SummaryTrace*"` |

### 13. Glossary

Full alphabetical glossary: ASN.1, CAMEL, DetailTrace, FSMId, M2PA, M3UA, MAP, MTP3, PCAP, SPC, SCCP, SCTP, SummaryTrace, TCAP, TID, TcapServer, Sigtran, SS7.

---

## Non-Goals

- Does not document internal architecture (that's in `CLAUDE.md` and the feature docs in `docs/`)
- Does not cover extending `hexlog2pcap.py` with custom parsers/decoders (developer concern, not user concern)
- Does not cover test suite usage

---

## Files to Create

| File | Action |
|---|---|
| `README.md` | Create new |
| `docs/user-guide.md` | Create new |
