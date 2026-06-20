# SDS7 Log Analyzer

Extracts and correlates telecom call logs for a specific call identified by its **FSMId** (StateMachineId). Supports SDS7-based applications: **CallService**, **iCampaign**, and **WSMS**.

Given an FSMId, the tool:
- Greps SummaryTrace, DetailTrace, WSMSTrace, CampaignTrace, and application logs for that ID
- Automatically discovers and extracts correlated FSMIds (FTN-forwarded calls)
- Extracts correlated TcapServer blocks by TCAP Transaction ID
- Converts DK/SS7 hex dumps in TcapServer logs to PCAP
- Filters real Sigtran PCAP captures by TCAP TID
- Optionally generates an HTML mermaid sequence diagram of the full signalling flow

## Requirements

- Python 3.10 or later
- [scapy](https://scapy.net/) — `pip install scapy`
- Wireshark CLI tools: `tshark`, `mergecap`, `text2pcap`
  - macOS: `brew install wireshark`
  - Linux: `sudo apt install tshark`
  - *(Only needed for PCAP filtering and HTML diagram generation)*

## Quick Start

**CallService:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "applogs/DetailTrace*" \
  -m "applogs/callservice-*" \
  -i <FSMId>
```

**iCampaign / WSMS:**
```bash
python3 extract-sds7-logs.py \
  -f "applogs/SummaryTrace*" \
  -f "wsmstrace/WSMSTrace*" \
  -f "campaigntrace/CampaignTrace*" \
  -m "applogs/applog*" \
  -i <FSMId>
```

Output files are written to `logs/` by default.

## Full Documentation

See [docs/user-guide.md](docs/user-guide.md) for the complete guide: installation, all workflows, CLI reference, troubleshooting, and glossary.
