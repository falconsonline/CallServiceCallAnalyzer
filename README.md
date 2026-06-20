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
