# Design: HTML Flow Direction Fix + Generic Trace Flag

Date: 2026-06-11

## Summary

Two independent enhancements to `extract-callservice-logs.py`:

1. Fix HTML sequence diagram showing all messages as inbound
2. Replace `-s`/`-d` trace flags with a single repeatable `--trace` flag

---

## Enhancement 1A: HTML Flow Direction Fix

### Root Causes

**Bug A — TcapServer `outgoing` logic (line 1516)**

```python
# CURRENT (wrong)
outgoing = forwarded_to_app or sent_to_nw

# FIXED
outgoing = sent_to_nw
```

- `"Sending to App"` (`forwarded_to_app=True`) means TcapServer forwarded a network-received message to the app — this is **inbound**
- `"Sending to n/w"` (`sent_to_nw=True`) means TcapServer sent an app-originated message to the network — this is **outbound**
- The bug marks both as `outgoing=True`, so all normal TcapServer blocks get `direction='out'`

**Bug B — `_detect_our_ips` first-record-wins poisoning**

The function takes the first DetailedTrace record per dialog to determine direction, then uses that direction to classify a PCAP IP as "ours". If the first DetailedTrace record is `'in'` but the matching PCAP packet happens to be one we sent, the remote IP gets added to `our_ips`. The correction pass at lines 1961–1970 then flips every direction — all outbound messages (ip_dst = remote = wrongly in `our_ips`) get labelled `'in'`.

### Fix: Counter-based `_detect_our_ips`

Replace first-record-wins with a counter across **all** matching detail+PCAP pairs:

```
For each detail record with a known direction:
    Find all PCAP flow records in the same dialog
    direction='in'  → ip_dst is a candidate "our IP"
    direction='out' → ip_src is a candidate "our IP"
Tally all candidates; IP(s) with the most votes become our_ips
```

A single miscorrelated record cannot poison detection; it is outvoted by the majority.

### Fallback hierarchy (unchanged structure, corrected behaviour)

| Condition | Direction source |
|---|---|
| `--signode` given | Explicit IP map (highest priority) |
| PCAP available + our_ips detected | PCAP ip_src/ip_dst override (existing lines 1961–1970) |
| No PCAP or detection failed | DetailedTrace field 8 as-is |
| No DetailedTrace | TcapServer semantics: `sent_to_nw` → out, else in |

No new code paths — two targeted fixes only.

---

## Enhancement 1B: Main Log "Releasing state machine" Cut-off

### Problem

PASS 2.5 in `process_main_log` accumulates "no-fsmid" lines on tracked threads into `pending`. When the last seen line was a target-FSMId line, all of `pending` is added to `target_context_indices` with no upper bound. This allows thread lines from a **new call** that reuses the same thread to bleed into the extraction.

The semantic end of a FSMId in main callservice logs is a line containing both the FSMId and `"Releasing state machine"`. After this, 1–2 cleanup logger lines on the same thread follow before the thread picks up a new call.

### Fix

**Constant:**
```python
TRAILING_AFTER_RELEASE = 3
```

**PASS 1 addition** — detect the release line index per thread (in the existing `fsmid_line_indices` loop):
```python
release_indices = {}  # thread -> idx of "Releasing state machine" line for this FSMId
if 'releasing state machine' in line.lower():
    thread = parse_thread(line)
    if thread and thread not in release_indices:
        release_indices[thread] = idx
```

**PASS 2.5 change** — cap trailing no-fsmid lines after the release point:
```python
# CURRENT
if last_was_target:
    target_context_indices.update(pending)

# FIXED
if last_was_target:
    release_idx = release_indices.get(thread)
    if release_idx is not None:
        capped = [i for i in pending if i <= release_idx + TRAILING_AFTER_RELEASE]
        target_context_indices.update(capped)
    else:
        target_context_indices.update(pending)  # unchanged if no release line found
```

No change to PASS 3/4; `target_context_indices` is already bounded before the extraction loop runs.

**Backward compatible:** if no "Releasing state machine" line exists for the FSMId (truncated log, call type that does not emit it), existing behaviour is unchanged.

---

## Enhancement 2: Generic `--trace` Flag

### CLI Change

Remove mandatory `-s`/`-d`. Add repeatable `--trace` / `-f`:

```bash
python3 extract-callservice-logs.py \
  --trace "applogs/SummaryTrace*" \
  --trace "applogs/DetailTrace*" \
  --trace "applogs/applog*" \
  -i <FSMId> ...
```

- `-s`/`-d` become **deprecated aliases** — still accepted, hidden from `--help`, mapped to `--trace` internally
- Mandatory check: at least one `--trace` argument must be given
- All other flags (`-i`, `-m`, `-t`, `-p`, etc.) unchanged

### Auto-detection for PCAP Correlation and HTML

Each `--trace` argument's files are identified by their **basename prefix** (case-insensitive):

| Basename prefix | Treatment |
|---|---|
| `SummaryTrace*` | `parse_summary_trace_fields` + PCAP filter generation; text output |
| `DetailTrace*` or `DetailedTrace*` | `parse_detail_trace_records` for HTML; text output |
| anything else | text output (`process_simple_search`) only |

### Prefix Extraction (Section Header)

Each `--trace` glob pattern produces one output section. Header is derived from matched files:

1. Expand glob → collect basenames; strip `.gz`
2. Strip date/version suffix: remove `[._-]\d{4}\d*.*$` (covers `.20260603-162248`, `.2026`, `-20260101`, etc.)
3. Strip file extension (`.log`, `.csv`, `.txt`, etc.)
4. Find **longest common prefix** of all stripped names in the group
5. Strip trailing `-`, `_`, `.`, or digits from that common prefix → **header**

Examples:

| Glob | Matched basenames (stripped) | Header |
|---|---|---|
| `SummaryTrace*` | `SummaryTrace`, `SummaryTrace` | `SummaryTrace` |
| `appfulltrace2.2026*` | `appfulltrace2` | `appfulltrace2` |
| `app-trace1*` + `app-trace2*` (two args) | `app-trace1`, `app-trace2` | `app-trace` |
| `app-trace1*` + `app-trace-02*` | `app-trace1`, `app-trace-02` | `app-trace` |
| `appevent.csv` | `appevent` | `appevent` |

Output section format (unchanged):
```
==================== SECTION: <header> ====================
```

### Output Ordering

Sections written in the order `--trace` arguments appear on the command line. Existing SummaryTrace → DetailedTrace → CallService → TcapServer ordering is preserved when the user passes them in that order.

---

## Files Changed

| File | Changes |
|---|---|
| `extract-callservice-logs.py` | Fix `outgoing = sent_to_nw`; replace `_detect_our_ips` IP detection with counter; add `release_indices` to PASS 1; cap trailing lines in PASS 2.5; add `--trace`/`-f` flag; deprecate `-s`/`-d` as aliases; add prefix extraction helper; update `process_simple_search` call sites |

No new files. No changes to `hexlog2pcap.py` or test files.

---

## Out of Scope

- TcapServer timestamp-matching fix (separate backlog item)
- Sigtran node identification from config files
- Correct log block ordering via timestamp+thread mapping
