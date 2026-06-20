# PCAP Extraction Bug Fixes — Session Notes

## Background

Scripts involved: `extract-sds7-logs.py`, `debug_detail_filter.py`

Test case: FSMId `2e277b400013022`, outgoing MAP InsertSubscriberData dialog.

The script was failing to capture the following frames in its generated PCAP:

```
6  172.26.131.18:4087 → 172.26.132.2:5000   invoke insertSubscriberData  otid=74a6cd3d
7  172.26.133.19:5000 → 172.26.131.3:4086   returnResultLast             otid=7204032a dtid=74a6cd3d
8  172.26.131.3:4086  → 172.26.133.19:5000  End                          dtid=7204032a
```

The relevant DetailedTrace events:

```
27-04-2026 12:49:05,759,Call-02,1,2e277b400013022,SentBeginMAPV2InsertSubscriberData,,,out,map,7,1032381399,,74001,5294100009980,udt,2,begin,...
27-04-2026 12:49:05,963,Call-02,1,2e277b400013022,ReceivedContinueMAPV2InsertSubscriberDataReturnResult,,,in,map,7,1032381399,,5294100009980,59397999302,udt,2,cont,...
27-04-2026 12:49:05,964,Call-02,1,2e277b400013022,SentEndMAPV2,,,out,map,,1032381399,,59397999302,5294100009980,udt,2,end,...
```

The manual tshark filter that correctly captured the Begin frame:

```
sccp.called.digits == "5294100009980" && gsm_old.localValue == 7 && frame.time_epoch >= 1777312145.559 && frame.time_epoch <= 1777312145.95
```

---

## Bug 1 — Trace-based path not used when `-m` is present

### Problem

`process_pcap` (called when `-m` callservice logs are provided) extracts TIDs exclusively from
the extracted callservice log using:

```python
TID_RE = re.compile(r'(?:otid|dtid)\s*[=\[]\s*([0-9a-fA-F]{8})', re.IGNORECASE)
```

The outgoing MAP ISD OTID (`3d88e3d7`, decimal `1032381399`) was never logged by callservice in
any of the three recognised formats (`otid=...`, `otid[...]`, `map_otid=...`), so `extract_tids`
returned nothing for this dialog and the PCAP filter skipped it entirely.

The DetailedTrace log had the SCCP digits and opcode that would have identified the packet, but
`process_pcap` never consulted the trace files.

### Fix

When `-m` and trace files are both present, supplement the callservice-log TIDs with TIDs
discovered via trace-based PCAP filtering (merge+dechunk before extraction — see Bug 5).
`process_pcap` gains an `extra_tids` parameter; `main()` computes them before the call.

```python
# main() — before calling process_pcap
trace_filter, t_min, t_max = build_trace_based_filter(summary_fields, detail_sccp, tz_for_trace)
if trace_filter:
    pass1_filter = trace_filter
    if t_min is not None and t_max is not None:
        pass1_filter = (f'({trace_filter}) && '
                        f'frame.time_epoch >= {t_min - 1.0:.3f} && '
                        f'frame.time_epoch <= {t_max + 1.0:.3f}')
    extra_tids = _extract_tids_dechunked(pcap_files, pass1_filter)
process_pcap(log_output_path, args.pcaps, pcap_output_path, extra_tids=extra_tids or None)
```

---

## Bug 2 — IMSI added as standalone OR condition

### Problem

`build_trace_based_filter` was adding `e212.imsi == "740010215580251"` as a standalone OR
condition from the SummaryTrace loop. As a bare filter with no SCCP, opcode, or timestamp
constraint, it matched any packet in the entire PCAP carrying that IMSI — including packets from
unrelated dialogs — inflating the TID set.

### Fix

Removed the `if imsi: conditions.add(...)` block entirely. IMSI is already implicitly covered by
the SCCP digit + opcode conditions derived from the same call.

Also removed the now-unused `imsi = f.get('imsi', '').strip()` dead assignment from the summary
loop.

---

## Bug 3 — TCAP message type not included in trace filter

### Problem

DetailedTrace field 18 (index 17) carries the TCAP message type (`begin`, `cont`, `continue`,
`end`, `abort`). It was being parsed for the HTML diagram but not for PCAP filter generation.
Without it, a condition like `sccp.called.digits == "5294100009980" && gsm_old.localValue == 7`
could match any ISD packet to that VLR, not just the Begin.

### Fix

Added `_TCAP_MSG_TYPE_FILTER` mapping and wired it into `parse_detail_trace_sccp_fields` and
`build_trace_based_filter`:

```python
_TCAP_MSG_TYPE_FILTER = {
    'begin':    'tcap.begin_element',
    'continue': 'tcap.continue_element',
    'cont':     'tcap.continue_element',   # alias used in DetailedTrace
    'end':      'tcap.end_element',
    'abort':    'tcap.abort_element',
}
```

The `'cont'` alias was needed because DetailedTrace uses `cont`, not `continue`, for Continue
messages.

The filter for the Begin event becomes:

```
(sccp.called.digits == "5294100009980" && gsm_old.localValue == 7 && tcap.begin_element
 && frame.time_epoch >= 1777312145.559 && frame.time_epoch <= 1777312145.959)
```

The same mapping and alias were added to `debug_detail_filter.py`.

---

## Bug 4 — `tcap.tid` is the wrong field for TID matching in Pass 2

### Problem

`build_tshark_filter` was generating `tcap.tid == 74:a6:cd:3d`. However:

- Pass 1 extracts TIDs using `tshark -e tcap.otid -e tcap.dtid` — these are the 4-byte value
  fields from the TCAP structure.
- `tcap.tid` is a different field (session-tracking meta field in the ITU-T TCAP dissector); its
  byte content does not match the values extracted via `tcap.otid`/`tcap.dtid`.

Result: Pass 1 correctly discovered `74a6cd3d` from `tcap.otid`, but Pass 2's filter
`tcap.tid == 74:a6:cd:3d` never matched any packet.

**Confirmed via debug logs**: the trace-based filter DID extract the PCAP and find
`tcap.otid == 74:a6:cd:3d`; the TID was present in the Pass 1 result set but absent from the
Pass 2 output.

### Fix

Changed `build_tshark_filter` to generate `tcap.otid == X || tcap.dtid == X` per TID, matching
the same fields used in extraction:

```python
def build_tshark_filter(tids, first_ts=None, last_ts=None):
    tid_parts = []
    for tid in tids:
        colon = _tid_to_colon(tid)
        tid_parts.append(f'tcap.otid == {colon}')
        tid_parts.append(f'tcap.dtid == {colon}')
    tid_clause = ' || '.join(tid_parts)
    ...
```

This correctly matches Begin (OTID only), Continue (both), and End (DTID only) for each dialog.

---

## Bug 5 — Multi-chunk SCTP frame contaminates TID set

### Problem

Pass 1 was running the trace filter on raw (un-dechunked) PCAPs. Frame 79391 in the capture was
a single SCTP frame containing **two bundled chunks** — one from the correct ISD dialog and one
from an unrelated ISD dialog happening concurrently:

```
Frame 79391: calling=59397999302,50255300420  called=5294100009980,5294100059040
             otid=74a6cd3d,2220019d  dtid=00e8aa5b  opcode=7,7
             invoke insertSubscriberData / returnResultLast insertSubscriberData
```

Because `extract_tids_from_pcap_packets` saw the entire frame, it extracted **all** TIDs present:
`74a6cd3d`, `2220019d`, `00e8aa5b`. TIDs `2220019d` and `00e8aa5b` from the unrelated dialog were
then used in Pass 2, pulling in frames with `sccp.called == 5294100059040` that had nothing to do
with the call being analysed.

### Fix

Added `_extract_tids_dechunked` helper. Instead of extracting TIDs directly from raw PCAPs, it:

1. **Stage 1** — runs the trace filter on raw PCAPs, collecting matching frames
2. **Merge + dechunk** — splits multi-chunk SCTP frames so each chunk becomes its own frame
3. **Stage 2** — re-runs the same trace filter on the dechunked output and extracts TIDs

After dechunking, frame 79391 becomes two separate frames. Stage 2's filter
(`sccp.called == "5294100009980" && gsm_old.localValue == 7 && tcap.begin_element && ...`)
only matches the correct chunk (74a6cd3d). The unrelated chunk (2220019d) does not match and is
excluded — so `2220019d` and `00e8aa5b` never enter the TID set.

```python
def _extract_tids_dechunked(pcap_files, trace_filter):
    with tempfile.TemporaryDirectory() as tmpdir:
        stage1 = []
        for i, pcap in enumerate(pcap_files):
            out = os.path.join(tmpdir, f"s1_{i}.pcap")
            if run_tshark(pcap, trace_filter, out) and count_packets(out) > 0:
                stage1.append(out)
        if not stage1:
            return []
        merged    = os.path.join(tmpdir, "s1_merged.pcap")
        dechunked = os.path.join(tmpdir, "s1_dechunked.pcap")
        merge_pcaps(stage1, merged)
        dechunk_sctp_stream(merged, dechunked)
        return extract_tids_from_pcap_packets([dechunked], trace_filter)
```

Both `process_pcap_from_traces` and the `main()` supplementary path use this helper.

---

## Bug 6 — SummaryTrace conditions bound the Pass 1 window incorrectly

### Problem

`build_trace_based_filter` generates SummaryTrace conditions (SCCP pairs, e164 pairs) without any
timestamp bounds — they match packets at any point in the PCAP. Even after fixing Bug 5, a
SummaryTrace condition like `sccp.called.digits == "5294100009980"` could still match packets from
other dialogs visiting the same VLR at different times and inject their TIDs.

### Fix

The global time bound for Pass 1 must come exclusively from the **first and last DetailedTrace
records** (`min_epoch` / `max_epoch` from `build_trace_based_filter`'s detail loop — SummaryTrace
records have no timestamps and must not influence these bounds).

The entire `display_filter` (SummaryTrace + DetailedTrace conditions) is wrapped with a ±1 s
window around the DetailedTrace time range before being used in `_extract_tids_dechunked`:

```python
pass1_filter = display_filter
if min_epoch is not None and max_epoch is not None:
    pass1_filter = (f'({display_filter}) && '
                    f'frame.time_epoch >= {min_epoch - 1.0:.3f} && '
                    f'frame.time_epoch <= {max_epoch + 1.0:.3f}')
```

The same wrapping is applied in the `main()` supplementary path using `t_min`/`t_max` returned by
`build_trace_based_filter`.

---

## Debug logging

`extract_tids_from_pcap_packets` now logs the raw tshark field output per PCAP at `DEBUG` level.
`_extract_tids_dechunked` logs stage 1 file count, stage 2 packet count, and the final TID list.

Enable with `-v` / `--verbose`.

---

## File changes summary

| File | Changes |
|---|---|
| `extract-sds7-logs.py` | `process_pcap` gains `extra_tids` param; `main()` computes supplementary TIDs; `build_trace_based_filter` loses IMSI, gains TCAP msg type; `parse_detail_trace_sccp_fields` gains field 18; `build_tshark_filter` uses `tcap.otid`/`tcap.dtid`; `_extract_tids_dechunked` helper added; Pass 1 bounded by DetailedTrace time window; debug logging added |
| `debug_detail_filter.py` | `TCAP_MSG_TYPE_FILTER` gains `cont` alias; field [17] shown in debug output |
