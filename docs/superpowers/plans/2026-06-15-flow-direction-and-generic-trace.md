# Flow Direction Fix + Generic Trace Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix HTML sequence diagram showing all arrows as inbound, cap main-log extraction at "Releasing state machine", and replace `-s`/`-d` flags with a unified `--trace` flag.

**Architecture:** All changes are in `extract-callservice-logs.py`. Bug A is a one-line fix in `process_tcap_logs`. Bug B replaces `_detect_our_ips` with a timestamp-matched per-record voting approach. The release cut-off adds a dict to PASS 1 and a list-filter in PASS 2.5. The `--trace` flag adds `_extract_trace_prefix` + `_is_summary_trace` + `_is_detail_trace` helpers, updates argparse, and rewires all `args.summary`/`args.detail` call sites.

**Tech Stack:** Python 3, pytest, argparse, existing scapy/tshark dependencies unchanged.

---

## File Structure

| File | Changes |
|---|---|
| `extract-callservice-logs.py` | Fix line 1516; replace `_detect_our_ips` (lines 1593–1629); extend PASS 1 loop (lines 371–386); update PASS 2.5 (lines 436–437); add three helpers near line 265; update argparse (lines 2721–2757); rewire ~6 call sites in `main()` |
| `tests/test_trace_pcap.py` | Fix 4 stale `build_tshark_filter` tests; add 7 new tests across the four tasks |

---

## Task 1: Fix stale build_tshark_filter tests

The implementation at line 552 generates `tcap.otid`/`tcap.dtid` but the existing tests assert `tcap.tid`. They currently fail. Fix the tests to match the implementation.

**Files:**
- Modify: `tests/test_trace_pcap.py:481-503`

- [ ] **Step 1: Verify the tests currently fail**

```bash
cd "/Users/shiju/Library/Mobile Documents/com~apple~CloudDocs/Personal/Scripts/GitHub/CallServiceCallAnalyzer"
python3 -m pytest tests/test_trace_pcap.py::test_build_tshark_filter_quotes_tids tests/test_trace_pcap.py::test_build_tshark_filter_no_bare_hex tests/test_trace_pcap.py::test_build_tshark_filter_with_time_window tests/test_trace_pcap.py::test_build_tshark_filter_no_time_window -v
```

Expected: all four FAIL (they assert `tcap.tid ==` but implementation emits `tcap.otid ==` / `tcap.dtid ==`).

- [ ] **Step 2: Replace the four stale tests**

In `tests/test_trace_pcap.py`, replace lines 481–503 with:

```python
def test_build_tshark_filter_uses_otid_dtid():
    f = build_tshark_filter(['118459e7', '042e7fbe'])
    assert 'tcap.otid == 11:84:59:e7' in f
    assert 'tcap.dtid == 11:84:59:e7' in f
    assert 'tcap.otid == 04:2e:7f:be' in f
    assert 'tcap.dtid == 04:2e:7f:be' in f


def test_build_tshark_filter_no_bare_hex():
    f = build_tshark_filter(['118459e7'])
    assert '"118459e7"' not in f
    assert 'tcap.otid == 11:84:59:e7' in f


def test_build_tshark_filter_with_time_window():
    f = build_tshark_filter(['042e7fbe'], first_ts=1777312145.0, last_ts=1777312999.0)
    assert 'tcap.otid == 04:2e:7f:be' in f
    assert 'frame.time_epoch >= 1777312144.800' in f
    assert 'frame.time_epoch <= 1777312999.200' in f


def test_build_tshark_filter_no_time_window():
    f = build_tshark_filter(['042e7fbe'])
    assert 'frame.time_epoch' not in f
    assert 'tcap.otid == 04:2e:7f:be' in f
```

- [ ] **Step 3: Run to verify they pass**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_build_tshark_filter_uses_otid_dtid tests/test_trace_pcap.py::test_build_tshark_filter_no_bare_hex tests/test_trace_pcap.py::test_build_tshark_filter_with_time_window tests/test_trace_pcap.py::test_build_tshark_filter_no_time_window -v
```

Expected: all four PASS.

- [ ] **Step 4: Run full test suite — no new failures**

```bash
python3 -m pytest tests/ -v
```

Expected: all previously-passing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_trace_pcap.py
git commit -m "fix: update build_tshark_filter tests to match otid/dtid implementation"
```

---

## Task 2: Fix TcapServer direction — Bug A

`outgoing = forwarded_to_app or sent_to_nw` at line 1516 marks blocks with "Sending to App" (inbound) as outgoing. Fix: `outgoing = sent_to_nw` only.

**Files:**
- Modify: `extract-callservice-logs.py:1516`
- Modify: `tests/test_trace_pcap.py` (add 1 test)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_trace_pcap.py` after the last import block:

```python
import io
from extract_callservice_logs import process_tcap_logs


def _make_tcap_block_log(tmp_path, fsmid, dialog_id, thread_hex, direction):
    """Write a minimal TcapServer log file with one block.

    direction='in'  → block has 'Received from n/w' + 'Sending to App'
    direction='out' → block has 'Received from App' + 'Sending to n/w'
    """
    if direction == 'in':
        marker_start = 'Received from n/w'
        marker_end   = 'Sending to App'
    else:
        marker_start = 'Received from App'
        marker_end   = 'Sending to n/w'

    # Pipe-delimited TcapServer format: ts|level|cls|thread_hex|dialog_id|...
    def _line(content):
        return f"2026-04-27 12:49:05,100 | INFO | Tcap | {thread_hex} | {dialog_id} | {content}\n"

    f = tmp_path / "TcapServer.log"
    f.write_text(
        _line(f"{fsmid} {marker_start}") +
        _line(f"StateMachineId={fsmid}") +
        _line(marker_end)
    )
    return str(tmp_path / "TcapServer*")


def test_tcapserver_sending_to_app_is_inbound(tmp_path):
    """'Sending to App' means TcapServer forwarded a network message to CallService — inbound."""
    fsmid = "ab12cd34ef56789"
    glob  = _make_tcap_block_log(tmp_path, fsmid, '12345678', 'DD5FDB40', direction='in')
    out   = io.StringIO()
    _, flow_records, _ = process_tcap_logs(glob, [fsmid[:8]], out)
    inbound = [r for r in flow_records if r.get('source') != 'pcap']
    assert inbound, "Expected at least one TcapServer flow record"
    assert all(r['direction'] == 'in' for r in inbound), (
        f"Expected all inbound, got: {[r['direction'] for r in inbound]}"
    )


def test_tcapserver_sending_to_nw_is_outbound(tmp_path):
    """'Sending to n/w' means TcapServer forwarded an app message to the network — outbound."""
    fsmid = "ab12cd34ef56789"
    glob  = _make_tcap_block_log(tmp_path, fsmid, '12345678', 'DD5FDB40', direction='out')
    out   = io.StringIO()
    _, flow_records, _ = process_tcap_logs(glob, [fsmid[:8]], out)
    outbound = [r for r in flow_records if r.get('source') != 'pcap']
    assert outbound, "Expected at least one TcapServer flow record"
    assert all(r['direction'] == 'out' for r in outbound), (
        f"Expected all outbound, got: {[r['direction'] for r in outbound]}"
    )
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_tcapserver_sending_to_app_is_inbound tests/test_trace_pcap.py::test_tcapserver_sending_to_nw_is_outbound -v
```

Expected: `test_tcapserver_sending_to_app_is_inbound` FAILS (direction is 'out' because of the bug).

Note: `test_tcapserver_sending_to_nw_is_outbound` may also fail depending on how the log blocks are parsed — both are expected to fail until the fix.

- [ ] **Step 3: Fix line 1516 in extract-callservice-logs.py**

Find:
```python
        outgoing = forwarded_to_app or sent_to_nw
```

Replace with:
```python
        outgoing = sent_to_nw
```

- [ ] **Step 4: Run to verify both pass**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_tcapserver_sending_to_app_is_inbound tests/test_trace_pcap.py::test_tcapserver_sending_to_nw_is_outbound -v
```

Expected: both PASS.

- [ ] **Step 5: Run full test suite**

```bash
python3 -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add extract-callservice-logs.py tests/test_trace_pcap.py
git commit -m "fix: TcapServer 'Sending to App' is inbound, not outgoing (Bug A)"
```

---

## Task 3: Fix _detect_our_ips — Bug B

Replace the first-record-wins approach with per-detail-record timestamp matching + IP vote counting. The old code adds both the remote IP and our IP to `our_ips` when the first PCAP record for a dialog is outbound while the first detail record says 'in', poisoning direction detection.

**Files:**
- Modify: `extract-callservice-logs.py:1593-1629` (replace `_detect_our_ips`)
- Modify: `tests/test_trace_pcap.py` (add 2 tests)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_trace_pcap.py`:

```python
from extract_callservice_logs import _detect_our_ips


def test_detect_our_ips_rejects_remote_ip():
    """Old first-record approach adds remote IP to our_ips when first PCAP record is
    outbound but first detail record is 'in'. Counter + timestamp matching must exclude it."""
    detail_records = [
        # Only one detail record for dialog D1: direction='in' at ts 10:00:02
        {'dialog_id': 'D1', 'direction': 'in', 'timestamp': '2026-01-01 10:00:02.000'},
    ]
    flow_records = [
        # First PCAP record is outbound Begin (our node sent to remote)
        {
            'source': 'pcap', 'dialog_id': 'D1',
            'timestamp': '2026-01-01 10:00:01.000',
            'pcap': {'ip_src': '10.0.0.2', 'ip_dst': '10.0.0.1', 'ts': '10:00:01.000'},
        },
        # Second PCAP record is inbound response — matches the detail record
        {
            'source': 'pcap', 'dialog_id': 'D1',
            'timestamp': '2026-01-01 10:00:02.000',
            'pcap': {'ip_src': '10.0.0.1', 'ip_dst': '10.0.0.2', 'ts': '10:00:02.000'},
        },
    ]
    our_ips = _detect_our_ips(detail_records, flow_records)
    assert '10.0.0.2' in our_ips, f"Expected 10.0.0.2 as our IP, got {our_ips}"
    assert '10.0.0.1' not in our_ips, f"Remote IP 10.0.0.1 should not be in our_ips, got {our_ips}"


def test_detect_our_ips_majority_vote_across_dialogs():
    """Votes across multiple detail records and dialogs converge on the correct IP."""
    detail_records = [
        {'dialog_id': 'D1', 'direction': 'in',  'timestamp': '2026-01-01 10:00:01.000'},
        {'dialog_id': 'D1', 'direction': 'out', 'timestamp': '2026-01-01 10:00:02.000'},
        {'dialog_id': 'D2', 'direction': 'in',  'timestamp': '2026-01-01 10:00:03.000'},
    ]
    flow_records = [
        {'source': 'pcap', 'dialog_id': 'D1', 'timestamp': '2026-01-01 10:00:01.000',
         'pcap': {'ip_src': '10.0.0.1', 'ip_dst': '10.0.0.2', 'ts': '10:00:01.000'}},
        {'source': 'pcap', 'dialog_id': 'D1', 'timestamp': '2026-01-01 10:00:02.000',
         'pcap': {'ip_src': '10.0.0.2', 'ip_dst': '10.0.0.1', 'ts': '10:00:02.000'}},
        {'source': 'pcap', 'dialog_id': 'D2', 'timestamp': '2026-01-01 10:00:03.000',
         'pcap': {'ip_src': '10.0.0.1', 'ip_dst': '10.0.0.2', 'ts': '10:00:03.000'}},
    ]
    our_ips = _detect_our_ips(detail_records, flow_records)
    assert '10.0.0.2' in our_ips
    assert '10.0.0.1' not in our_ips
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_detect_our_ips_rejects_remote_ip tests/test_trace_pcap.py::test_detect_our_ips_majority_vote_across_dialogs -v
```

Expected: `test_detect_our_ips_rejects_remote_ip` FAILS (old code adds both IPs).

- [ ] **Step 3: Replace _detect_our_ips (lines 1593–1629)**

Replace the entire function with:

```python
def _detect_our_ips(detail_records: list, flow_records: list,
                    node_ip_map: dict = None) -> set:
    """Infer our node's Sigtran IPs from DetailedTrace direction + PCAP ip fields.

    When node_ip_map is provided (from --signode), use those IPs directly.
    Otherwise, pair each DetailedTrace record to the closest-timestamp PCAP record
    in the same dialog and tally IP candidates:
      direction='in'  → ip_dst is a candidate "our IP"
      direction='out' → ip_src is a candidate "our IP"
    The IP(s) with the most votes become our_ips.
    """
    if node_ip_map:
        our_ips = set(node_ip_map.keys())
        logging.info("Using explicit our Sigtran IPs from --signode: %s", our_ips)
        return our_ips

    def _ts_sec(ts: str) -> float:
        try:
            t = ts.strip().split(' ')[-1]
            h, mi, s = t[:12].split(':')
            return int(h) * 3600 + int(mi) * 60 + float(s)
        except Exception:
            return 0.0

    pcap_by_did: dict = defaultdict(list)
    for r in flow_records:
        if r.get('source') == 'pcap':
            did = r.get('dialog_id', '')
            if did:
                pcap_by_did[did].append(r)

    ip_votes: dict = defaultdict(int)
    for r in detail_records:
        did  = r.get('dialog_id', '')
        dirn = r.get('direction', '')
        if not did or dirn not in ('in', 'out'):
            continue
        candidates = pcap_by_did.get(did, [])
        if not candidates:
            continue
        ref_sec = _ts_sec(r.get('timestamp', ''))
        best    = min(candidates,
                      key=lambda p: abs(_ts_sec(p.get('timestamp', '')) - ref_sec))
        pcap    = best.get('pcap', {})
        ip_src  = pcap.get('ip_src', '')
        ip_dst  = pcap.get('ip_dst', '')
        if dirn == 'in' and ip_dst:
            ip_votes[ip_dst] += 1
        elif dirn == 'out' and ip_src:
            ip_votes[ip_src] += 1

    if not ip_votes:
        logging.warning("Could not auto-detect our Sigtran IPs — PCAP direction may be approximate")
        return set()

    max_votes = max(ip_votes.values())
    our_ips   = {ip for ip, v in ip_votes.items() if v == max_votes}
    logging.info("Detected our Sigtran IPs: %s (votes: %s)", our_ips, dict(ip_votes))
    return our_ips
```

- [ ] **Step 4: Run to verify both tests pass**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_detect_our_ips_rejects_remote_ip tests/test_trace_pcap.py::test_detect_our_ips_majority_vote_across_dialogs -v
```

Expected: both PASS.

- [ ] **Step 5: Run full test suite**

```bash
python3 -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Syntax check**

```bash
python3 -m py_compile extract-callservice-logs.py && echo OK
```

Expected: `OK`

- [ ] **Step 7: Commit**

```bash
git add extract-callservice-logs.py tests/test_trace_pcap.py
git commit -m "fix: replace first-record-wins in _detect_our_ips with timestamp-matched vote counting (Bug B)"
```

---

## Task 4: Add "Releasing state machine" cut-off in process_main_log

After the FSMId's "Releasing state machine" line, only include at most `TRAILING_AFTER_RELEASE = 3` further no-fsmid lines on that thread. Lines beyond this cap belong to the next call on that thread.

**Files:**
- Modify: `extract-callservice-logs.py` — PASS 1 loop + constant + PASS 2.5 end
- Modify: `tests/test_trace_pcap.py` (add 2 tests)

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_trace_pcap.py`:

```python
from extract_callservice_logs import process_main_log


def _main_log_line(fsmid, thread, event, content='data', ms='100', n='1'):
    """Minimal pipe-delimited callservice log line."""
    return (f"2026-04-27 12:49:05,{ms} | INFO | Logger | {thread} "
            f"| {fsmid}:{event} | {content} | Cls | m | {n}")


def _no_fsmid_line(thread, content='data', ms='100', n='1'):
    """Pipe-delimited line with thread but no FSMId in field 5."""
    return (f"2026-04-27 12:49:05,{ms} | INFO | Logger | {thread} "
            f"| noFsmId | {content} | Cls | m | {n}")


def test_process_main_log_caps_lines_after_release(tmp_path):
    """Lines on the tracked thread more than TRAILING_AFTER_RELEASE positions after
    'Releasing state machine' must not appear in the output."""
    fsmid = "abc123def456789"
    lines = [
        _main_log_line(fsmid, 'Thread-1', 'Start', ms='100', n='1'),
        _main_log_line(fsmid, 'Thread-1', 'Release',
                       content='Releasing state machine', ms='200', n='2'),
        _no_fsmid_line('Thread-1', content='cleanup1', ms='300', n='3'),   # within cap
        _no_fsmid_line('Thread-1', content='cleanup2', ms='400', n='4'),   # within cap
        _no_fsmid_line('Thread-1', content='cleanup3', ms='450', n='45'),  # within cap (cap=3)
        _no_fsmid_line('Thread-1', content='new_call_here', ms='500', n='5'),  # BEYOND cap
    ]
    f = tmp_path / "callservice.log"
    f.write_text('\n'.join(lines) + '\n')

    out = io.StringIO()
    process_main_log(str(tmp_path / "callservice*"), fsmid, out)
    result = out.getvalue()

    assert 'cleanup1' in result
    assert 'cleanup2' in result
    assert 'cleanup3' in result
    assert 'new_call_here' not in result, (
        "Lines beyond TRAILING_AFTER_RELEASE after 'Releasing state machine' must be excluded"
    )


def test_process_main_log_no_release_line_unchanged(tmp_path):
    """When no 'Releasing state machine' line exists, trailing thread lines are still included."""
    fsmid = "abc123def456789"
    lines = [
        _main_log_line(fsmid, 'Thread-1', 'Start', ms='100', n='1'),
        _main_log_line(fsmid, 'Thread-1', 'Proceed', ms='200', n='2'),
        _no_fsmid_line('Thread-1', content='trailing1', ms='300', n='3'),
        _no_fsmid_line('Thread-1', content='trailing2', ms='400', n='4'),
    ]
    f = tmp_path / "callservice.log"
    f.write_text('\n'.join(lines) + '\n')

    out = io.StringIO()
    process_main_log(str(tmp_path / "callservice*"), fsmid, out)
    result = out.getvalue()

    assert 'trailing1' in result
    assert 'trailing2' in result
```

- [ ] **Step 2: Run to verify the first test fails**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_process_main_log_caps_lines_after_release tests/test_trace_pcap.py::test_process_main_log_no_release_line_unchanged -v
```

Expected: `test_process_main_log_caps_lines_after_release` FAILS (`new_call_here` appears in output). `test_process_main_log_no_release_line_unchanged` should PASS (no change to existing behaviour).

- [ ] **Step 3: Add TRAILING_AFTER_RELEASE constant and release_indices to PASS 1**

In `extract-callservice-logs.py`, find the line just before `for file_path in files:` in `process_main_log` (currently `MAX_LINES_IN_BLOCK = 1000`). Add the constant there:

```python
    MAX_LINES_IN_BLOCK = 1000
    BACKTRACK_LIMIT = 500
    TRAILING_AFTER_RELEASE = 3
```

Inside the existing PASS 1 loop (starting `for idx, line in enumerate(lines):`), extend the block that builds `thread_map`. The full loop body becomes:

```python
            for idx, line in enumerate(lines):
                if target_fsmid in line.lower():
                    fsmid_line_indices.append(idx)
                    thread = parse_thread(line)
                    if thread and thread not in thread_map:
                        thread_map[thread] = idx
                    if ('releasing state machine' in line.lower()
                            and thread and thread not in release_indices):
                        release_indices[thread] = idx
```

Add `release_indices = {}` just before the PASS 1 loop (alongside `fsmid_line_indices = []` and `thread_map = {}`):

```python
            # PASS 1: Identify FSMId lines and threads
            fsmid_line_indices = []
            thread_map = {}
            release_indices = {}
```

- [ ] **Step 4: Update PASS 2.5 to cap trailing lines**

Find the end of the PASS 2.5 block (currently lines 435–437):

```python
                # No-fsmid lines trailing after the last target fsmid belong to the target
                if last_was_target:
                    target_context_indices.update(pending)
```

Replace with:

```python
                # No-fsmid lines trailing after the last target fsmid belong to the target,
                # capped at TRAILING_AFTER_RELEASE lines past any "Releasing state machine" line.
                if last_was_target:
                    release_idx = release_indices.get(thread)
                    if release_idx is not None:
                        capped = [i for i in pending if i <= release_idx + TRAILING_AFTER_RELEASE]
                        target_context_indices.update(capped)
                    else:
                        target_context_indices.update(pending)
```

- [ ] **Step 5: Run to verify both tests pass**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_process_main_log_caps_lines_after_release tests/test_trace_pcap.py::test_process_main_log_no_release_line_unchanged -v
```

Expected: both PASS.

- [ ] **Step 6: Run full test suite**

```bash
python3 -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 7: Syntax check**

```bash
python3 -m py_compile extract-callservice-logs.py && echo OK
```

- [ ] **Step 8: Commit**

```bash
git add extract-callservice-logs.py tests/test_trace_pcap.py
git commit -m "feat: cap main-log thread extraction after 'Releasing state machine'"
```

---

## Task 5: Add _extract_trace_prefix helper and auto-detection functions

These three helpers drive the `--trace` flag logic. Add them near `process_simple_search` (around line 265).

**Files:**
- Modify: `extract-callservice-logs.py` (add 3 functions before `process_simple_search`)
- Modify: `tests/test_trace_pcap.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_trace_pcap.py`:

```python
from extract_callservice_logs import _extract_trace_prefix, _is_summary_trace, _is_detail_trace


def test_extract_trace_prefix_strips_date_suffix(tmp_path):
    f = tmp_path / "appfulltrace2.20260603-162248.log"
    f.write_text("line\n")
    result = _extract_trace_prefix(str(tmp_path / "appfulltrace2*"))
    assert result == "appfulltrace2"


def test_extract_trace_prefix_strips_csv_extension(tmp_path):
    f = tmp_path / "appevent.csv"
    f.write_text("line\n")
    result = _extract_trace_prefix(str(tmp_path / "appevent*"))
    assert result == "appevent"


def test_extract_trace_prefix_common_prefix_strips_trailing_digit(tmp_path):
    (tmp_path / "app-trace1.log").write_text("a\n")
    (tmp_path / "app-trace2.log").write_text("b\n")
    result = _extract_trace_prefix(str(tmp_path / "app-trace*"))
    assert result == "app-trace"


def test_extract_trace_prefix_common_prefix_mixed_separators(tmp_path):
    (tmp_path / "app-trace1.log").write_text("a\n")
    (tmp_path / "app-trace-02.log").write_text("b\n")
    result = _extract_trace_prefix(str(tmp_path / "app-trace*"))
    assert result == "app-trace"


def test_is_summary_trace_true():
    assert _is_summary_trace("applogs/SummaryTrace.20260101.log") is True
    assert _is_summary_trace("SummaryTrace*") is True


def test_is_summary_trace_false():
    assert _is_summary_trace("DetailTrace*") is False
    assert _is_summary_trace("applog*") is False


def test_is_detail_trace_true():
    assert _is_detail_trace("applogs/DetailTrace.20260101.log") is True
    assert _is_detail_trace("DetailedTrace*") is True


def test_is_detail_trace_false():
    assert _is_detail_trace("SummaryTrace*") is False
    assert _is_detail_trace("applog*") is False
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_extract_trace_prefix_strips_date_suffix tests/test_trace_pcap.py::test_is_summary_trace_true -v
```

Expected: ImportError — functions don't exist yet.

- [ ] **Step 3: Add the three helper functions to extract-callservice-logs.py**

Insert the following block just before `def process_simple_search(` (around line 265):

```python
_DATE_SUFFIX_RE = re.compile(r'[._-]\d{4}\d*.*$')
_EXT_RE         = re.compile(r'\.[a-zA-Z]+$')


def _extract_trace_prefix(glob_pattern: str) -> str:
    """Derive a section-header name from a glob pattern.

    Expands the glob, strips .gz, date/version suffixes, and file extensions
    from each matched basename, then returns the longest common prefix with
    trailing digits and separators removed.
    Falls back to pattern-based extraction when no files match.
    """
    files = sorted(glob.glob(glob_pattern))
    if not files:
        name = os.path.basename(glob_pattern.rstrip('*?'))
        if name.endswith('.gz'):
            name = name[:-3]
        name = _DATE_SUFFIX_RE.sub('', name)
        name = _EXT_RE.sub('', name)
        return re.sub(r'[-_.\d]+$', '', name) or 'trace'

    names = []
    for f in files:
        n = os.path.basename(f)
        if n.endswith('.gz'):
            n = n[:-3]
        n = _DATE_SUFFIX_RE.sub('', n)
        n = _EXT_RE.sub('', n)
        if n:
            names.append(n)

    if not names:
        return 'trace'

    prefix = os.path.commonprefix(names)
    prefix = re.sub(r'[-_.\d]+$', '', prefix)
    return prefix or names[0]


def _is_summary_trace(pattern: str) -> bool:
    """Return True if the glob pattern / path refers to a SummaryTrace file."""
    return os.path.basename(pattern).lower().startswith('summarytrace')


def _is_detail_trace(pattern: str) -> bool:
    """Return True if the glob pattern / path refers to a DetailedTrace or DetailTrace file."""
    name = os.path.basename(pattern).lower()
    return name.startswith('detailtrace') or name.startswith('detailedtrace')

```

- [ ] **Step 4: Run to verify all helper tests pass**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_extract_trace_prefix_strips_date_suffix tests/test_trace_pcap.py::test_extract_trace_prefix_strips_csv_extension tests/test_trace_pcap.py::test_extract_trace_prefix_common_prefix_strips_trailing_digit tests/test_trace_pcap.py::test_extract_trace_prefix_common_prefix_mixed_separators tests/test_trace_pcap.py::test_is_summary_trace_true tests/test_trace_pcap.py::test_is_summary_trace_false tests/test_trace_pcap.py::test_is_detail_trace_true tests/test_trace_pcap.py::test_is_detail_trace_false -v
```

Expected: all 8 PASS.

- [ ] **Step 5: Run full test suite**

```bash
python3 -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Syntax check**

```bash
python3 -m py_compile extract-callservice-logs.py && echo OK
```

- [ ] **Step 7: Commit**

```bash
git add extract-callservice-logs.py tests/test_trace_pcap.py
git commit -m "feat: add _extract_trace_prefix, _is_summary_trace, _is_detail_trace helpers"
```

---

## Task 6: Wire --trace flag into CLI and main()

Replace `-s`/`-d` with `--trace`/`-f` in argparse and rewire all call sites in `main()`.

**Files:**
- Modify: `extract-callservice-logs.py` — argparse block + `main()` body
- Modify: `tests/test_trace_pcap.py` (update 1 existing test, add 2 new)

- [ ] **Step 1: Write the failing tests**

The existing test `test_m_flag_is_optional` checks `[-m` in `--help` output. Add:

```python
def test_trace_flag_in_help():
    result = subprocess.run(
        [sys.executable, SCRIPT, '--help'],
        capture_output=True, text=True
    )
    assert '--trace' in result.stdout or '-f' in result.stdout, (
        f"--trace/-f should appear in help, got:\n{result.stdout}"
    )
    # -s and -d should NOT appear in help (they are hidden aliases)
    assert '-s ' not in result.stdout, "-s should be hidden from help"
    assert '-d ' not in result.stdout, "-d should be hidden from help"


def test_trace_requires_at_least_one():
    result = subprocess.run(
        [sys.executable, SCRIPT, '-i', 'abc123'],
        capture_output=True, text=True
    )
    assert result.returncode != 0, "Should fail when no --trace or -s/-d given"
```

- [ ] **Step 2: Run to verify they fail**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_trace_flag_in_help tests/test_trace_pcap.py::test_trace_requires_at_least_one -v
```

Expected: both FAIL (current code has `-s`/`-d` not `--trace`, and requires `-s`/`-d` not checked the same way).

- [ ] **Step 3: Update argparse in extract-callservice-logs.py**

Find the argparse block in `main()` starting around line 2711. Replace the `-s`/`-d` argument definitions and update the epilog:

**Remove these two lines:**
```python
    parser.add_argument("-s", "--summary",  required=True,
                        help="[MANDATORY] Glob pattern for SummaryTrace file(s)")
    parser.add_argument("-d", "--detail",   required=True,
                        help="[MANDATORY] Glob pattern for DetailedTrace file(s)")
```

**Replace with:**
```python
    parser.add_argument("-f", "--trace", action="append", dest="trace", default=None,
                        metavar="GLOB",
                        help="[MANDATORY, repeatable] Glob pattern for a trace file group. "
                             "Files named SummaryTrace* and DetailTrace*/DetailedTrace* are "
                             "automatically used for PCAP correlation and HTML diagram. "
                             "Each pattern produces a separate output section whose header "
                             "is derived from the file prefix (date/version suffix stripped). "
                             "Example: --trace 'applogs/SummaryTrace*' "
                             "--trace 'applogs/DetailTrace*' --trace 'applogs/applog*'")
    # Deprecated aliases — kept for backward compat, hidden from --help
    parser.add_argument("-s", "--summary", action="append", dest="trace",
                        help=argparse.SUPPRESS)
    parser.add_argument("-d", "--detail",  action="append", dest="trace",
                        help=argparse.SUPPRESS)
```

**Update the epilog** (replace the current one):
```python
        epilog=(
            "MANDATORY arguments:  -f/--trace (at least one), -i\n"
            "CONDITIONAL mandatory:\n"
            "  -z  required when -p is given (PCAP timestamp window needs explicit timezone)\n"
            "  -t  required when --html is given\n"
            "Backward compat: -s <glob> and -d <glob> are accepted as aliases for --trace.\n"
        ),
```

- [ ] **Step 4: Add trace validation and derive summary/detail globs in main()**

After `args = parser.parse_args()`, find the existing `-p`/`-z` validation block. Add trace validation immediately before it:

```python
    if not args.trace:
        print(
            "\nERROR: at least one -f/--trace argument is required.\n"
            "Example: --trace 'applogs/SummaryTrace*' --trace 'applogs/DetailTrace*'\n",
            file=sys.stderr)
        sys.exit(1)

    # Derive summary/detail globs for PCAP correlation (first matching pattern wins)
    _summary_patterns = [p for p in args.trace if _is_summary_trace(p)]
    _detail_patterns  = [p for p in args.trace if _is_detail_trace(p)]
    _summary_glob     = _summary_patterns[0] if _summary_patterns else None
    _detail_glob      = _detail_patterns[0]  if _detail_patterns  else None
```

- [ ] **Step 5: Replace process_simple_search call sites in main()**

Find:
```python
            process_simple_search(args.summary, args.id, "SummaryTrace", out_file)
            process_simple_search(args.detail, args.id, "DetailedTrace", out_file)
```

Replace with:
```python
            for _pattern in args.trace:
                _header = _extract_trace_prefix(_pattern)
                process_simple_search(_pattern, args.id, _header, out_file)
```

- [ ] **Step 6: Replace args.detail reference for detail_records_for_html**

Find:
```python
        if args.detail:
            detail_records_for_html = parse_detail_trace_records(
                args.detail, args.id)
            logging.info("DetailedTrace: %d in/out records",
                         len(detail_records_for_html))
```

Replace with:
```python
        if _detail_glob:
            detail_records_for_html = parse_detail_trace_records(
                _detail_glob, args.id)
            logging.info("DetailedTrace: %d in/out records",
                         len(detail_records_for_html))
```

- [ ] **Step 7: Replace args.summary / args.detail in PCAP correlation block**

Find this block (inside `if args.pcaps:` → `if args.main:`):
```python
                summary_fields = parse_summary_trace_fields(args.summary, args.id)
                detail_sccp    = parse_detail_trace_sccp_fields(args.detail, args.id)
```

Replace with:
```python
                summary_fields = (parse_summary_trace_fields(_summary_glob, args.id)
                                  if _summary_glob else [])
                detail_sccp    = (parse_detail_trace_sccp_fields(_detail_glob, args.id)
                                  if _detail_glob else [])
```

Also find the `process_pcap_from_traces` call in the `else` branch (when `-m` is not given):
```python
            process_pcap_from_traces(args.summary, args.detail, args.id, ...)
```

Replace with:
```python
            process_pcap_from_traces(_summary_glob or '', _detail_glob or '', args.id, ...)
```

- [ ] **Step 8: Syntax check**

```bash
python3 -m py_compile extract-callservice-logs.py && echo OK
```

Expected: `OK`

- [ ] **Step 9: Run the new CLI tests**

```bash
python3 -m pytest tests/test_trace_pcap.py::test_trace_flag_in_help tests/test_trace_pcap.py::test_trace_requires_at_least_one -v
```

Expected: both PASS.

- [ ] **Step 10: Run full test suite**

```bash
python3 -m pytest tests/ -v
```

Expected: all tests pass (including the existing `test_m_flag_is_optional`).

- [ ] **Step 11: Smoke-test --help output manually**

```bash
python3 extract-callservice-logs.py --help
```

Verify:
- `--trace` / `-f` appears in usage and options
- `-s`, `-d` do **not** appear
- `MANDATORY arguments` line lists `-f/--trace`

- [ ] **Step 12: Smoke-test backward compat**

```bash
python3 extract-callservice-logs.py -s "applogs/SummaryTrace*" -d "applogs/DetailTrace*" -i dummy 2>&1 | head -5
```

Expected: does not crash with "unrecognized arguments" (may fail on missing files — that's fine).

- [ ] **Step 13: Commit**

```bash
git add extract-callservice-logs.py tests/test_trace_pcap.py
git commit -m "feat: replace -s/-d with repeatable --trace/-f flag; auto-detect SummaryTrace/DetailTrace by name"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Bug A — `outgoing = sent_to_nw` fix → Task 2
- [x] Bug B — counter-based `_detect_our_ips` → Task 3
- [x] "Releasing state machine" cut-off → Task 4 (`TRAILING_AFTER_RELEASE=3`, `release_indices` in PASS 1, cap in PASS 2.5)
- [x] `--trace`/`-f` flag replacing `-s`/`-d` → Tasks 5–6
- [x] Prefix extraction (`_extract_trace_prefix`) → Task 5
- [x] Auto-detect SummaryTrace/DetailedTrace by filename → Task 5 + 6
- [x] `-s`/`-d` hidden deprecated aliases → Task 6 Step 3
- [x] Section header from extracted prefix → Task 6 Step 5
- [x] Output ordering matches argument order → Task 6 Step 5 (iterates `args.trace` in order)

**Placeholder scan:** None found.

**Type consistency:**
- `_extract_trace_prefix(pattern: str) -> str` used in Task 6 Step 5 — matches Task 5 Step 3 definition ✓
- `_is_summary_trace(pattern: str) -> bool` / `_is_detail_trace(pattern: str) -> bool` — used in Task 6 Step 4, defined in Task 5 Step 3 ✓
- `release_indices` added to PASS 1 in Task 4 Step 3, read in PASS 2.5 in Task 4 Step 4 ✓
- `_summary_glob` / `_detail_glob` derived in Task 6 Step 4, consumed in Steps 6–7 ✓
