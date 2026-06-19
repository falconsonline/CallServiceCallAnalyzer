import subprocess
import sys
import os
import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'extract-callservice-logs.py')


def test_m_flag_is_optional():
    """Script's -m flag should be optional (appear as [-m ...] in usage output)."""
    result = subprocess.run(
        [sys.executable, SCRIPT, '--help'],
        capture_output=True, text=True
    )
    assert '[-m' in result.stdout, (
        f"-m should be optional in usage output, got:\n{result.stdout}"
    )


from extract_callservice_logs import parse_summary_trace_fields


def _write_summary(tmp_path, lines):
    f = tmp_path / "SummaryTrace.log"
    f.write_text('\n'.join(lines) + '\n')
    return str(f)


def test_parse_summary_trace_fields_extracts_all_fields(tmp_path):
    fsmid = "2e277b400013022"
    fields = ['x'] * 21
    fields[12] = '234150123456789'   # IMSI at index 12 (field 13)
    fields[13] = '441234567890'      # calling at index 13 (field 14)
    fields[14] = '12345678'          # sccp_calling at index 14 (field 15)
    fields[15] = '87654321'          # sccp_called at index 15 (field 16)
    fields[20] = '449876543210'      # called at index 20 (field 21)
    # embed fsmid at index 0
    line = fsmid + ',' + ','.join(fields[1:])
    _write_summary(tmp_path, [line])

    result = parse_summary_trace_fields(str(tmp_path / "SummaryTrace*"), fsmid)

    assert len(result) == 1
    r = result[0]
    assert r['imsi'] == '234150123456789'
    assert r['calling_number'] == '441234567890'
    assert r['sccp_calling'] == '12345678'
    assert r['sccp_called'] == '87654321'
    assert r['called_number'] == '449876543210'


def test_parse_summary_trace_fields_skips_non_matching(tmp_path):
    fsmid = "2e277b400013022"
    fields = ['x'] * 21
    fields[12] = 'IMSI_OTHER'
    line = 'OTHER_ID,' + ','.join(fields[1:])
    _write_summary(tmp_path, [line])

    result = parse_summary_trace_fields(str(tmp_path / "SummaryTrace*"), fsmid)
    assert result == []


def test_parse_summary_trace_fields_skips_short_lines(tmp_path):
    fsmid = "abc123"
    line = fsmid + ',a,b,c'  # fewer than 21 fields
    _write_summary(tmp_path, [line])

    result = parse_summary_trace_fields(str(tmp_path / "SummaryTrace*"), fsmid)
    assert result == []


def test_parse_summary_trace_fields_skips_all_empty_fields(tmp_path):
    fsmid = "abc123"
    fields = [''] * 21
    line = fsmid + ',' + ','.join(fields[1:])
    _write_summary(tmp_path, [line])

    result = parse_summary_trace_fields(str(tmp_path / "SummaryTrace*"), fsmid)
    assert result == []  # all fields empty → no entry added


from extract_callservice_logs import parse_detail_trace_sccp_fields


def _write_detail(tmp_path, lines):
    f = tmp_path / "DetailTrace.log"
    f.write_text('\n'.join(lines) + '\n')
    return str(f)


def _make_detail_line(fsmid, field4='1', opcode='0', sccp_calling='12345678', sccp_called='87654321',
                      timestamp='27-04-2026 12:49:05', ms='123'):
    """Build a comma-delimited DetailedTrace line.

    Layout (0-indexed):
      [0]=timestamp  [1]=ms  [2]=x  [3]=field4  [4]=x  [5]=fsmid (for grep)
      [6..9]=padding  [10]=opcode  [11..12]=padding
      [13]=sccp_calling (field 14)  [14]=sccp_called (field 15)
    """
    parts = [timestamp, ms, 'x', field4, 'x', fsmid]
    parts += ['x'] * 4   # indices 6–9
    parts += [opcode]     # index 10 (field 11)
    parts += ['x'] * 2   # indices 11–12
    parts += [sccp_calling, sccp_called]  # indices 13–14
    return ','.join(parts)


def test_parse_detail_trace_sccp_fields_extracts_fields(tmp_path):
    fsmid = "2e277b400013022"
    line = _make_detail_line(fsmid, field4='1', opcode='22',
                             sccp_calling='AAAA1111', sccp_called='BBBB2222',
                             timestamp='27-04-2026 12:49:05', ms='456')
    _write_detail(tmp_path, [line])

    result = parse_detail_trace_sccp_fields(str(tmp_path / "DetailTrace*"), fsmid)

    assert len(result) == 1
    r = result[0]
    assert r['sccp_calling'] == 'AAAA1111'
    assert r['sccp_called']  == 'BBBB2222'
    assert r['opcode']       == '22'
    assert r['timestamp']    == '27-04-2026 12:49:05'
    assert r['ms']           == '456'


def test_parse_detail_trace_sccp_fields_skips_field4_not_1(tmp_path):
    fsmid = "2e277b400013022"
    line = _make_detail_line(fsmid, field4='0', sccp_calling='AAAA1111', sccp_called='BBBB2222')
    _write_detail(tmp_path, [line])

    result = parse_detail_trace_sccp_fields(str(tmp_path / "DetailTrace*"), fsmid)
    assert result == []


def test_parse_detail_trace_sccp_fields_skips_non_matching_fsmid(tmp_path):
    fsmid = "2e277b400013022"
    line = _make_detail_line('OTHER_ID', field4='1')
    _write_detail(tmp_path, [line])

    result = parse_detail_trace_sccp_fields(str(tmp_path / "DetailTrace*"), fsmid)
    assert result == []


def test_parse_detail_trace_sccp_fields_multiple_messages(tmp_path):
    fsmid = "2e277b400013022"
    lines = [
        _make_detail_line(fsmid, field4='1', sccp_calling='AAAA1111', sccp_called='BBBB2222'),
        _make_detail_line(fsmid, field4='1', sccp_calling='CCCC3333', sccp_called='DDDD4444'),
        _make_detail_line(fsmid, field4='0', sccp_calling='XXXX9999', sccp_called='YYYY8888'),
    ]
    _write_detail(tmp_path, lines)

    result = parse_detail_trace_sccp_fields(str(tmp_path / "DetailTrace*"), fsmid)
    assert len(result) == 2
    callings = {r['sccp_calling'] for r in result}
    assert callings == {'AAAA1111', 'CCCC3333'}


def test_parse_detail_trace_sccp_fields_skips_short_lines(tmp_path):
    fsmid = "abc123"
    line = fsmid + ',x,x,1,x'   # only 5 fields — too short
    _write_detail(tmp_path, [line])

    result = parse_detail_trace_sccp_fields(str(tmp_path / "DetailTrace*"), fsmid)
    assert result == []


from extract_callservice_logs import build_trace_based_filter


def test_build_filter_imsi_standalone():
    summary = [{'imsi': '234150123456789', 'calling_number': '', 'sccp_calling': '',
                'sccp_called': '', 'called_number': ''}]
    f, _, _ = build_trace_based_filter(summary, [])
    assert 'e212.imsi == "234150123456789"' in f


def test_build_filter_sccp_pair_anded():
    summary = [{'imsi': '', 'calling_number': '', 'sccp_calling': '1234567890',
                'sccp_called': '9876543210', 'called_number': ''}]
    f, _, _ = build_trace_based_filter(summary, [])
    assert '(sccp.calling.digits == "1234567890" && sccp.called.digits == "9876543210")' in f


def test_build_filter_e164_pair_anded():
    summary = [{'imsi': '', 'calling_number': '441234567890', 'sccp_calling': '',
                'sccp_called': '', 'called_number': '449876543210'}]
    f, _, _ = build_trace_based_filter(summary, [])
    assert 'e164.calling_party_number.digits == "441234567890"' in f
    assert 'e164.called_party_number.digits == "449876543210"' in f


def test_build_filter_ors_across_messages():
    detail = [
        {'timestamp': '', 'ms': '', 'protocol': '', 'opcode': '', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'},
        {'timestamp': '', 'ms': '', 'protocol': '', 'opcode': '', 'sccp_calling': '1111111111', 'sccp_called': '2222222222'},
    ]
    f, _, _ = build_trace_based_filter([], detail)
    assert ' || ' in f
    assert 'sccp.calling.digits == "1234567890"' in f
    assert 'sccp.calling.digits == "1111111111"' in f


def test_build_filter_deduplicates():
    summary = [{'imsi': '', 'calling_number': '', 'sccp_calling': '1234567890',
                'sccp_called': '9876543210', 'called_number': ''}]
    detail  = [{'timestamp': '', 'ms': '', 'protocol': '', 'opcode': '',
                'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter(summary, detail)
    assert f.count('1234567890') == 1


def test_build_filter_returns_none_when_empty():
    filter_str, min_ts, max_ts = build_trace_based_filter([], [])
    assert filter_str is None
    assert min_ts is None
    assert max_ts is None


def test_build_filter_single_sccp_calling_only():
    detail = [{'timestamp': '', 'ms': '', 'protocol': '', 'opcode': '', 'sccp_calling': '1234567890', 'sccp_called': ''}]
    f, _, _ = build_trace_based_filter([], detail)
    assert 'sccp.calling.digits == "1234567890"' in f


def test_build_filter_opcode_anded():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'map', 'opcode': '22',
               'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert 'gsm_old.localValue == 22' in f
    assert '&&' in f


def test_build_filter_camel_opcode_uses_camel_local():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'camel', 'opcode': '0',
               'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert 'camel.local == 0' in f
    assert 'gsm_old.localValue' not in f


def test_build_filter_non_numeric_opcode_ignored():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'map', 'opcode': 'connect',
               'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert 'gsm_old.localValue' not in f


def test_build_filter_time_window_included():
    detail = [{'timestamp': '27-04-2026 12:49:05', 'ms': '200', 'protocol': 'map',
               'opcode': '0', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, min_ts, max_ts = build_trace_based_filter([], detail)
    assert 'frame.time_epoch >=' in f
    assert 'frame.time_epoch <=' in f
    assert min_ts is not None
    assert max_ts is not None
    assert min_ts == max_ts  # only one entry


def test_build_filter_no_time_window_when_timestamp_empty():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'map',
               'opcode': '0', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, min_ts, max_ts = build_trace_based_filter([], detail)
    assert 'frame.time_epoch' not in f
    assert min_ts is None
    assert max_ts is None


def test_build_filter_invalid_timestamp_no_crash():
    detail = [{'timestamp': 'NOT_A_DATE', 'ms': 'bad', 'protocol': 'map',
               'opcode': '0', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert f is not None  # still produces a filter (just without time window)
    assert 'frame.time_epoch' not in f


def test_build_filter_time_window_min_max_tracked():
    detail = [
        {'timestamp': '27-04-2026 12:49:05', 'ms': '100', 'protocol': 'map',
         'opcode': '0', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'},
        {'timestamp': '27-04-2026 12:49:10', 'ms': '500', 'protocol': 'map',
         'opcode': '0', 'sccp_calling': '1234567890', 'sccp_called': '9876543210'},
    ]
    _, min_ts, max_ts = build_trace_based_filter([], detail)
    assert min_ts is not None and max_ts is not None
    assert max_ts > min_ts


def test_build_filter_invalid_sccp_digits_skipped():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'map', 'opcode': '9',
               'sccp_calling': 'NA', 'sccp_called': '59397999302'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert 'NA' not in f
    assert 'sccp.called.digits == "59397999302"' in f


def test_build_filter_short_digits_skipped():
    detail = [{'timestamp': '', 'ms': '', 'protocol': 'map', 'opcode': '7',
               'sccp_calling': '74001', 'sccp_called': '9876543210'}]
    f, _, _ = build_trace_based_filter([], detail)
    assert '74001' not in f
    assert 'sccp.called.digits == "9876543210"' in f


from unittest.mock import patch, MagicMock
from extract_callservice_logs import extract_tids_from_pcap_packets


def test_extract_tids_parses_otid_dtid(tmp_path):
    fake_pcap = str(tmp_path / "test.pcap")
    open(fake_pcap, 'w').close()

    mock_result = MagicMock()
    # tshark -T fields outputs byte sequences in colon-separated form
    mock_result.stdout = "04:2e:7f:be\tde:ad:be:ef\n\t\n"
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        tids = extract_tids_from_pcap_packets([fake_pcap], display_filter='sccp.calling.digits == "X"')

    assert '042e7fbe' in tids
    assert 'deadbeef' in tids


def test_extract_tids_lowercases():
    mock_result = MagicMock()
    mock_result.stdout = "04:2E:7F:BE\t\n"   # mixed case colon format
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        tids = extract_tids_from_pcap_packets(['fake.pcap'])

    assert '042e7fbe' in tids
    assert '042E7FBE' not in tids


def test_extract_tids_deduplicates():
    mock_result = MagicMock()
    mock_result.stdout = "04:2e:7f:be\t04:2e:7f:be\n04:2E:7F:BE\t\n"   # same TID twice
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        tids = extract_tids_from_pcap_packets(['fake.pcap'])

    assert tids.count('042e7fbe') == 1


def test_extract_tids_skips_non_8hex():
    mock_result = MagicMock()
    mock_result.stdout = "NOTAHEX\t042e7fbe\nshort\t\n"
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        tids = extract_tids_from_pcap_packets(['fake.pcap'])

    assert 'notahex' not in tids
    assert '042e7fbe' in tids


def test_extract_tids_no_filter_omits_Y():
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result) as mock_run:
        extract_tids_from_pcap_packets(['fake.pcap'])
        cmd = mock_run.call_args[0][0]
        assert '-Y' not in cmd


def test_extract_tids_with_filter_includes_Y():
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result) as mock_run:
        extract_tids_from_pcap_packets(['fake.pcap'], display_filter='e212.imsi == "123"')
        cmd = mock_run.call_args[0][0]
        assert '-Y' in cmd
        assert 'e212.imsi == "123"' in cmd


def test_extract_tids_uses_t_ad_flag():
    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result) as mock_run:
        extract_tids_from_pcap_packets(['fake.pcap'])
        cmd = mock_run.call_args[0][0]
        assert '-t' in cmd
        t_idx = cmd.index('-t')
        assert cmd[t_idx + 1] == 'ad'


def test_extract_tids_returns_sorted():
    mock_result = MagicMock()
    mock_result.stdout = "ff:ff:ff:ff\t00:00:00:00\n"
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        tids = extract_tids_from_pcap_packets(['fake.pcap'])

    assert tids == sorted(tids)


from extract_callservice_logs import process_pcap_from_traces


def _make_summary_glob(tmp_path, fsmid):
    fields = ['x'] * 21
    fields[12] = '234150123456789'
    fields[14] = '12345678'
    fields[15] = '87654321'
    line = fsmid + ',' + ','.join(fields[1:])
    f = tmp_path / "SummaryTrace.log"
    f.write_text(line + '\n')
    return str(tmp_path / "SummaryTrace*")


def _make_detail_glob_for_orch(tmp_path, fsmid):
    parts = ['27-04-2026 12:49:05', '123', 'x', '1', 'x', fsmid]
    parts += ['x'] * 4
    parts += ['22']
    parts += ['x'] * 2   # indices 11–12; sccp at 13–14
    parts += ['12345678', '87654321']
    f = tmp_path / "DetailTrace.log"
    f.write_text(','.join(parts) + '\n')
    return str(tmp_path / "DetailTrace*")


def test_process_pcap_from_traces_no_pcap_files(tmp_path):
    fsmid = "2e277b400013022"
    sglo = _make_summary_glob(tmp_path, fsmid)
    dglo = _make_detail_glob_for_orch(tmp_path, fsmid)

    process_pcap_from_traces(sglo, dglo, fsmid,
                              str(tmp_path / "*.pcap"),
                              str(tmp_path / "out.pcap"))
    assert not (tmp_path / "out.pcap").exists()


def test_process_pcap_from_traces_no_tids_found(tmp_path):
    fsmid = "2e277b400013022"
    sglo = _make_summary_glob(tmp_path, fsmid)
    dglo = _make_detail_glob_for_orch(tmp_path, fsmid)

    pcap = tmp_path / "test.pcap"
    pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x00' * 20)  # pcap magic + minimal header

    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.returncode = 0

    with patch('subprocess.run', return_value=mock_result):
        process_pcap_from_traces(sglo, dglo, fsmid,
                                  str(tmp_path / "*.pcap"),
                                  str(tmp_path / "out.pcap"))

    assert not (tmp_path / "out.pcap").exists()


def test_process_pcap_from_traces_empty_trace_fields(tmp_path):
    fsmid = "NOMATCH"
    (tmp_path / "SummaryTrace.log").write_text("OTHER_ID,x\n")
    (tmp_path / "DetailTrace.log").write_text("OTHER_ID,x\n")

    process_pcap_from_traces(
        str(tmp_path / "SummaryTrace*"),
        str(tmp_path / "DetailTrace*"),
        fsmid,
        str(tmp_path / "*.pcap"),
        str(tmp_path / "out.pcap"))

    assert not (tmp_path / "out.pcap").exists()


from extract_callservice_logs import build_tshark_filter, process_tcap_logs
import io
from extract_callservice_logs import process_main_log


def _main_line(fsmid, thread, event, content='data', ms='100', n='1'):
    """Pipe-delimited callservice log line with FSMId in field 5 (index 4)."""
    return (f"2026-04-27 12:49:05,{ms} | INFO | Logger | {thread} "
            f"| {fsmid}:{event} | {content} | Cls | m | {n}")


def _nofsmid_line(thread, content='data', ms='100', n='1'):
    """Pipe-delimited line on a thread but with no FSMId in field 5."""
    return (f"2026-04-27 12:49:05,{ms} | INFO | Logger | {thread} "
            f"| noFsmId | {content} | Cls | m | {n}")


def test_process_main_log_caps_lines_after_release(tmp_path):
    """Lines on the tracked thread more than TRAILING_AFTER_RELEASE positions after
    'Releasing state machine' must not appear in the output."""
    fsmid = "abc123def456789"
    lines = [
        _main_line(fsmid, 'Thread-1', 'Start', ms='100', n='1'),
        _main_line(fsmid, 'Thread-1', 'Release',
                   content='Releasing state machine', ms='200', n='2'),
        _nofsmid_line('Thread-1', content='cleanup1', ms='300', n='3'),   # within cap
        _nofsmid_line('Thread-1', content='cleanup2', ms='400', n='4'),   # within cap
        _nofsmid_line('Thread-1', content='cleanup3', ms='450', n='45'),  # within cap (cap=3)
        _nofsmid_line('Thread-1', content='new_call_here', ms='500', n='5'),  # BEYOND cap
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
        _main_line(fsmid, 'Thread-1', 'Start', ms='100', n='1'),
        _main_line(fsmid, 'Thread-1', 'Proceed', ms='200', n='2'),
        _nofsmid_line('Thread-1', content='trailing1', ms='300', n='3'),
        _nofsmid_line('Thread-1', content='trailing2', ms='400', n='4'),
    ]
    f = tmp_path / "callservice.log"
    f.write_text('\n'.join(lines) + '\n')

    out = io.StringIO()
    process_main_log(str(tmp_path / "callservice*"), fsmid, out)
    result = out.getvalue()

    assert 'trailing1' in result
    assert 'trailing2' in result


def _write_tcap_log(tmp_path, fsmid, dialog_id, thread_hex, direction):
    """Write a minimal TcapServer log with one complete block.

    direction='in'  -> Received from n/w ... Sending to App
    direction='out' -> Received from App ... Sending to n/w
    """
    if direction == 'in':
        start_marker = 'Received from n/w'
        end_marker   = 'Sending to App'
    else:
        start_marker = 'Received from App'
        end_marker   = 'Sending to n/w'

    def L(content):
        return f"2026-04-27 12:49:05,100 | INFO | Tcap | {thread_hex} | {dialog_id} | {content}\n"

    f = tmp_path / "TcapServer.log"
    f.write_text(
        L(start_marker) +
        L(f"StateMachineId={fsmid} Dialog[{dialog_id}]") +
        L(end_marker)
    )
    return str(tmp_path / "TcapServer*")


def test_tcapserver_sending_to_app_is_inbound(tmp_path):
    """'Sending to App' means TcapServer forwarded a network message to CallService -- inbound."""
    fsmid = "ab12cd34ef56789"
    glob  = _write_tcap_log(tmp_path, fsmid, '12345678', 'DD5FDB40', direction='in')
    out   = io.StringIO()
    _, flow_records, _ = process_tcap_logs(glob, [fsmid[:8]], out)
    non_pcap = [r for r in flow_records if r.get('source') != 'pcap']
    assert non_pcap, "Expected at least one TcapServer flow record"
    assert all(r['direction'] == 'in' for r in non_pcap), (
        f"Expected all inbound, got: {[r['direction'] for r in non_pcap]}"
    )


def test_tcapserver_sending_to_nw_is_outbound(tmp_path):
    """'Sending to n/w' means TcapServer sent an app message to the network -- outbound."""
    fsmid = "ab12cd34ef56789"
    glob  = _write_tcap_log(tmp_path, fsmid, '12345678', 'DD5FDB40', direction='out')
    out   = io.StringIO()
    _, flow_records, _ = process_tcap_logs(glob, [fsmid[:8]], out)
    non_pcap = [r for r in flow_records if r.get('source') != 'pcap']
    assert non_pcap, "Expected at least one TcapServer flow record"
    assert all(r['direction'] == 'out' for r in non_pcap), (
        f"Expected all outbound, got: {[r['direction'] for r in non_pcap]}"
    )


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


from extract_callservice_logs import _detect_our_ips


def test_detect_our_ips_rejects_remote_ip():
    """Old first-record approach adds remote IP when first PCAP record is outbound
    but first detail record is 'in'. Counter + timestamp matching must exclude it."""
    detail_records = [
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
