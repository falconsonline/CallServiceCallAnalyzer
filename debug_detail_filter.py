#!/usr/bin/env python3
"""Diagnostic: print each DetailedTrace line (field4==1) for an FSMId alongside its tshark filter.

Usage:
    python3 debug_detail_filter.py -d "applogs/DetailTrace*" -i 2e277b400013022
    python3 debug_detail_filter.py -d "applogs/DetailTrace*" -i 2e277b400013022 \\
        -z "America/Mexico_City" -p "pcaps/stp*.pcap*"
"""
import argparse
import glob
import gzip
import re
import shlex
import sys
import time
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo


# Protocol → tshark opcode field name
OPCODE_FIELD = {
    'camel': 'camel.local',
    'map':   'gsm_old.localValue',
}

# TCAP message type (field[17]) → tshark presence filter
TCAP_MSG_TYPE_FILTER = {
    'begin':    'tcap.begin_element',
    'continue': 'tcap.continue_element',
    'cont':     'tcap.continue_element',
    'end':      'tcap.end_element',
    'abort':    'tcap.abort_element',
}


# ── helpers ──────────────────────────────────────────────────────────────────

def parse_timezone(tz_str):
    """Parse a timezone string into a tzinfo object.

    Accepts:
      Fixed UTC offsets: '-0500', '+0530', '-05:00', 'UTC-5', 'UTC+5:30'
      IANA names:        'America/Mexico_City', 'Europe/London', 'UTC'

    Fixed offsets are reliable when the log system's DST rules differ from the
    current IANA database (e.g. Mexico abolished DST in 2023 but the system ran CDT).
    """
    # [+-]HH:MM or [+-]HHMM
    m = re.match(r'^([+-])(\d{2}):?(\d{2})$', tz_str)
    if m:
        sign = 1 if m.group(1) == '+' else -1
        return timezone(timedelta(hours=sign * int(m.group(2)),
                                  minutes=sign * int(m.group(3))))
    # UTC[+-]H or UTC[+-]H:MM (case-insensitive)
    m = re.match(r'^UTC([+-])(\d{1,2})(?::(\d{2}))?$', tz_str, re.IGNORECASE)
    if m:
        sign = 1 if m.group(1) == '+' else -1
        return timezone(timedelta(hours=sign * int(m.group(2)),
                                  minutes=sign * int(m.group(3) or 0)))
    # IANA name
    return ZoneInfo(tz_str)


def open_file(path):
    return gzip.open(path, 'rt', errors='replace') if path.endswith('.gz') else open(path, errors='replace')


def ts_to_epoch(timestamp_str, ms_str, tz=None):
    """'DD-MM-YYYY HH:MM:SS' + ms → float epoch.

    tz: ZoneInfo instance for the log system's timezone, or None to use local system time.
    """
    try:
        dt = datetime.strptime(timestamp_str.strip(), '%d-%m-%Y %H:%M:%S')
        if tz is not None:
            dt = dt.replace(tzinfo=tz)
        ms = int(ms_str.strip()) if ms_str.strip().isdigit() else 0
        return dt.timestamp() + ms / 1000.0
    except (ValueError, AttributeError):
        return None


def is_valid_sccp_digits(s):
    """True only for all-digit strings of at least 7 characters."""
    return bool(s) and s.isdigit() and len(s) >= 7


def build_line_filter(parts, tz=None):
    """Build the tshark display filter for a single DetailedTrace line.

    Field layout (0-indexed, comma-delimited):
      [0]  timestamp    DD-MM-YYYY HH:MM:SS
      [1]  ms
      [3]  field4       must be '1' (caller's responsibility)
      [9]  protocol     camel | map | ...
      [10] opcode       numeric string
      [13] sccp_calling digits (or "NA" → skipped)
      [14] sccp_called  digits (or "NA" → skipped)
      [17] tcap_msg_type begin | continue | end | abort
    """
    timestamp     = parts[0].strip()
    ms            = parts[1].strip()
    protocol      = parts[9].strip().lower()  if len(parts) > 9  else ''
    opcode        = parts[10].strip()         if len(parts) > 10 else ''
    sccp_calling  = parts[13].strip()         if len(parts) > 13 else ''
    sccp_called   = parts[14].strip()         if len(parts) > 14 else ''
    tcap_msg_type = parts[17].strip().lower() if len(parts) > 17 else ''

    epoch = ts_to_epoch(timestamp, ms, tz)

    clauses = []

    if is_valid_sccp_digits(sccp_calling) and is_valid_sccp_digits(sccp_called):
        clauses.append(f'sccp.calling.digits == "{sccp_calling}"')
        clauses.append(f'sccp.called.digits == "{sccp_called}"')
    elif is_valid_sccp_digits(sccp_calling):
        clauses.append(f'sccp.calling.digits == "{sccp_calling}"')
    elif is_valid_sccp_digits(sccp_called):
        clauses.append(f'sccp.called.digits == "{sccp_called}"')

    opcode_field = OPCODE_FIELD.get(protocol)
    if opcode_field and opcode and opcode.isdigit():
        clauses.append(f'{opcode_field} == {opcode}')

    msg_filter = TCAP_MSG_TYPE_FILTER.get(tcap_msg_type)
    if msg_filter:
        clauses.append(msg_filter)

    if epoch is not None:
        clauses.append(f'frame.time_epoch >= {epoch - 0.2:.3f}')
        clauses.append(f'frame.time_epoch <= {epoch + 0.2:.3f}')

    if not clauses:
        return None
    if len(clauses) == 1:
        return clauses[0]
    return '(' + ' && '.join(clauses) + ')'


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Debug DetailedTrace → tshark filter per line")
    parser.add_argument('-d', '--detail',   required=True, help='Glob for DetailedTrace files')
    parser.add_argument('-i', '--id',       required=True, help='FSMId to search for')
    parser.add_argument('-p', '--pcaps',    default=None,
                        help='(optional) Glob for PCAP files — prints example tshark command')
    parser.add_argument('-z', '--timezone', default=None,
                        help='Timezone of the log system. Accepts IANA names '
                             '("America/Mexico_City") or fixed UTC offsets '
                             '("-0500", "+0530", "UTC-5"). Use a fixed offset '
                             'when the IANA database DST rules differ from the '
                             'actual system (e.g. Mexico abolished DST in 2023).')
    args = parser.parse_args()

    # Resolve timezone
    tz = None
    if args.timezone:
        try:
            tz = parse_timezone(args.timezone)
        except Exception as e:
            print(f"ERROR: invalid timezone {args.timezone!r}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        if time.timezone != 0:
            print("WARNING: --timezone not set; timestamps treated as local system time "
                  "(results will be wrong if the log system runs in a different timezone)",
                  file=sys.stderr)

    pcap_files = sorted(glob.glob(args.pcaps)) if args.pcaps else []
    target = args.id.lower()
    total = 0

    for fpath in sorted(glob.glob(args.detail)):
        with open_file(fpath) as f:
            for lineno, raw in enumerate(f, 1):
                if target not in raw.lower():
                    continue
                parts = raw.rstrip('\n').split(',')
                if len(parts) < 15:
                    print(f"[{fpath}:{lineno}] SKIP — only {len(parts)} fields (need ≥15)")
                    continue
                if parts[3].strip() != '1':
                    continue

                filt = build_line_filter(parts, tz)

                print(f"\n{'─'*80}")
                print(f"FILE   : {fpath}:{lineno}")
                print(f"LINE   : {raw.rstrip()}")
                print(f"FIELDS : [0]={parts[0].strip()!r}  [1]={parts[1].strip()!r}  "
                      f"[3]={parts[3].strip()!r}  "
                      f"[9]={parts[9].strip() if len(parts) > 9 else '?'!r}  "
                      f"[10]={parts[10].strip() if len(parts) > 10 else '?'!r}  "
                      f"[13]={parts[13].strip() if len(parts) > 13 else '?'!r}  "
                      f"[14]={parts[14].strip() if len(parts) > 14 else '?'!r}  "
                      f"[17]={parts[17].strip() if len(parts) > 17 else '?'!r}")
                if filt:
                    print(f"FILTER : {filt}")
                    if pcap_files:
                        for pcap in pcap_files[:2]:
                            cmd = ['tshark', '-r', pcap, '-t', 'ad', '-Y', filt,
                                   '-T', 'fields', '-e', 'tcap.otid', '-e', 'tcap.dtid',
                                   '-E', 'separator=\t']
                            print(f"CMD    : {shlex.join(cmd)}")
                else:
                    print("FILTER : (none — no usable SCCP digits or timestamp)")
                total += 1

    print(f"\n{'═'*80}")
    print(f"Total field4==1 lines for FSMId '{args.id}': {total}")


if __name__ == '__main__':
    main()
