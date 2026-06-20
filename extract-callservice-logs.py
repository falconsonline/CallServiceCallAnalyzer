# DEPRECATED — use extract-sds7-logs.py instead.
# This script is no longer maintained. extract-sds7-logs.py is the current
# version with the same CLI flags plus support for iCampaign, WSMS, and
# trace-based PCAP extraction without a main log.

import argparse
import glob
import gzip
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from scapy.all import PcapReader, PcapWriter, SCTP, SCTPChunkData, NoPayload, IP

import hexlog2pcap

THREAD_RE = re.compile(r"\b(Thread-\d+|Rule Executor \d+)\b")
KEYWORD_RE = re.compile(r"\b(decoded|incoming|outgoing)\b", re.IGNORECASE)
ASN1_END_RE = re.compile(r"asnlogger\|log\|", re.IGNORECASE)

# Match TID values in all three formats found in call service logs:
#   otid = 042e7fbe          (ASN.1 dump)
#   Incoming otid [042E7FBE] (thread log)
#   map_otid=042e7fbe        (rule log)
TID_RE = re.compile(r'(?:otid|dtid)\s*[=\[]\s*([0-9a-fA-F]{8})', re.IGNORECASE)

# TcapServer-specific patterns
_TCAP_NW_RE      = re.compile(r'Received from n/w', re.IGNORECASE)
_TCAP_APP_RE     = re.compile(r'Received from App', re.IGNORECASE)
_TCAP_READY_RE   = re.compile(r'ProcessMessage RWTcap Decode Successful', re.IGNORECASE)
_TCAP_SEND_NW_RE = re.compile(r'Sending (?:Message to network|to n/w)', re.IGNORECASE)
_TCAP_SEND_APP_RE= re.compile(r'Sending (?:Message to App|to App)', re.IGNORECASE)
_TCAP_HEX_RE     = re.compile(r'^[\s0-9a-fA-F]+$')
_TCAP_DIALOG_RE  = re.compile(r'Dialog\s*\[(\d+)')
_TCAP_THREAD_ID_RE  = re.compile(r'^[0-9A-Fa-f]{8}$')
_TCAP_BRACKET_TID_RE = re.compile(r'\[([0-9A-Fa-f]{8})[\]:]')
_TCAP_APP_NAME_RE= re.compile(r'application id:\s*([0-9A-Fa-f]+)\s*\(name:\s*([^)]+)\)')
_TCAP_TS_RE      = re.compile(r'(\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)')
_TCAP_INSTANCE_RE = re.compile(r'[Tt]cap[Ss]erver-(\w+)', re.IGNORECASE)
_CS_INSTANCE_RE   = re.compile(r'instance:#([^#]+)#')

# ── CAMEL operation code → human name ───────────────────────────────────────
CAMEL_OP_MAP: dict = {
    0: 'initialDP', 4: 'establishTemporaryConnection',
    14: 'disconnectForwardConnection', 16: 'applyCharging',
    17: 'applyChargingReport', 18: 'callGap',
    19: 'callInformationReport', 20: 'callInformationRequest',
    21: 'cancel', 22: 'connect', 23: 'requestReportBCSMEvent',
    24: 'eventReportBCSM', 25: 'continue', 26: 'releaseCall',
    27: 'resetTimer', 28: 'furnishChargingInformation',
    29: 'specializedResourceReport', 30: 'playAnnouncement',
    31: 'promptAndCollectUserInformation', 35: 'disconnectLeg',
    36: 'moveLeg', 37: 'splitLeg',
}

# ── GSM MAP operation code → human name ────────────────────────────────────
MAP_OP_MAP: dict = {
    2: 'updateLocation', 3: 'cancelLocation', 6: 'sendIdentification',
    7: 'insertSubscriberData', 8: 'deleteSubscriberData',
    9: 'sendParameters', 10: 'registerSS', 11: 'eraseSS',
    12: 'activateSS', 13: 'deactivateSS', 14: 'interrogateSS',
    17: 'processUnstructuredSS', 19: 'unstructuredSS',
    22: 'sendRoutingInfo', 23: 'updateGprsLocation',
    24: 'sendRoutingInfoForGprs', 29: 'provideRoamingNumber',
    38: 'prepareHandover', 40: 'sendEndSignal',
    41: 'processAccessSignalling', 43: 'forwardAccessSignalling',
    46: 'sendAuthenticationInfo', 47: 'restoreData', 48: 'sendIMSI',
    50: 'provideSubscriberInfo', 55: 'anyTimeInterrogation',
    71: 'sendRoutingInfoForSM', 72: 'mForwardSM',
    73: 'reportSMDeliveryStatus', 77: 'alertServiceCentre',
}

# ── TCAP message type integer → label ───────────────────────────────────────
TCAP_MSGTYPE_MAP: dict = {
    1: 'UNI', 2: 'Begin', 3: 'End', 4: 'Continue', 7: 'Abort',
}

# ── CAMEL BCSM event type map ────────────────────────────────────────────────
BCASM_EVENT_MAP: dict = {
    1: 'origAttemptAuthorized', 2: 'collectedInfo', 3: 'analyzedInformation',
    4: 'routeSelectFailure', 5: 'oCalledPartyBusy', 6: 'oNoAnswer',
    7: 'oAnswer', 8: 'oMidCall', 9: 'oDisconnect', 10: 'oAbandon',
    12: 'termAttemptAuthorized', 13: 'tBusy', 14: 'tNoAnswer',
    15: 'tAnswer', 16: 'tMidCall', 17: 'tDisconnect', 18: 'tAbandon',
}

# ── CAMEL monitor mode map ───────────────────────────────────────────────────
MONITOR_MODE_MAP: dict = {
    0: 'interrupted',
    1: 'notifyAndContinue',
    2: 'transparent',
}

# ── CallService log patterns for subscriber numbers ─────────────────────────
_CS_CALL_RE      = re.compile(r'Received call from \[([^\]]+)\] to \[([^\]]+)\]')
_CS_CALL_IMSI_RE = re.compile(
    r'Received call from \[([^\]]+)\] to \[([^\]]+)\] with IMSI \[([^\]]*)\]')
_CS_DNIS_RE      = re.compile(
    r'Created DNISCallsMap entry for imsi\[([^\]]*)\],'
    r'\s*busy\[([^\]]*)\],\s*NoReply\[([^\]]*)\],\s*NotReachable\[([^\]]*)\]')
_CS_CONNECT_RE   = re.compile(r'(?:SENDING CONNECT,\s*ON|Sending Connect on MSRN)=(\S+)')


def _sanitize_label(text: str) -> str:
    """Escape characters that break mermaid arrow labels.

    Uses Armenian full stop (U+0589) as a colon substitute — visually
    identical but safe inside mermaid label strings.
    """
    return (text
            .replace('"', "'")
            .replace(':', '։')
            .replace('{', '(')
            .replace('}', ')'))


def _decode_int(val: str, base: int = 10):
    """Return int from val or None if blank / unparseable."""
    v = val.strip() if val else ''
    if not v:
        return None
    try:
        return int(v, base)
    except ValueError:
        return None


# ── Hex-decode helpers for CAMEL/MAP application parameters ─────────────────
_RRBCSM_BCSM_RE = re.compile(r'(?i)8001([0-9a-f]{2})8101')  # RRBCSM eventTypeBCSM
_MAP_MSISDN_RE  = re.compile(r'(?i)8107([0-9a-f]{14})')      # MSISDN 7-byte GT
_MAP_FTN_RE     = re.compile(r'(?i)8507([0-9a-f]{14})')      # ForwardedToNumber GT


def _decode_bcd_gt(hex_7bytes: str) -> str:
    """Decode a BCD-packed GT address from hex, skipping the leading TOA byte."""
    digits = []
    for i in range(2, len(hex_7bytes), 2):
        try:
            b = int(hex_7bytes[i:i + 2], 16)
        except ValueError:
            break
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        if lo <= 9:
            digits.append(str(lo))
        if hi <= 9:   # 0xF nibble = filler → stop
            digits.append(str(hi))
        else:
            break
    return ''.join(digits)


def _find_bcsm_types_in_hex(hex_str: str) -> list:
    """Return list of distinct BCSM event type ints from a CAMEL RRBCSM payload."""
    seen: set = set()
    result: list = []
    for m in _RRBCSM_BCSM_RE.finditer(hex_str):
        v = int(m.group(1), 16)
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _find_msisdn_from_hex(hex_str: str) -> str:
    """Decode subscriber MSISDN from a MAP SendParameters response hex payload."""
    m = _MAP_MSISDN_RE.search(hex_str)
    return _decode_bcd_gt(m.group(1)) if m else ''


def _find_ftns_from_hex(hex_str: str) -> list:
    """Decode all ForwardedToNumber GT addresses from a MAP ISD hex payload."""
    seen: set = set()
    result: list = []
    for m in _MAP_FTN_RE.finditer(hex_str):
        n = _decode_bcd_gt(m.group(1))
        if n and n not in seen:
            seen.add(n)
            result.append(n)
    return result


def _get_tool(name):
    found = shutil.which(name)
    if found:
        return found
    for p in ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"]:
        exe = os.path.join(p, name)
        if os.path.isfile(exe):
            return exe
    return name


TSHARK_CMD   = _get_tool("tshark")
MERGECAP_CMD = _get_tool("mergecap")


def _tid_to_colon(raw: str) -> str:
    """Normalise an 8-char hex TID to colon-separated form: 'aabbccdd' → 'aa:bb:cc:dd'."""
    h = re.sub(r'[^0-9a-fA-F]', '', raw)
    if len(h) == 8:
        return ':'.join(h[i:i+2] for i in range(0, 8, 2))
    return raw


def _tcap_thread_id(line):
    """Extract TcapServer thread ID from field[3] of pipe-delimited log (8 hex chars)."""
    parts = line.split('|')
    if len(parts) >= 4:
        tid = parts[3].strip()
        if _TCAP_THREAD_ID_RE.match(tid):
            return tid.upper()
    return None


def setup_logging(debug_mode, log_dir):
    """Setup logging with file and console output."""
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
    except (IOError, OSError) as e:
        print(f"Failed to create log directory {log_dir}: {e}", file=sys.stderr)
        raise

    log_path = os.path.join(log_dir, "execution_debug.log")

    # Rotate existing log if it belongs to a previous day
    if os.path.exists(log_path):
        mtime = datetime.fromtimestamp(os.path.getmtime(log_path))
        if mtime.date() < datetime.now().date():
            rotated = os.path.join(
                log_dir,
                f"execution_debug.{mtime.strftime('%Y%m%d-%H%M%S')}.log"
            )
            os.rename(log_path, rotated)

    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    try:
        logging.basicConfig(
            level=logging.DEBUG if debug_mode else logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.FileHandler(log_path), logging.StreamHandler(sys.stdout) if debug_mode else logging.NullHandler()]
        )
    except (IOError, OSError) as e:
        print(f"Failed to setup log file {log_path}: {e}", file=sys.stderr)
        raise


def hex_to_dec(hex_str):
    try:
        return str(int(hex_str, 16))
    except ValueError:
        return None


def get_files(pattern):
    return sorted(glob.glob(pattern))


def open_file(file_path):
    if file_path.endswith('.gz'):
        return gzip.open(file_path, 'rt', errors='ignore')
    return open(file_path, 'r', errors='ignore')


def parse_thread(line):
    """Extract thread name from line and normalize to lowercase for consistent matching."""
    match = THREAD_RE.search(line)
    return match.group(1).lower() if match else None


def line_fsmid(line):
    """Extract fsmid from field 5 (before first ':') of a standard '|'-delimited log line."""
    parts = line.split('|')
    if len(parts) < 5:
        return None
    colon_idx = parts[4].find(':')
    if colon_idx <= 0:
        return None
    return parts[4][:colon_idx].strip().lower()


def is_asn1_start(line, target_fsmid, known_threads):
    """Check if line starts an ASN.1 block (must have keyword, brace, and context)."""
    if not KEYWORD_RE.search(line):
        return False
    if "{" not in line:
        return False
    lower = line.lower()
    if target_fsmid in lower:
        return True
    current_thread = parse_thread(line)
    if current_thread and current_thread in known_threads:
        return True
    return False


def is_asn1_end(line):
    """Check if line ends an ASN.1 block (AsnLogger marker or closing brace marker)."""
    if ASN1_END_RE.search(line):
        return True
    if "}|" in line and ("com.roamware" in line or "AsnLogger" in line):
        return True
    return False


def count_braces(line):
    """Count net braces: +1 for {, -1 for }."""
    return line.count("{") - line.count("}")


def is_log_entry_end(line):
    """Return True if line terminates a log entry (ends with |class|method|linenum)."""
    stripped = line.rstrip('\n\r')
    if '|' not in stripped:
        return False
    return stripped.split('|')[-1].strip().isdigit()


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

    if len(names) == 1:
        # Single file: strip only trailing non-alphanumeric separators, not digits
        return re.sub(r'[-_.]+$', '', names[0]) or names[0]

    prefix = os.path.commonprefix(names)
    prefix = re.sub(r'[-_.\d]+$', '', prefix)
    return prefix or names[0]


def _is_summary_trace(pattern: str) -> bool:
    """Return True if the glob pattern / path refers to a SummaryTrace file."""
    name = os.path.basename(pattern).lower()
    return name.startswith('summarytrace') or name.startswith('summary-')


def _is_detail_trace(pattern: str) -> bool:
    """Return True if the glob pattern / path refers to a DetailedTrace or DetailTrace file."""
    name = os.path.basename(pattern).lower()
    return (name.startswith('detailtrace') or name.startswith('detailedtrace')
            or name.startswith('detailed-'))


def discover_correlated_fsmids(main_glob, primary_fsmid,
                               summary_patterns, detail_glob):
    """Find forwarded-leg FSMIds via DNISCallsMap (busy/NoReply/NotReachable FTNs).

    Returns:
        correlated : list of str  — secondary FSMIds (may be empty)
        meta       : dict with keys a_number, b_number, imsi, busy, no_reply,
                     not_reachable, fwd_fsmids {fsmid: (ftn, reason)}
    """
    meta = {
        'a_number': '', 'b_number': '', 'imsi': '',
        'busy': '', 'no_reply': '', 'not_reachable': '',
        'fwd_fsmids': {},
        'cleanup_fsmids': [],
    }
    if not (main_glob and summary_patterns and detail_glob):
        return [], meta

    primary_lower = primary_fsmid.lower()

    # ── Step 1a: extract A#, IMSI from "Received call from" line for primary FSMId ──
    # These lines carry "FSMId: message" format in field 5.
    for fpath in get_files(main_glob):
        try:
            with open_file(fpath) as f:
                for line in f:
                    if primary_lower not in line.lower():
                        continue
                    if line_fsmid(line) != primary_lower:
                        continue
                    parts = line.split('|')
                    msg = parts[4][parts[4].find(':')+1:].strip() if len(parts) >= 5 else ''
                    m = _CS_CALL_IMSI_RE.search(msg)
                    if m:
                        meta['a_number'] = m.group(1).strip()
                        meta['b_number'] = m.group(2).strip()
                        meta['imsi']     = m.group(3).strip()
                        break
        except (IOError, OSError):
            continue
        if meta['a_number']:
            break

    # ── Step 1b: find DNISCallsMap entry by IMSI (not tagged with FSMId prefix) ──
    if meta['imsi']:
        for fpath in get_files(main_glob):
            try:
                with open_file(fpath) as f:
                    for line in f:
                        m2 = _CS_DNIS_RE.search(line)
                        if m2 and m2.group(1).strip() == meta['imsi']:
                            meta['busy']          = m2.group(2).strip()
                            meta['no_reply']      = m2.group(3).strip()
                            meta['not_reachable'] = m2.group(4).strip()
                            break
            except (IOError, OSError):
                continue
            if meta['busy']:
                break

    if not meta['a_number'] or not meta['busy']:
        return [], meta

    ftn_reasons = {ftn: reason
                   for ftn, reason in [
                       (meta['busy'],          'busy'),
                       (meta['no_reply'],       'no_reply'),
                       (meta['not_reachable'],  'not_reachable'),
                   ] if ftn}
    logging.info("Correlation search: A#=%s IMSI=%s busy=%s noreply=%s notreachable=%s",
                 meta['a_number'], meta['imsi'],
                 meta['busy'], meta['no_reply'], meta['not_reachable'])

    # ── Step 2: determine DetailedTrace time range for primary FSMId ──────────
    start_ts_f = end_ts_f = None
    detail_pats = detail_glob if isinstance(detail_glob, list) else [detail_glob]
    for dpat in detail_pats:
        for fpath in get_files(dpat):
            try:
                with open_file(fpath) as f:
                    for line in f:
                        if primary_lower not in line.lower():
                            continue
                        pts = line.rstrip('\n').split(',')
                        if len(pts) < 2:
                            continue
                        try:
                            _, tp = pts[0].strip().split(' ', 1)
                            hh, mm, ss = tp.split(':')
                            ts_f = int(hh)*3600 + int(mm)*60 + int(ss) + int(pts[1].strip())/1000.0
                        except (ValueError, IndexError):
                            continue
                        if start_ts_f is None:
                            start_ts_f = ts_f
                        end_ts_f = ts_f
            except (IOError, OSError):
                continue

    if start_ts_f is None:
        logging.info("Correlation search: no DetailedTrace entries for primary FSMId; skipping")
        return [], meta

    logging.info("Correlation search: DetailedTrace window %.3f – %.3f s from midnight",
                 start_ts_f, end_ts_f)

    # ── Step 3: scan SummaryTrace for matching secondary FSMId(s) ─────────────
    correlated: list = []
    seen = {primary_lower}
    spats = summary_patterns if isinstance(summary_patterns, list) else [summary_patterns]
    for spat in spats:
        for fpath in get_files(spat):
            try:
                with open_file(fpath) as f:
                    for line in f:
                        pts = line.rstrip('\n').split(',')
                        if len(pts) < 21:
                            continue
                        try:
                            _, tp = pts[0].strip().split(' ', 1)
                            hh, mm, ss = tp.split(':')
                            ts_f = (int(hh)*3600 + int(mm)*60 + int(ss)
                                    + int(pts[1].strip())/1000.0)
                        except (ValueError, IndexError):
                            continue
                        if ts_f < start_ts_f or ts_f > end_ts_f:
                            continue
                        a_f   = pts[13].strip() if len(pts) > 13 else ''
                        b_f   = pts[20].strip() if len(pts) > 20 else ''
                        cfsmid = pts[5].strip()  if len(pts) > 5  else ''
                        if (a_f == meta['a_number'] and b_f in ftn_reasons
                                and cfsmid.lower() not in seen):
                            seen.add(cfsmid.lower())
                            correlated.append(cfsmid)
                            meta['fwd_fsmids'][cfsmid] = (b_f, ftn_reasons[b_f])
                            reason = ftn_reasons[b_f]
                            logging.info("[*] Correlated FSMId: %s  A#=%s FTN=%s reason=%s",
                                         cfsmid, meta['a_number'], b_f, reason)
                            print(f"[*] Correlated FSMId found: {cfsmid}  "
                                  f"(A#={meta['a_number']} → FTN {b_f} [{reason}])")
            except (IOError, OSError) as e:
                logging.warning("SummaryTrace scan error %s: %s", fpath, e)

    # ── Step 4: scan callservice log for cleanup FSMId (RESTORE-ISD-SENT-FROM-CLEANUPRULE) ──
    # These are ISD restore operations triggered when the VMCC call ends; logged within
    # the same second as the primary FSMId's StateMachineClosed event.
    ts_lo = start_ts_f - 5.0
    ts_hi = end_ts_f   + 5.0
    for fpath in get_files(main_glob):
        try:
            with open_file(fpath) as f:
                for line in f:
                    if 'RESTORE-ISD-SENT-FROM-CLEANUPRULE' not in line:
                        continue
                    parts4 = line.split('|', 3)
                    if len(parts4) < 2:
                        continue
                    try:
                        hh, mm, ss_ms = parts4[1].strip().split(':', 2)
                        ts_f = int(hh)*3600 + int(mm)*60 + float(ss_ms)
                    except (ValueError, IndexError):
                        continue
                    if not (ts_lo <= ts_f <= ts_hi):
                        continue
                    cln_id = line_fsmid(line)
                    if cln_id and cln_id not in seen:
                        seen.add(cln_id)
                        meta['cleanup_fsmids'].append(cln_id)
                        logging.info("[*] Cleanup FSMId: %s (RESTORE-ISD-SENT-FROM-CLEANUPRULE)",
                                     cln_id)
                        print(f"[*] Cleanup FSMId found:  {cln_id}  "
                              f"(RESTORE-ISD-SENT-FROM-CLEANUPRULE, within 5s of primary)")
        except (IOError, OSError) as e:
            logging.warning("Cleanup scan error %s: %s", fpath, e)

    return correlated, meta


def process_simple_search(file_pattern, fsmid, section_name, out_handle):
    """Search for FSMId in files (case-insensitive)."""
    out_handle.write(f"{'='*20} SECTION: {section_name} {'='*20}\n")
    target_lower = fsmid.lower()
    files = get_files(file_pattern)
    if not files:
        print(f"{section_name}: no files found for pattern: {file_pattern}")
    for file_path in files:
        print(f"{section_name}: searching {file_path}")
        try:
            with open_file(file_path) as f:
                for line in f:
                    if target_lower in line.lower():
                        out_handle.write(line)
        except (IOError, OSError) as e:
            logging.error("Failed to read %s: %s", file_path, e)
        except Exception as e:
            logging.error("Unexpected error reading %s: %s", file_path, e)
    out_handle.write("\n\n")


def parse_detail_trace_records(file_pattern: str, fsmid: str) -> list:
    """Parse DetailedTrace log lines for fsmid into structured records.

    Two-pass: first collect ALL events (not just in/out), then build one dict
    per in/out TCAP line enriched with parameter context from nearby auxiliary
    events (ReceivedCallTrigger, ReceivedERB, ActionComplete ConnectTo, etc.).
    """
    target_lower = fsmid.lower()
    all_events: list = []   # (ts_sec_float, ts_str, event_name, parts_list, direction)

    def _p(parts: list, idx: int) -> str:
        return parts[idx].strip() if len(parts) > idx else ''

    def _ts_sec(ts_base: str, ms_str: str) -> float:
        try:
            _, time_part = ts_base.split(' ', 1)
            hh, mm, ss  = time_part.split(':')
            return int(hh) * 3600 + int(mm) * 60 + int(ss) + int(ms_str) / 1000.0
        except (ValueError, IndexError):
            return 0.0

    for file_path in get_files(file_pattern):
        try:
            with open_file(file_path) as f:
                for line in f:
                    if target_lower not in line.lower():
                        continue
                    parts = line.rstrip('\n').split(',')
                    if len(parts) < 6:
                        continue
                    ts_base = _p(parts, 0)
                    ms      = _p(parts, 1)
                    ev_name = _p(parts, 5)
                    dirn    = _p(parts, 8)
                    try:
                        dt_part, time_part = ts_base.split(' ', 1)
                        d, mo, y = dt_part.split('-')
                        ts_str = f"{y}-{mo}-{d} {time_part}.{ms}"
                    except ValueError:
                        ts_str = f"{ts_base}.{ms}"
                    all_events.append((_ts_sec(ts_base, ms), ts_str, ev_name, parts, dirn))
        except (IOError, OSError) as e:
            logging.warning("DetailedTrace parse error %s: %s", file_path, e)

    records: list = []
    for ev_idx, (ts_f, ts_str, ev_name, parts, dirn) in enumerate(all_events):
        if dirn not in ('in', 'out'):
            continue
        ev_lo = ev_name.lower()
        rec = {
            'source':        'detail',
            'fsmid':         fsmid,
            'timestamp':     ts_str,
            'direction':     dirn,
            'protocol':      _p(parts, 9),
            'opcode':        _p(parts, 10),
            'dialog_id':     _p(parts, 11),
            'cgpa':          _p(parts, 13),
            'cdpa':          _p(parts, 14),
            'tcap_msg_type': _p(parts, 17),
            'comp_type':     _p(parts, 20),
            'hex_payload':   _p(parts, 25),
            'remote_entity': _p(parts, 28),   # field 28 = remote entity name
            'event_name':    ev_name,
            'tcap_instance': '',
            'cs_instance':   '',
            'pcap':          {},
            'lines':         [],
        }

        # Scan neighbouring events within ±1 s for context parameters.
        for ctx_ts, _, ctx_ev, ctx_parts, ctx_dir in all_events:
            if ctx_dir in ('in', 'out'):
                continue
            if abs(ctx_ts - ts_f) > 1.0:
                continue
            ctx_lo = ctx_ev.lower()

            if ctx_lo == 'receivedcalltrigger':
                if 'initialdp' in ev_lo:
                    rec.setdefault('calling_number', _p(ctx_parts, 8))
                    rec.setdefault('called_number',  _p(ctx_parts, 9))
                    rec.setdefault('imsi',           _p(ctx_parts, 10))
                elif 'sendparameters' in ev_lo and dirn == 'out':
                    rec.setdefault('imsi', _p(ctx_parts, 10))

            elif ctx_lo == 'receivederb':
                if 'eventreport' in ev_lo:
                    rec.setdefault('erb_bcsm_type', _p(ctx_parts, 6))

            elif ctx_lo == 'actioncomplete' and _p(ctx_parts, 6) == 'ConnectTo':
                if 'connect' in ev_lo and 'requestreport' not in ev_lo:
                    rec.setdefault('connect_num', _p(ctx_parts, 9))

        records.append(rec)
    return records


def process_main_log(file_pattern, fsmid, out_handle, section_label: str = ''):
    """
    Four-pass extraction with smart backtracking:
    Pass 1: Identify FSMId lines and threads
    Pass 2: Smart backtrack (stop on different FSMId or thread change)
    Pass 3: Extract lines containing target FSMId
    Pass 4: Extract ASN.1 blocks from FSMId lines and thread lines
    """
    logging.info("<----Starting new log extract run---->")
    logging.info("Executing log extract logic for FSMId: %s", fsmid)
    _sec = section_label or 'Log Extract'
    out_handle.write(f"{'='*20} SECTION: {_sec} {'='*20}\n")

    target_fsmid = fsmid.lower()
    files = get_files(file_pattern)
    if not files:
        print(f"Log Extract: no files found for pattern: {file_pattern}")
    MAX_LINES_IN_BLOCK = 1000
    BACKTRACK_LIMIT = 500
    TRAILING_AFTER_RELEASE = 3
    fsmid_len = len(target_fsmid)
    fsmid_hex_re = re.compile(rf'\b[0-9a-f]{{{fsmid_len}}}\b')

    for file_path in files:
        print(f"Log Extract: searching {file_path}")
        try:
            with open_file(file_path) as f:
                lines = f.readlines()
        except (IOError, OSError) as e:
            logging.error("Failed to read file %s: %s", file_path, e)
            continue

        try:
            # PASS 1: Identify FSMId lines and threads
            fsmid_line_indices = []
            thread_map = {}  # thread_name -> first_line_idx_with_fsmid
            release_indices = {}

            for idx, line in enumerate(lines):
                if target_fsmid in line.lower():
                    fsmid_line_indices.append(idx)
                    thread = parse_thread(line)
                    if thread and thread not in thread_map:
                        thread_map[thread] = idx
                    if ('releasing state machine' in line.lower()
                            and thread and thread not in release_indices):
                        release_indices[thread] = idx

            if not fsmid_line_indices:
                logging.debug("No FSMId occurrences found in %s", file_path)
                continue

            fsmid_start_idx = min(fsmid_line_indices)
            fsmid_end_idx = max(fsmid_line_indices)

            logging.debug("FSMId found: lines %d-%d, %d threads",
                         fsmid_start_idx, fsmid_end_idx, len(thread_map))

            # PASS 2: Smart backtrack - stop on different FSMId or thread change
            thread_start_points = {}
            for thread, fsmid_first_idx in thread_map.items():
                backtrack_start = max(0, fsmid_first_idx - BACKTRACK_LIMIT)
                earliest_idx = fsmid_first_idx

                for idx in range(fsmid_first_idx - 1, backtrack_start - 1, -1):
                    line_lower = lines[idx].lower()

                    lf = line_fsmid(lines[idx])
                    if lf and fsmid_hex_re.fullmatch(lf) and lf != target_fsmid:
                        logging.debug("Backtrack stopped at line %d: different FSMId detected", idx)
                        break

                    line_thread = parse_thread(lines[idx])
                    if line_thread and line_thread != thread:
                        logging.debug("Backtrack stopped at line %d: thread changed from %s to %s",
                                     idx, thread, line_thread)
                        break

                    if thread in line_lower:
                        earliest_idx = idx

                thread_start_points[thread] = earliest_idx
                logging.debug("Thread '%s': backtracked from %d to %d", thread, fsmid_first_idx, earliest_idx)

            # PASS 2.5: Forward scan — no-fsmid thread lines belong to the NEXT fsmid on that
            # thread. Only include them if that next fsmid is the target.
            target_context_indices = set(fsmid_line_indices)
            scan_end = min(fsmid_end_idx + 51, len(lines))
            for thread, thread_start in thread_start_points.items():
                pending = []
                last_was_target = False
                for idx in range(thread_start, scan_end):
                    line_thread = parse_thread(lines[idx])
                    if line_thread != thread:
                        continue
                    lf = line_fsmid(lines[idx])
                    if lf and fsmid_hex_re.fullmatch(lf):
                        if lf == target_fsmid:
                            target_context_indices.update(pending)
                            last_was_target = True
                        else:
                            last_was_target = False
                        pending = []  # consumed — start fresh after any fsmid line
                    else:
                        pending.append(idx)
                # No-fsmid lines trailing after the last target fsmid belong to the target,
                # capped at TRAILING_AFTER_RELEASE lines past any "Releasing state machine" line.
                if last_was_target:
                    release_idx = release_indices.get(thread)
                    if release_idx is not None:
                        capped = [i for i in pending if i <= release_idx + TRAILING_AFTER_RELEASE]
                        target_context_indices.update(capped)
                    else:
                        target_context_indices.update(pending)

            # PASS 3 & 4: Extract FSMId lines and ASN.1 blocks
            written_indices = set()
            in_block = False
            in_multiline = False  # inside a multi-line log entry (no ASN.1 braces)
            block_start_idx = -1
            block_start_thread = None
            brace_depth = 0
            lines_in_block = 0

            earliest_start = min(thread_start_points.values()) if thread_start_points else fsmid_start_idx
            extraction_end = fsmid_end_idx + 50  # Capture trailing events after last FSMId

            for idx in range(earliest_start, min(extraction_end + 1, len(lines))):
                if idx in written_indices:
                    continue

                line = lines[idx]
                lower_line = line.lower()
                current_thread = parse_thread(line)

                # CASE 0: Continuation lines of a multi-line log entry
                if in_multiline:
                    out_handle.write(line)
                    written_indices.add(idx)
                    if is_log_entry_end(line):
                        in_multiline = False
                    continue

                # CASE 1: Inside an ASN.1 block
                if in_block:
                    out_handle.write(line)
                    written_indices.add(idx)
                    brace_depth += count_braces(line)
                    lines_in_block += 1

                    if is_asn1_end(line) or brace_depth < 0 or lines_in_block > MAX_LINES_IN_BLOCK:
                        in_block = False
                        logging.debug("Block ended at line %d (lines: %d)", idx, lines_in_block)
                    continue

                # CASE 2: Line contains target FSMId
                if target_fsmid in lower_line:
                    out_handle.write(line)
                    written_indices.add(idx)

                    if count_braces(line) > 0:
                        in_block = True
                        block_start_idx = idx
                        block_start_thread = current_thread
                        brace_depth = count_braces(line)
                        lines_in_block = 1
                        if is_asn1_end(line):
                            in_block = False
                        logging.debug("Block started at FSMId line %d", idx)
                    elif not is_log_entry_end(line):
                        in_multiline = True
                    continue

                # CASE 3: No-fsmid thread lines pre-approved by PASS 2.5
                if not in_block and current_thread and current_thread in thread_start_points:
                    thread_start = thread_start_points[current_thread]
                    if idx >= thread_start and idx in target_context_indices:
                        out_handle.write(line)
                        written_indices.add(idx)
                        if count_braces(line) > 0:
                            in_block = True
                            block_start_idx = idx
                            block_start_thread = current_thread
                            brace_depth = count_braces(line)
                            lines_in_block = 1
                            if is_asn1_end(line):
                                in_block = False
                            logging.debug("Block started at thread line %d (thread: %s)", idx, current_thread)
                        elif not is_log_entry_end(line):
                            in_multiline = True
                    continue

            out_handle.write("\n")

        except ValueError as e:
            logging.error("Value error processing %s: %s", file_path, e)
        except (IndexError, KeyError) as e:
            logging.error("Data structure error in %s: %s", file_path, e)
        except Exception as e:
            logging.error("Unexpected error processing %s: %s", file_path, e)


# ---------------------------------------------------------------------------
# PCAP extraction
# ---------------------------------------------------------------------------

def extract_tids(log_path):
    """Return sorted list of unique 8-char lowercase hex TID values from log."""
    tids = set()
    try:
        with open_file(log_path) as f:
            for line in f:
                for m in TID_RE.finditer(line):
                    tids.add(m.group(1).lower())
    except (IOError, OSError) as e:
        logging.error("Cannot read log file %s: %s", log_path, e)
        sys.exit(1)
    return sorted(tids)


def extract_tids_from_tcap_for_fsmids(tcap_glob, fsmids):
    """Scan TcapServer logs for lines containing any of the given FSMId strings and
    return 8-char hex TIDs found in bracket patterns on those lines.

    Used for FSMIds (e.g. cleanup FSMIds) that don't emit otid/dtid text in the
    callservice log, so their TIDs can't be seeded by extract_tids().
    """
    if not fsmids:
        return []
    needles = {f.lower() for f in fsmids}
    tids: set = set()
    for fpath in get_files(tcap_glob):
        try:
            with open_file(fpath) as f:
                for line in f:
                    ll = line.lower()
                    if not any(n in ll for n in needles):
                        continue
                    for m in _TCAP_BRACKET_TID_RE.finditer(line):
                        t = m.group(1).lower()
                        if t != '00000000':   # skip null TID
                            tids.add(t)
        except (IOError, OSError) as e:
            logging.warning("TID scan error %s: %s", fpath, e)
    return sorted(tids)


TSHARK_TRUNCATED = "cut short in the middle of a packet"


def build_tshark_filter(tids, first_ts=None, last_ts=None):
    """Build tshark display filter matching any TID (otid or dtid) via tcap.tid."""
    tid_parts = []
    for tid in tids:
        colon = _tid_to_colon(tid)
        tid_parts.append(f'tcap.tid == {colon}')
    tid_clause = ' || '.join(tid_parts)
    if first_ts is None and last_ts is None:
        return tid_clause
    parts = [f'({tid_clause})']
    if first_ts is not None:
        parts.append(f'frame.time_epoch >= {first_ts - 0.2:.3f}')
    if last_ts is not None:
        parts.append(f'frame.time_epoch <= {last_ts + 0.2:.3f}')
    return ' && '.join(parts)


def dechunk_sctp_stream(pcap_in, pcap_out, ports=None):
    """Split SCTP frames with multiple DATA chunks into one frame per chunk."""
    port_list = [int(p.strip()) for p in ports.split(',')] if ports else None
    try:
        with PcapWriter(pcap_out, append=False, sync=True) as writer:
            with PcapReader(pcap_in) as reader:
                for pkt in reader:
                    if pkt.haslayer(SCTP) and (not port_list or pkt.sport in port_list or pkt.dport in port_list):
                        control_chunks = []
                        data_chunks = []
                        current = pkt[SCTP].payload
                        while current and not isinstance(current, NoPayload):
                            chunk_copy = current.copy()
                            chunk_copy.payload = NoPayload()
                            if isinstance(current, SCTPChunkData):
                                data_chunks.append(chunk_copy)
                            else:
                                control_chunks.append(chunk_copy)
                            current = current.payload

                        if len(data_chunks) > 1:
                            for dc in data_chunks:
                                new_pkt = pkt.copy()
                                rebuilt = dc
                                for ctrl in reversed(control_chunks):
                                    ctrl.payload = rebuilt
                                    rebuilt = ctrl
                                new_pkt[SCTP].payload = rebuilt
                                new_pkt.time = pkt.time
                                if new_pkt.haslayer(IP):
                                    del new_pkt[IP].len
                                    del new_pkt[IP].chksum
                                del new_pkt[SCTP].chksum
                                finalized = new_pkt.__class__(bytes(new_pkt))
                                finalized.time = pkt.time
                                writer.write(finalized)
                        else:
                            writer.write(pkt)
                    else:
                        writer.write(pkt)
    except Exception as e:
        logging.error("Error dechunking %s: %s", pcap_in, e)
        sys.exit(1)


def run_tshark(pcap_path, display_filter, out_path):
    """Run tshark on one pcap file and write matching packets to out_path."""
    cmd = ['tshark', '-r', pcap_path, '-Y', display_filter, '-w', out_path]
    logging.debug("Running: %s", shlex.join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        combined = result.stdout + result.stderr
        if result.returncode not in (0, 2):  # tshark exits 2 on empty output
            if TSHARK_TRUNCATED in combined:
                logging.warning("Truncated packet at end of %s — last incomplete packet ignored", pcap_path)
            else:
                logging.warning("tshark exited %d for %s: %s", result.returncode, pcap_path, result.stderr.strip())
        return result.returncode in (0, 2) or TSHARK_TRUNCATED in combined
    except FileNotFoundError:
        logging.error("tshark not found — install Wireshark/tshark and ensure it is on PATH")
        sys.exit(1)


def count_packets(pcap_path):
    """Return packet count in a pcap file using tshark."""
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields', '-e', 'frame.number'],
            capture_output=True, text=True
        )
        return len([l for l in result.stdout.splitlines() if l.strip()])
    except Exception:
        return -1


def merge_pcaps(input_files, output_path):
    """Merge a list of pcap files into output_path using mergecap."""
    cmd = ['mergecap', '-w', output_path] + input_files
    logging.debug("Running: %s", shlex.join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error("mergecap failed: %s", result.stderr.strip())
            sys.exit(1)
    except FileNotFoundError:
        logging.error("mergecap not found — install Wireshark and ensure it is on PATH")
        sys.exit(1)


def process_pcap(log_path, pcap_pattern, pcap_output_path, extra_tids=None,
                 first_ts=None, last_ts=None):
    """Extract PCAP packets whose TCAP TID matches values found in log_path.

    extra_tids: optional iterable of hex TID strings discovered via trace-based
    PCAP filtering; merged with TIDs from log_path before filtering.
    first_ts / last_ts: epoch float bounds derived from the DetailedTrace window.
    Packets outside [first_ts - 5s, last_ts + 5s] are skipped even if TID matches,
    preventing collisions with reused TIDs from other calls outside this window.

    Pipeline:
      1. Filter each original pcap with tshark (no dechunking) → fast per-file pass
      2. Merge all filtered results into one pcap
      3. Dechunk the merged pcap (split multi-chunk SCTP frames)
      4. Filter again on the dechunked pcap → final output
    """
    tids_set = set(extract_tids(log_path))
    if extra_tids:
        new = set(extra_tids) - tids_set
        if new:
            logging.info("Trace-based discovery added %d TID(s): %s",
                         len(new), ', '.join(sorted(new)))
        tids_set.update(extra_tids)
    tids = sorted(tids_set)
    if not tids:
        logging.warning("No TCAP TIDs found in %s — skipping PCAP extraction", log_path)
        return

    logging.info("Found %d unique TID(s): %s", len(tids), ', '.join(tids))
    _PCAP_WINDOW_BUFFER = 5.0
    ts_first = (first_ts - _PCAP_WINDOW_BUFFER) if first_ts is not None else None
    ts_last  = (last_ts  + _PCAP_WINDOW_BUFFER) if last_ts  is not None else None
    if first_ts is not None:
        logging.info("PCAP time window: %.3f – %.3f (±%.0fs buffer)",
                     first_ts, last_ts, _PCAP_WINDOW_BUFFER)
    display_filter = build_tshark_filter(tids, ts_first, ts_last)
    logging.info("Filter: %s", display_filter)

    pcap_files = sorted(glob.glob(pcap_pattern))
    if not pcap_files:
        print(f"PCAP: no files found for pattern: {pcap_pattern}")
        return

    logging.info("Step 1: Filtering %d PCAP file(s) ...", len(pcap_files))
    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: filter each original pcap directly (no dechunking)
        filtered_files = []
        for i, pcap in enumerate(pcap_files):
            print(f"PCAP: searching {pcap}")
            filtered = os.path.join(tmpdir, f"filtered_{i:04d}.pcap")
            run_tshark(pcap, display_filter, filtered)
            if os.path.exists(filtered) and os.path.getsize(filtered) > 24:
                pkt_count = count_packets(filtered)
                logging.info("    -> %d matching packet(s)", pkt_count)
                filtered_files.append(filtered)

        if not filtered_files:
            logging.warning("No matching packets found across all PCAP files")
            return

        # Step 2: merge all filtered results
        merged = os.path.join(tmpdir, "merged.pcap")
        if len(filtered_files) == 1:
            merged = filtered_files[0]
        else:
            logging.info("Step 2: Merging %d filtered file(s) ...", len(filtered_files))
            merge_pcaps(filtered_files, merged)

        # Step 3: dechunk the merged pcap
        dechunked = os.path.join(tmpdir, "dechunked.pcap")
        logging.info("Step 3: Dechunking merged extract ...")
        dechunk_sctp_stream(merged, dechunked)

        # Step 4: filter again on dechunked to catch TIDs split across chunks
        logging.info("Step 4: Final filter on dechunked pcap ...")
        run_tshark(dechunked, display_filter, pcap_output_path)

    total = count_packets(pcap_output_path)
    print(f"PCAP extraction complete. {total} packet(s) written to: {pcap_output_path}")


def parse_summary_trace_fields(summary_glob, fsmid):
    """Parse SummaryTrace files (comma-delimited) for FSMId lines; return tshark-relevant fields.

    Field mapping (1-indexed → 0-indexed):
      13→12 IMSI (e212.imsi)
      14→13 Calling Number (e164.calling_party_number.digits)
      15→14 SCCP Calling Digit (sccp.calling.digits)
      16→15 SCCP Called Digit (sccp.called.digits)
      21→20 Called Number (e164.called_party_number.digits)
    """
    results = []
    target = fsmid.lower()
    for fpath in sorted(glob.glob(summary_glob)):
        with open_file(fpath) as f:
            for line in f:
                if target not in line.lower():
                    continue
                parts = line.rstrip('\n').split(',')
                if len(parts) < 21:
                    continue
                entry = {
                    'imsi':           parts[12].strip(),
                    'calling_number': parts[13].strip(),
                    'sccp_calling':   parts[14].strip(),
                    'sccp_called':    parts[15].strip(),
                    'called_number':  parts[20].strip(),
                }
                if any(entry.values()):
                    results.append(entry)
    return results


def parse_detail_trace_sccp_fields(detail_glob, fsmid):
    """Parse DetailedTrace files for FSMId lines where Field 4 (index 3) == '1'.

    Field mapping (1-indexed → 0-indexed):
       1→ 0 Timestamp string "DD-MM-YYYY HH:MM:SS"
       2→ 1 Milliseconds (integer string)
      10→ 9 Protocol ("camel" | "map")
      11→10 Opcode (numeric)
      14→13 SCCP Calling Digit (sccp.calling.digits)
      15→14 SCCP Called Digit (sccp.called.digits)
      18→17 TCAP message type (begin | continue | end | abort)

    Only lines with Field 4 (index 3) == '1' carry a meaningful direction tag and
    are used for SCCP digit, opcode, and timestamp extraction.
    """
    results = []
    target = fsmid.lower()
    for fpath in sorted(glob.glob(detail_glob)):
        with open_file(fpath) as f:
            for line in f:
                if target not in line.lower():
                    continue
                parts = line.rstrip('\n').split(',')
                if len(parts) < 15:
                    continue
                if parts[3].strip() != '1':
                    continue
                entry = {
                    'timestamp':     parts[0].strip(),                                        # field 1
                    'ms':            parts[1].strip(),                                        # field 2
                    'protocol':      parts[9].strip().lower() if len(parts) > 9  else '',    # field 10
                    'opcode':        parts[10].strip()         if len(parts) > 10 else '',    # field 11
                    'sccp_calling':  parts[13].strip()         if len(parts) > 13 else '',    # field 14
                    'sccp_called':   parts[14].strip()         if len(parts) > 14 else '',    # field 15
                    'tcap_msg_type': parts[17].strip().lower() if len(parts) > 17 else '',    # field 18
                }
                if entry['sccp_calling'] or entry['sccp_called']:
                    results.append(entry)
    return results


def _parse_timezone(tz_str):
    """Parse a timezone string into a tzinfo object.

    Accepts fixed UTC offsets ("-0500", "+0530", "UTC-5") or IANA names
    ("America/Mexico_City"). Fixed offsets are preferred when the log system's
    DST rules differ from the current IANA database.
    """
    m = re.match(r'^([+-])(\d{2}):?(\d{2})$', tz_str)
    if m:
        sign = 1 if m.group(1) == '+' else -1
        return timezone(timedelta(hours=sign * int(m.group(2)),
                                  minutes=sign * int(m.group(3))))
    m = re.match(r'^UTC([+-])(\d{1,2})(?::(\d{2}))?$', tz_str, re.IGNORECASE)
    if m:
        sign = 1 if m.group(1) == '+' else -1
        return timezone(timedelta(hours=sign * int(m.group(2)),
                                  minutes=sign * int(m.group(3) or 0)))
    return ZoneInfo(tz_str)


def _ts_to_epoch(timestamp_str, ms_str, tz=None):
    """Convert DetailedTrace timestamp + ms string to UTC epoch (float seconds).

    timestamp_str format: "DD-MM-YYYY HH:MM:SS" in the log system's timezone.
    tz: tzinfo from _parse_timezone() for the log system. None = local system time.
    Returns None on parse failure.
    """
    try:
        dt = datetime.strptime(timestamp_str.strip(), '%d-%m-%Y %H:%M:%S')
        if tz is not None:
            dt = dt.replace(tzinfo=tz)
        ms = int(ms_str.strip()) if ms_str.strip().isdigit() else 0
        return dt.timestamp() + ms / 1000.0
    except (ValueError, AttributeError):
        return None


def _detail_trace_epoch_window(detail_records: list, tz=None):
    """Return (first_epoch, last_epoch) from parse_detail_trace_records() output.

    Timestamps in those records are 'YYYY-MM-DD HH:MM:SS.mmm' (log-system local time).
    tz: tzinfo from _parse_timezone(). None = assume local system time.
    Returns (None, None) if records are empty or all timestamps fail to parse.
    """
    epochs = []
    for r in detail_records:
        ts = r.get('timestamp', '')
        if not ts:
            continue
        try:
            dt = datetime.strptime(ts.strip(), '%Y-%m-%d %H:%M:%S.%f')
            if tz is not None:
                dt = dt.replace(tzinfo=tz)
            epochs.append(dt.timestamp())
        except (ValueError, AttributeError):
            continue
    return (min(epochs), max(epochs)) if epochs else (None, None)


def is_valid_sccp_digits(s):
    """Return True only for all-digit strings of at least 7 characters."""
    return bool(s) and s.isdigit() and len(s) >= 7


_OPCODE_FIELD = {
    'camel': 'camel.local',
    'map':   'gsm_old.localValue',
}

_TCAP_MSG_TYPE_FILTER = {
    'begin':    'tcap.begin_element',
    'continue': 'tcap.continue_element',
    'cont':     'tcap.continue_element',
    'end':      'tcap.end_element',
    'abort':    'tcap.abort_element',
}


def build_trace_based_filter(summary_fields, detail_sccp_list, tz=None):
    """Build a tshark display filter from SummaryTrace and DetailedTrace fields.

    Filter logic:
    - SCCP calling + called pair → AND'd together per message (invalid digits skipped)
    - e164 calling + called pair → AND'd together
    - Numeric opcode → AND'd with SCCP pair; field name chosen by protocol
      (camel → camel.local, map → gsm_old.localValue)
    - Timestamp window → AND'd: frame.time_epoch >= T-0.2 && frame.time_epoch <= T+0.2
    - Across all messages (Summary and Detail): OR
    - Duplicate conditions are collapsed via set.

    Invalid SCCP digits (non-numeric or fewer than 7 chars) are silently skipped.
    Returns a 3-tuple (filter_str, min_epoch, max_epoch) where filter_str is the
    tshark display filter string (or None if no usable fields), and min_epoch/max_epoch
    are the earliest/latest DetailedTrace timestamps as float epoch seconds (or None).
    """
    conditions = set()
    min_epoch = None
    max_epoch = None

    for f in summary_fields:
        calling_num  = f.get('calling_number', '').strip()
        called_num   = f.get('called_number', '').strip()
        sccp_calling = f.get('sccp_calling', '').strip()
        sccp_called  = f.get('sccp_called', '').strip()

        if is_valid_sccp_digits(sccp_calling) and is_valid_sccp_digits(sccp_called):
            conditions.add(
                f'(sccp.calling.digits == "{sccp_calling}" && sccp.called.digits == "{sccp_called}")')
        elif is_valid_sccp_digits(sccp_calling):
            conditions.add(f'sccp.calling.digits == "{sccp_calling}"')
        elif is_valid_sccp_digits(sccp_called):
            conditions.add(f'sccp.called.digits == "{sccp_called}"')
        if calling_num and called_num:
            conditions.add(
                f'(e164.calling_party_number.digits == "{calling_num}" && '
                f'e164.called_party_number.digits == "{called_num}")')

    for d in detail_sccp_list:
        protocol      = d.get('protocol', '').strip().lower()
        sccp_calling  = d.get('sccp_calling', '').strip()
        sccp_called   = d.get('sccp_called', '').strip()
        opcode        = d.get('opcode', '').strip()
        tcap_msg_type = d.get('tcap_msg_type', '').strip().lower()
        epoch         = _ts_to_epoch(d.get('timestamp', ''), d.get('ms', ''), tz)

        if epoch is not None:
            min_epoch = epoch if min_epoch is None else min(min_epoch, epoch)
            max_epoch = epoch if max_epoch is None else max(max_epoch, epoch)

        sccp_parts = []
        if is_valid_sccp_digits(sccp_calling) and is_valid_sccp_digits(sccp_called):
            sccp_parts.append(f'sccp.calling.digits == "{sccp_calling}"')
            sccp_parts.append(f'sccp.called.digits == "{sccp_called}"')
        elif is_valid_sccp_digits(sccp_calling):
            sccp_parts.append(f'sccp.calling.digits == "{sccp_calling}"')
        elif is_valid_sccp_digits(sccp_called):
            sccp_parts.append(f'sccp.called.digits == "{sccp_called}"')

        opcode_field = _OPCODE_FIELD.get(protocol)
        if opcode_field and opcode and opcode.isdigit():
            sccp_parts.append(f'{opcode_field} == {opcode}')

        msg_filter = _TCAP_MSG_TYPE_FILTER.get(tcap_msg_type)
        if msg_filter:
            sccp_parts.append(msg_filter)

        if epoch is not None:
            sccp_parts.append(f'frame.time_epoch >= {epoch - 0.2:.3f}')
            sccp_parts.append(f'frame.time_epoch <= {epoch + 0.2:.3f}')

        if len(sccp_parts) > 1:
            conditions.add('(' + ' && '.join(sccp_parts) + ')')
        elif sccp_parts:
            conditions.add(sccp_parts[0])

    if not conditions:
        return None, min_epoch, max_epoch
    return ' || '.join(sorted(conditions)), min_epoch, max_epoch


def _extract_tids_dechunked(pcap_files, trace_filter):
    """Extract TCAP TIDs after dechunking to avoid multi-dialog SCTP frame contamination.

    Multi-chunk SCTP frames can carry packets from several dialogs simultaneously.
    Extracting TIDs directly from such frames picks up TIDs from ALL dialogs in the
    chunk, not just the one that matched the filter.  This function avoids that by:
      Stage 1 — run trace_filter on raw PCAPs → collect matching raw frames
      Stage 2 — merge + dechunk → each SCTP chunk becomes its own frame
      Stage 3 — re-run trace_filter on dechunked PCAP → extract TIDs
    After dechunking, only the chunk that genuinely matched the trace filter survives
    stage 3, so foreign TIDs from co-bundled chunks are excluded.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        stage1 = []
        for i, pcap in enumerate(pcap_files):
            out = os.path.join(tmpdir, f"s1_{i}.pcap")
            if run_tshark(pcap, trace_filter, out) and count_packets(out) > 0:
                stage1.append(out)

        if not stage1:
            return []

        logging.debug("Stage 1 matched %d file(s); merging for dechunk", len(stage1))
        merged    = os.path.join(tmpdir, "s1_merged.pcap")
        dechunked = os.path.join(tmpdir, "s1_dechunked.pcap")
        merge_pcaps(stage1, merged)
        dechunk_sctp_stream(merged, dechunked)
        logging.debug("Stage 2: re-running trace filter on dechunked PCAP (%d packets)",
                      count_packets(dechunked))
        tids = extract_tids_from_pcap_packets([dechunked], trace_filter)
        logging.debug("Stage 2 TIDs after dechunk: %s", tids)
        return tids


def extract_tids_from_pcap_packets(pcap_files, display_filter=None):
    """Extract TCAP TIDs from PCAP files via tshark field extraction.

    Runs tshark on each file with -T fields -e tcap.tid.
    If display_filter is given, only matching packets are inspected.
    Returns a sorted list of unique 8-character lowercase hex TID strings.
    """
    tids = set()

    for pcap in pcap_files:
        cmd = ['tshark', '-r', pcap, '-t', 'ad']
        if display_filter:
            cmd.extend(['-Y', display_filter])
        cmd.extend([
            '-T', 'fields',
            '-e', 'tcap.tid',
            '-E', 'separator=\t',
        ])
        logging.debug("Running: %s", shlex.join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            logging.error("tshark not found — install Wireshark/tshark and ensure it is on PATH")
            sys.exit(1)
        if result.stdout.strip():
            logging.debug("TID extraction output from %s:\n%s", pcap, result.stdout.rstrip())
        for line in result.stdout.splitlines():
            for val in line.split('\t'):
                hex_val = val.strip().replace(':', '')  # tshark outputs "04:2e:7f:be"
                if re.fullmatch(r'[0-9a-fA-F]{8}', hex_val):
                    tids.add(hex_val.lower())

    return sorted(tids)


def _dedup_pcap(src, dst):
    """Deduplicate packets by IP-and-above payload hash, writing result to dst.

    editcap -d compares raw frame bytes, so it misses duplicates that differ only
    in link-layer headers (common when the same packet is captured on two interfaces).
    Hashing from the IP layer upward catches those cases.
    """
    seen = set()
    kept = dropped = 0
    with PcapWriter(dst, append=False, sync=True) as writer:
        with PcapReader(src) as reader:
            for pkt in reader:
                key = bytes(pkt[IP]) if IP in pkt else bytes(pkt)
                if key not in seen:
                    seen.add(key)
                    writer.write(pkt)
                    kept += 1
                else:
                    dropped += 1
    if dropped:
        logging.info("Dedup: removed %d duplicate packet(s), kept %d", dropped, kept)


def process_pcap_from_traces(summary_glob, detail_glob, fsmid, pcap_pattern, pcap_output_path, tz=None):
    """Extract PCAP when callservice logs (-m) are absent.

    Two-pass pipeline:
      Pass 1 — build tshark display filter from SummaryTrace/DetailedTrace fields;
               run tshark on each PCAP with that filter to extract TCAP TIDs.
      Pass 2 — apply TID-based filter on all PCAPs → merge → dechunk SCTP →
               final TID filter → output PCAP.

    tz: tzinfo for the log system's timezone (from _parse_timezone()); None = local time.
    Reuses: build_tshark_filter, run_tshark, count_packets, merge_pcaps,
            dechunk_sctp_stream (all defined elsewhere in this file).
    """
    summary_fields = parse_summary_trace_fields(summary_glob, fsmid)
    detail_sccp    = parse_detail_trace_sccp_fields(detail_glob, fsmid)

    display_filter, min_epoch, max_epoch = build_trace_based_filter(summary_fields, detail_sccp, tz)
    if not display_filter:
        logging.warning(
            "No usable trace fields found for FSMId %s — skipping trace-based PCAP extraction",
            fsmid)
        return

    logging.info("Trace-based tshark filter: %s", display_filter)
    if min_epoch is not None and max_epoch is not None:
        logging.debug("DetailedTrace time window: %.3f – %.3f (±0.2 s applied to TID filter)",
                      min_epoch, max_epoch)

    pcap_files = sorted(glob.glob(pcap_pattern))
    if not pcap_files:
        logging.warning("No PCAP files found for pattern: %s", pcap_pattern)
        return

    # Pass 1: extract TIDs — merge+dechunk first so multi-dialog SCTP frames don't contaminate
    pass1_filter = display_filter
    if min_epoch is not None and max_epoch is not None:
        pass1_filter = (f'({display_filter}) && '
                        f'frame.time_epoch >= {min_epoch - 1.0:.3f} && '
                        f'frame.time_epoch <= {max_epoch + 1.0:.3f}')
        logging.info("Pass 1 filter (DetailedTrace-bounded): %s", pass1_filter)
    tids = _extract_tids_dechunked(pcap_files, pass1_filter)
    if not tids:
        logging.warning(
            "No TCAP TIDs found in PCAPs matching trace-based filter — skipping")
        return

    logging.info("Found %d TCAP TID(s) via trace filter: %s", len(tids), ', '.join(tids))

    # Pass 2: TID-based filtering bounded by the DetailedTrace time window
    tid_filter = build_tshark_filter(tids, first_ts=min_epoch, last_ts=max_epoch)
    logging.info("TID filter: %s", tid_filter)

    with tempfile.TemporaryDirectory() as tmpdir:
        filtered_files = []
        for i, pcap in enumerate(pcap_files):
            tmp = os.path.join(tmpdir, f"tid_{i}.pcap")
            if run_tshark(pcap, tid_filter, tmp) and count_packets(tmp) > 0:
                filtered_files.append(tmp)

        if not filtered_files:
            logging.warning("No PCAP packets matched TID filter in Pass 2")
            return

        merged    = os.path.join(tmpdir, "merged.pcap")
        dechunked = os.path.join(tmpdir, "dechunked.pcap")
        deduped   = os.path.join(tmpdir, "deduped.pcap")

        merge_pcaps(filtered_files, merged)
        dechunk_sctp_stream(merged, dechunked)
        run_tshark(dechunked, tid_filter, deduped)
        _dedup_pcap(deduped, pcap_output_path)

    n = count_packets(pcap_output_path)
    logging.info("Trace-based PCAP extraction complete: %d packet(s) → %s",
                 n, pcap_output_path)
    print(f"PCAP (trace-based): {n} packet(s) → {pcap_output_path}")


def process_tcap_pcap(tcap_pattern, tcap_tids, output_path):
    """Convert DKSS7Interface hex dumps in TcapServer logs to a filtered PCAP.

    Pipeline: convert all log files → merge into one → single tshark filter pass
    with all TIDs combined.
    """
    files = get_files(tcap_pattern)
    if not files or not tcap_tids:
        return

    display_filter = build_tshark_filter(tcap_tids)
    logging.info("TcapServer PCAP: converting %d file(s) with filter: %s",
                 len(files), display_filter)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: convert each log file to PCAP
        converted_pcaps = []
        for i, fpath in enumerate(files):
            tmp_pcap = os.path.join(tmpdir, f"dk_{i:04d}.pcap")
            try:
                count = hexlog2pcap.convert(fpath, tmp_pcap,
                                             parser="dk", decoder="sccp")
                if count > 0 and os.path.exists(tmp_pcap):
                    logging.info("  %s -> %d packet(s)", fpath, count)
                    converted_pcaps.append(tmp_pcap)
            except Exception as e:
                logging.warning("hexlog2pcap failed on %s: %s", fpath, e)

        if not converted_pcaps:
            logging.warning("TcapServer PCAP: no packets decoded from DK hex dumps")
            return

        # Step 2: merge all converted PCAPs into one
        if len(converted_pcaps) == 1:
            merged = converted_pcaps[0]
        else:
            merged = os.path.join(tmpdir, "merged_dk.pcap")
            logging.info("Step 2: Merging %d converted file(s)...", len(converted_pcaps))
            merge_pcaps(converted_pcaps, merged)

        # Step 3: single tshark filter pass with all TIDs
        logging.info("Step 3: Filtering merged PCAP with %d TID(s)...", len(tcap_tids))
        run_tshark(merged, display_filter, output_path)

    if os.path.exists(output_path) and os.path.getsize(output_path) > 24:
        total = count_packets(output_path)
        print(f"TcapServer PCAP: {total} packet(s) written to: {output_path}")
    else:
        logging.warning("TcapServer PCAP: no matching packets found")


# ---------------------------------------------------------------------------
# TcapServer helpers
# ---------------------------------------------------------------------------

def _sanitize_id(name):
    return re.sub(r'[^a-zA-Z0-9]', '_', name)


_DAY_ABBR = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
_MON_ABBR = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']


def _extract_pcap_timestamps(pcap_path, tcap_tids):
    """Return set of log-format timestamps for PCAP packets matching tcap_tids.

    Timestamp format matches TcapServer log field[0]|field[1]:
      'Mon Apr 27|12:49:05.290'
    Uses frame.time_epoch for sub-second precision.
    """
    if not pcap_path or not os.path.exists(pcap_path):
        return set()
    if os.path.getsize(pcap_path) <= 24:
        return set()

    display_filter = build_tshark_filter(tcap_tids)
    try:
        result = subprocess.run(
            [TSHARK_CMD, '-r', pcap_path, '-Y', display_filter,
             '-T', 'fields', '-e', 'frame.time_epoch'],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as e:
        logging.warning("_extract_pcap_timestamps failed: %s", e)
        return set()

    timestamps = set()
    for raw in result.stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            epoch = float(raw)
            dt = datetime.fromtimestamp(epoch)  # local time — matches TcapServer log timestamps
            ts = (f"{_DAY_ABBR[dt.weekday()]} {_MON_ABBR[dt.month - 1]} {dt.day:2d}"
                  f"|{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
                  f".{dt.microsecond // 1000:03d}")
            timestamps.add(ts)
        except (ValueError, OSError):
            pass

    logging.info("PCAP timestamp extraction: %d unique log-format timestamp(s)", len(timestamps))
    return timestamps


def _subtract_1ms(ts_str):
    """Subtract 1 ms from a log-format timestamp string.

    Input/output: 'Mon Apr 27|12:49:05.290'
    Handles ms=0 rollback into the previous second.
    Does not handle midnight boundary (rare; returns ts_str unchanged).
    """
    try:
        date_part, time_part = ts_str.split('|', 1)
        hms, ms_str = time_part.rsplit('.', 1)
        ms = int(ms_str)
        if ms > 0:
            return f"{date_part}|{hms}.{ms - 1:03d}"
        h, m, s = (int(x) for x in hms.split(':'))
        if s > 0:
            return f"{date_part}|{h:02d}:{m:02d}:{s - 1:02d}.999"
        if m > 0:
            return f"{date_part}|{h:02d}:{m - 1:02d}:59.999"
        if h > 0:
            return f"{date_part}|{h - 1:02d}:59:59.999"
        return ts_str  # midnight boundary — unchanged
    except Exception:
        return ts_str


# ---------------------------------------------------------------------------
# TcapServer log extraction
# ---------------------------------------------------------------------------

_HEX_DUMP_SRC_RE = re.compile(r'DKSS7Interface', re.IGNORECASE)


def _find_hex_dump_threads(files, pcap_timestamps):
    """Find DK hex dump threads and their line positions via PCAP timestamp matching.

    Scans TcapServer log files for lines at each PCAP packet timestamp (and 1 ms
    before, to capture the 'Received message from Dialogic' preamble line) whose
    source file field contains 'DKSS7Interface'.

    Returns
    -------
    hex_thread_ids : set[str]
    hex_positions  : set[tuple[str, int]]  — (fpath, line_no)
    """
    if not pcap_timestamps:
        return set(), set()

    ts_window = set(pcap_timestamps)
    for ts in pcap_timestamps:
        ts_window.add(_subtract_1ms(ts))

    hex_thread_ids: set[str] = set()
    hex_positions: set[tuple] = set()

    for fpath in sorted(files):
        try:
            with open_file(fpath) as f:
                for line_no, raw in enumerate(f):
                    line = raw.rstrip('\n\r')
                    parts = line.split('|')
                    if len(parts) < 6:
                        continue
                    line_ts = f"{parts[0]}|{parts[1]}"
                    if line_ts not in ts_window:
                        continue
                    tid = _tcap_thread_id(line)
                    if not tid:
                        continue
                    if _HEX_DUMP_SRC_RE.search(parts[5]):
                        hex_thread_ids.add(tid)
                        hex_positions.add((fpath, line_no))
        except (IOError, OSError) as e:
            logging.error("Cannot read %s: %s", fpath, e)

    logging.info("Phase 3: hex dump thread(s) %s (%d position(s))",
                 sorted(hex_thread_ids), len(hex_positions))
    return hex_thread_ids, hex_positions


def process_tcap_logs(file_pattern, tcap_tids, out_handle, tcap_pcap_path=None):
    """
    Thread-block extraction for TcapServer logs.

    A TcapServer "block" is one handling of a TCAP message on a thread:
      - Starts at a "Received from n/w|App" line on that thread
      - Ends at the next "Received from" on the same thread, or EOF
      - Aborted early if the dialog_id changes mid-block

    Phase 1: find threads via exact hex TID match in log text.
    Phase 2: expand to threads handling the same decimal dialog IDs.

    Returns (found_dialog_ids: set[str], flow_records: list[dict],
             tid_to_dialog: dict[str, str])
    """
    out_handle.write(f"\n{'='*20} SECTION: TcapServer {'='*20}\n")

    files = get_files(file_pattern)
    if not files:
        logging.warning("TcapServer: no files for pattern %s", file_pattern)
        out_handle.write("  (no files found)\n\n")
        return set(), [], {}

    if not tcap_tids:
        logging.warning("TcapServer: no TCAP TIDs to search for")
        out_handle.write("  (no TCAP TIDs available)\n\n")
        return set(), [], {}

    hex_terms = {re.sub(r'[^0-9a-fA-F]', '', t).lower() for t in tcap_tids if t}
    hex_terms.discard('')
    logging.info("TcapServer: initial hex TID search terms: %s", sorted(hex_terms))

    # Build per-thread ordered line list: {thread_id: [(line, fpath, line_no), ...]}
    thread_line_map: dict[str, list] = defaultdict(list)
    for fpath in sorted(files):
        logging.info("TcapServer: reading %s", fpath)
        try:
            with open_file(fpath) as f:
                for line_no, raw in enumerate(f):
                    line = raw.rstrip('\n\r')
                    tid = _tcap_thread_id(line)
                    if tid:
                        thread_line_map[tid].append((line, fpath, line_no))
        except (IOError, OSError) as e:
            logging.error("Cannot read %s: %s", fpath, e)

    def _matching_blocks(thread_id, search_terms):
        """
        Return blocks from thread_id whose content matches search_terms.
        Block boundaries: "Received from n/w|App" lines.
        Block stops early if dialog_id changes.
        Each block dict contains:
          'lines'     : list[str]             — line text (backward-compat)
          'positions' : list[tuple[str, int]] — (fpath, line_no) for sequential write
        """
        tlines = thread_line_map[thread_id]  # [(text, fpath, line_no), ...]

        recv_idx = [
            i for i, (ln, _fp, _lno) in enumerate(tlines)
            if _TCAP_NW_RE.search(ln) or _TCAP_APP_RE.search(ln)
        ]
        if not recv_idx:
            recv_idx = [0]

        matched = []
        for b_num, start in enumerate(recv_idx):
            end = recv_idx[b_num + 1] if b_num + 1 < len(recv_idx) else len(tlines)

            block_lines = []
            block_positions = []
            block_dialog = None
            block_type = 'network' if _TCAP_NW_RE.search(tlines[start][0]) else 'app'

            for (ln, fp, lno) in tlines[start:end]:
                m = _TCAP_DIALOG_RE.search(ln)
                if m:
                    did = m.group(1)
                    if block_dialog is None:
                        block_dialog = did
                    elif did != block_dialog:
                        # '0' is a placeholder used before a real dialog ID is assigned
                        # (e.g. "Received from App BEGIN Dialog [0:fsmid]"). Allow the
                        # transition from 0 → real ID without breaking the block.
                        if block_dialog == '0':
                            block_dialog = did
                        else:
                            break
                block_lines.append(ln)
                block_positions.append((fp, lno))

            combined_lower = '\n'.join(block_lines).lower()
            if any(t in combined_lower for t in search_terms):
                matched.append({
                    'thread_id':   thread_id,
                    'dialog_id':   block_dialog or '',
                    'thread_type': block_type,
                    'lines':       block_lines,      # list[str] — unchanged for downstream
                    'positions':   block_positions,  # list[(fpath, line_no)]
                })
        return matched

    # Phase 1: threads that contain hex TIDs
    all_blocks: list[dict] = []
    found_dialog_ids: set[str] = set()
    processed_threads: set[str] = set()

    for thread_id, tlines in thread_line_map.items():
        combined = '\n'.join(ln for ln, _fp, _lno in tlines).lower()
        if any(t in combined for t in hex_terms):
            blocks = _matching_blocks(thread_id, hex_terms)
            all_blocks.extend(blocks)
            processed_threads.add(thread_id)
            for blk in blocks:
                if blk['dialog_id']:
                    found_dialog_ids.add(blk['dialog_id'])

    logging.info("TcapServer Phase 1: %d thread(s), %d block(s), dialog IDs: %s",
                 len(processed_threads), len(all_blocks), sorted(found_dialog_ids))

    # Phase 2: expand via dialog_ids to other threads
    for _round in range(3):
        prev_count = len(all_blocks)
        new_threads = set()
        for thread_id, tlines in thread_line_map.items():
            if thread_id in processed_threads:
                continue
            combined = '\n'.join(ln for ln, _fp, _lno in tlines).lower()
            if any(did in combined for did in found_dialog_ids):
                new_threads.add(thread_id)
        for thread_id in new_threads:
            blocks = _matching_blocks(thread_id, found_dialog_ids)
            all_blocks.extend(blocks)
            processed_threads.add(thread_id)
            for blk in blocks:
                if blk['dialog_id']:
                    found_dialog_ids.add(blk['dialog_id'])
        if len(all_blocks) == prev_count:
            break

    logging.info("TcapServer: %d block(s) from %d thread(s); dialog IDs: %s",
                 len(all_blocks), len(processed_threads), sorted(found_dialog_ids))

    # Phase 3: find hex dump threads via PCAP timestamps
    hex_thread_ids: set[str] = set()
    hex_positions: set[tuple] = set()
    if tcap_pcap_path:
        pcap_timestamps = _extract_pcap_timestamps(tcap_pcap_path, tcap_tids)
        hex_thread_ids, hex_positions = _find_hex_dump_threads(files, pcap_timestamps)
        logging.info("Phase 3 complete: %d hex dump thread(s)", len(hex_thread_ids))

    if not all_blocks and not hex_positions:
        out_handle.write("  (no matching blocks found)\n\n")
        return found_dialog_ids, [], {}

    # Build tid_to_dialog from block content (each block already knows its dialog_id)
    tid_to_dialog: dict[str, str] = {}
    for blk in all_blocks:
        did = blk['dialog_id']
        if not did:
            continue
        for line in blk['lines']:
            for m in _TCAP_BRACKET_TID_RE.finditer(line):
                h = m.group(1).lower()
                if h in hex_terms and h not in tid_to_dialog:
                    tid_to_dialog[h] = did
    logging.info("TcapServer: TID→dialog mapping: %s", tid_to_dialog)

    # Build one flow record per block
    flow_records = []
    for blk in all_blocks:
        did = blk['dialog_id']
        if not did:
            continue
        ts = ''
        for ln in blk['lines']:
            m = _TCAP_TS_RE.search(ln)
            if m:
                ts = m.group(1)
                break
        app_name = ''
        for ln in blk['lines']:
            m = _TCAP_APP_NAME_RE.search(ln)
            if m:
                app_name = m.group(2)
                break
        # Instance names from filename and log content
        positions = blk.get('positions', [])
        fname = os.path.basename(positions[0][0]) if positions else ''
        m_inst = _TCAP_INSTANCE_RE.search(fname)
        tcap_instance = f"TCAP-{m_inst.group(1)}" if m_inst else 'TcapServer'
        cs_instance = ''
        for ln in blk['lines']:
            m_cs = _CS_INSTANCE_RE.search(ln)
            if m_cs:
                cs_instance = m_cs.group(1)
                break
        forwarded_to_app = any(_TCAP_SEND_APP_RE.search(l) for l in blk['lines'])
        sent_to_nw       = any(_TCAP_SEND_NW_RE.search(l)  for l in blk['lines'])
        outgoing = sent_to_nw
        flow_records.append({
            'dialog_id':        did,
            'thread_type':      blk['thread_type'],
            'thread_id':        blk['thread_id'],
            'timestamp':        ts,
            'otid':             '',
            'dtid':             '',
            'msg_type':         '',
            'calling':          '',
            'called':           '',
            'app_name':         app_name,
            'direction':        'out' if outgoing else 'in',
            'forwarded_to_app': forwarded_to_app,
            'sent_to_nw':       sent_to_nw,
            'tcap_instance':    tcap_instance,
            'cs_instance':      cs_instance or 'CallService',
            'lines':            blk['lines'],
        })

    # Build the complete set of (fpath, line_no) positions to write
    relevant_positions: set[tuple] = set()

    # From Phase 1/2 blocks
    for blk in all_blocks:
        for pos in blk.get('positions', []):
            relevant_positions.add(pos)

    # From Phase 3 hex dump threads
    relevant_positions.update(hex_positions)

    logging.info("TcapServer: writing %d line(s) in original file order",
                 len(relevant_positions))

    # Sequential write: re-read files in sorted order, emit relevant lines in place
    for fpath in sorted(files):
        try:
            with open_file(fpath) as f:
                for line_no, raw in enumerate(f):
                    if (fpath, line_no) in relevant_positions:
                        out_handle.write(raw if raw.endswith('\n') else raw + '\n')
        except (IOError, OSError) as e:
            logging.error("Cannot re-read %s for output: %s", fpath, e)

    out_handle.write('\n')
    return found_dialog_ids, flow_records, tid_to_dialog


# ---------------------------------------------------------------------------
# TcapServerEvent simple grep
# ---------------------------------------------------------------------------

def process_tcap_events(file_pattern, search_terms, out_handle):
    """Simple grep extraction for TcapServerEvent log (tid + fsmid + dialog_ids)."""
    out_handle.write(f"\n{'='*20} SECTION: TcapServerEvent {'='*20}\n")
    terms = [t.lower() for t in search_terms if t]
    files = get_files(file_pattern)
    if not files:
        logging.warning("TcapServerEvent: no files for pattern %s", file_pattern)
        out_handle.write("  (no files found)\n\n")
        return
    for fpath in sorted(files):
        logging.info("TcapServerEvent: searching %s", fpath)
        try:
            with open_file(fpath) as f:
                for line in f:
                    if any(t in line.lower() for t in terms):
                        out_handle.write(line)
        except (IOError, OSError) as e:
            logging.error("Cannot read %s: %s", fpath, e)
    out_handle.write('\n\n')


# ---------------------------------------------------------------------------
# Transaction Summary Diagram (HTML)
# ---------------------------------------------------------------------------

def _detect_our_ips(detail_records: list, flow_records: list,
                    node_ip_map: dict = None) -> set:
    """Infer our node's Sigtran IPs from DetailedTrace direction + PCAP ip fields.

    When node_ip_map is provided (from --signode), use those IPs directly.
    Otherwise, pair each DetailedTrace record to the closest-timestamp PCAP record
    in the same dialog and tally IP candidates:
      direction='in'  → ip_dst is a candidate 'our IP'
      direction='out' → ip_src is a candidate 'our IP'
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


def _enrich_flow_records_from_pcap(flow_records, pcap_path, tcap_tids, tid_to_dialog):
    """Query pcap with tshark, extract 38 fields, store as pkt_rec['pcap'] dict.

    PCAP filter uses the original hex TCAP TIDs from CallService logs.
    tid_to_dialog maps each hex TID → decimal dialog ID.
    Direction is NOT fixed here — corrected in generate_transaction_html using our_ips.
    """
    if not tcap_tids or not tid_to_dialog:
        return

    filter_parts = []
    for tid in tcap_tids:
        hex_str = re.sub(r'[^0-9a-fA-F]', '', tid)
        if len(hex_str) == 8:
            colon = _tid_to_colon(hex_str)
            filter_parts.append(f'tcap.tid == {colon}')

    if not filter_parts:
        return

    try:
        cmd = [TSHARK_CMD, '-r', pcap_path,
               '-Y', ' || '.join(filter_parts),
               '-T', 'fields',
               '-e', 'frame.number',
               '-e', 'frame.time',
               '-e', 'ip.src',
               '-e', 'ip.dst',
               '-e', 'sctp.srcport',
               '-e', 'sctp.dstport',
               '-e', 'e212.imsi',
               '-e', 'mtp3.opc',
               '-e', 'mtp3.dpc',
               '-e', 'mtp3.ansi_opc',
               '-e', 'mtp3.ansi_dpc',
               '-e', 'm3ua.protocol_data_opc',
               '-e', 'm3ua.protocol_data_dpc',
               '-e', 'sccp.calling.digits',
               '-e', 'sccp.called.digits',
               '-e', 'sccp.calling.tt',
               '-e', 'sccp.called.tt',
               '-e', 'tcap.otid',
               '-e', 'tcap.dtid',
               '-e', 'tcap.invokeID',
               '-e', 'tcap.msgtype',
               '-e', 'tcap.opCode',
               '-e', 'tcap.p_abortCause',
               '-e', 'tcap.u_abortCause',
               '-e', 'tcap.errorCode',
               '-e', 'gsm_map.imsi',
               '-e', 'gsm_map.msisdn',
               '-e', 'gsm_old.opCode',
               '-e', 'gsm_old.errorCode',
               '-e', 'gsm_old.localValue',
               '-e', 'camel.serviceKey',
               '-e', 'camel.opcode',
               '-e', 'camel.errcode',
               '-e', 'camel.eventTypeBCSM',
               '-e', 'camel.monitorMode',
               '-e', '_ws.col.Protocol',
               '-e', '_ws.col.Info',
               '-e', 'e164.calling_party_number.digits',
               '-e', 'e164.called_party_number.digits',
               '-E', 'separator=\t']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        logging.warning("PCAP enrichment failed: %s", e)
        return

    all_dialog_ids = {r['dialog_id'] for r in flow_records if r.get('dialog_id')}
    pcap_data: dict = defaultdict(list)
    seen_frames: set = set()

    for line in result.stdout.splitlines():
        parts = line.split('\t')

        def _f(i):
            return parts[i].strip() if len(parts) > i else ''

        frame_no = _f(0)
        otid_raw = re.sub(r'[^0-9a-fA-F]', '', _f(17)).lower()
        dtid_raw = re.sub(r'[^0-9a-fA-F]', '', _f(18)).lower()

        if frame_no in seen_frames:
            continue
        seen_frames.add(frame_no)

        did = tid_to_dialog.get(otid_raw, '') or tid_to_dialog.get(dtid_raw, '')
        if not (did and did in all_dialog_ids):
            continue

        # OPC/DPC: MTP3 preferred, then ANSI, then M3UA
        opc = _f(7) or _f(9)  or _f(11)
        dpc = _f(8) or _f(10) or _f(12)
        # IMSI: e212 preferred, fallback gsm_map
        imsi = _f(6) or _f(25)

        pcap_data[did].append({
            'ts':         _f(1),
            'ip_src':     _f(2),   'ip_dst':     _f(3),
            'sctp_sp':    _f(4),   'sctp_dp':    _f(5),
            'imsi':       imsi,
            'opc':        opc,     'dpc':        dpc,
            'sccp_cg':    _f(13),  'sccp_cd':    _f(14),
            'cg_tt':      _f(15),  'cd_tt':      _f(16),
            'otid':       otid_raw,'dtid':       dtid_raw,
            'invoke_id':  _f(19),
            'tcap_mt':    _f(20),  'tcap_op':    _f(21),
            'p_abort':    _f(22),  'u_abort':    _f(23),
            'tcap_err':   _f(24),
            'map_msisdn': _f(26),  'map_op':     _f(27),
            'map_err':    _f(28),  'map_local':  _f(29),
            'cam_sk':     _f(30),  'cam_op':     _f(31),
            'cam_err':    _f(32),  'cam_bcasm':  _f(33),
            'cam_monmode':_f(34),
            'protocol':   _f(35),  'col_info':   _f(36),
            'e164_cg':    _f(37),  'e164_cd':    _f(38),
        })

    for did in all_dialog_ids:
        if did not in pcap_data:
            logging.warning("Dialog ID %s: no PCAP packets matched — "
                            "TcapServer log coverage may be incomplete", did)

    # Keep all TcapServer blocks unchanged; add exactly ONE pcap record per unique
    # PCAP frame per dialog_id (not one per TcapServer block — that was N×M duplication).
    new_records = list(flow_records)
    added_for_did: dict = defaultdict(set)  # {did: set of frame indices already added}

    for rec in flow_records:
        did = rec.get('dialog_id', '')
        if not did:
            continue
        for i, entry in enumerate(pcap_data.get(did, [])):
            if i in added_for_did[did]:
                continue
            added_for_did[did].add(i)
            pkt_rec = dict(rec)
            pkt_rec['source']      = 'pcap'
            pkt_rec['thread_type'] = 'network'
            pkt_rec['timestamp']   = entry['ts']
            pkt_rec['calling']     = entry['sccp_cg'] or rec.get('calling', '')
            pkt_rec['called']      = entry['sccp_cd'] or rec.get('called', '')
            pkt_rec['otid']        = entry['otid']
            pkt_rec['dtid']        = entry['dtid']
            pkt_rec['pcap']        = entry
            pkt_rec['direction']   = 'out' if entry['dtid'] else 'in'
            new_records.append(pkt_rec)
    flow_records[:] = new_records


def _parse_signode_ips(signode_args: list) -> dict:
    """Parse --signode args into {ip: node_name} map.

    Each arg may be "nodename:IP1,IP2" or
    "nodename1:IP1,IP2 nodename2:IP3,IP4" (space-separated specs in one arg).
    """
    if not signode_args:
        return {}
    result: dict = {}
    # Match one or more "name:ip1,ip2,..." tokens within a single arg.
    # Lookahead marks where the current token ends (next name: or end of string).
    _TOKEN_RE = re.compile(r'([\w][\w-]*):([\d.,\s]+?)(?=\s+[\w][\w-]*:|\s*$)')
    _IP_RE    = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
    for spec_group in signode_args:
        tokens = _TOKEN_RE.findall(spec_group.strip())
        if not tokens:
            logging.warning("--signode: ignoring malformed spec %r "
                            "(expected name:IP1,IP2 ...)", spec_group)
            continue
        for name, ips_str in tokens:
            name = name.strip()
            for ip in re.split(r'[\s,]+', ips_str.strip()):
                ip = ip.strip()
                if not ip:
                    continue
                if _IP_RE.match(ip):
                    result[ip] = name
                else:
                    logging.warning("--signode: ignoring invalid IP %r for node %r",
                                    ip, name)
    return result


def generate_transaction_html(flow_records, html_path, display_id,
                              pcap_path=None, tcap_tids=None, tid_to_dialog=None,
                              detail_records=None, node_ip_map=None,
                              correlation_meta=None):
    """Generate HTML with 4-participant mermaid sequence diagram per transaction.

    Participants: Remote Entity → SmartSTP → TCAP instance → CallService instance.
    Each normal message = 3 arrows. Anomalies highlighted red. Dark/light toggle + PNG copy.
    """
    if node_ip_map is None:
        node_ip_map = {}
    if detail_records is None:
        detail_records = []

    # Remap detail records whose dialog_id='0' (placeholder before real ID is assigned)
    # to the real dialog ID used by other records for the same FSMId.
    # e.g. SentBeginMAP gets logged with dialog_id=0; later events use the real dialog_id.
    _fsmid_real_did: dict = {}   # fsmid → first real (non-0, non-empty) dialog_id seen
    for _dr in detail_records:
        _dr_did = _dr.get('dialog_id', '')
        _dr_fid = _dr.get('fsmid', '')
        if _dr_did and _dr_did != '0' and _dr_fid and _dr_fid not in _fsmid_real_did:
            _fsmid_real_did[_dr_fid] = _dr_did
    for _dr in detail_records:
        if _dr.get('dialog_id', '') == '0':
            _real = _fsmid_real_did.get(_dr.get('fsmid', ''))
            if _real:
                _dr['dialog_id'] = _real

    # Map each dialog_id to the FSMId that owns it (from tagged detail records).
    did_to_fsmid: dict = {}
    for _dr in detail_records:
        _did = _dr.get('dialog_id', '')
        _fid = _dr.get('fsmid', '')
        if _did and _fid and _did not in did_to_fsmid:
            did_to_fsmid[_did] = _fid

    if pcap_path and os.path.exists(pcap_path) and tcap_tids and tid_to_dialog:
        _enrich_flow_records_from_pcap(flow_records, pcap_path,
                                       tcap_tids, tid_to_dialog)

    our_ips = _detect_our_ips(detail_records, flow_records, node_ip_map=node_ip_map)

    if our_ips:
        for r in flow_records:
            if r.get('source') == 'pcap':
                pcap = r.get('pcap', {})
                if pcap.get('ip_dst', '') in our_ips:
                    r['direction'] = 'in'
                elif pcap.get('ip_src', '') in our_ips:
                    r['direction'] = 'out'

    # PCAP lookup by dialog_id
    pcap_by_did: dict = defaultdict(list)
    for r in flow_records:
        if r.get('source') == 'pcap':
            did = r.get('dialog_id', '')
            if did:
                pcap_by_did[did].append(r)
    for lst in pcap_by_did.values():
        lst.sort(key=lambda x: x.get('timestamp', ''))

    # Instance metadata per dialog
    did_meta: dict = {}
    for r in flow_records:
        if r.get('source') != 'pcap':
            did = r.get('dialog_id', '')
            if did and did not in did_meta:
                did_meta[did] = {
                    'cs_instance':   r.get('cs_instance', 'CallService'),
                    'tcap_instance': r.get('tcap_instance', ''),
                }

    # Anomaly detection
    detail_dids_in = {r['dialog_id'] for r in detail_records
                      if r.get('direction') == 'in' and r.get('dialog_id')}
    anomaly_records: list = []
    for r in flow_records:
        if r.get('source') == 'pcap':
            continue
        if r.get('thread_type') != 'network':
            continue
        did = r.get('dialog_id', '')
        if did in detail_dids_in:
            continue
        if not r.get('forwarded_to_app', True):
            anomaly_type = 'direct_response' if r.get('sent_to_nw', False) else 'dropped'
            anom = dict(r)
            anom['source']        = 'anomaly'
            anom['anomaly']       = anomaly_type
            anom['remote_entity'] = anom.get('remote_entity', '') or 'Network'
            anomaly_records.append(anom)

    # TcapServer-only records: for cleanup FSMIds that send MAP transactions without
    # producing any DetailedTrace events. Scoped to known cleanup FSMIds to avoid
    # polluting the diagram with collateral TcapServer dialogs from nearby calls.
    _TCAP_DLG_FSMID_RE = re.compile(r'Dialog\s*\[\d+:([0-9a-fA-F]{10,})\]')
    _TCAP_MSG_TYPE_RE  = re.compile(r'(?:BEGIN|CONTINUE|END|UNIDIRECTIONAL)', re.IGNORECASE)
    all_detail_dids = {r.get('dialog_id', '') for r in detail_records if r.get('dialog_id')}
    _detail_fsmids  = {r.get('fsmid', '') for r in detail_records if r.get('fsmid')}
    # Only consider cleanup FSMIds as candidates (forwarded legs always have DetailTrace)
    _cleanup_fsmid_set: set = set()
    if correlation_meta:
        _cleanup_fsmid_set = {f.lower() for f in (correlation_meta.get('cleanup_fsmids') or [])}
    tcap_only_records: list = []
    for r in flow_records:
        if r.get('source') == 'pcap':
            continue
        did = r.get('dialog_id', '')
        if not did or did in all_detail_dids:
            continue
        # Infer FSMId and message type from TcapServer block lines
        blk_fsmid = ''
        msg_type_hint = ''
        for ln in r.get('lines', []):
            if not blk_fsmid:
                m_fid = _TCAP_DLG_FSMID_RE.search(ln)
                if m_fid:
                    blk_fsmid = m_fid.group(1).lower()
            if not msg_type_hint:
                m_mt = _TCAP_MSG_TYPE_RE.search(ln)
                if m_mt:
                    msg_type_hint = m_mt.group(0).capitalize()
        # Only show blocks from known cleanup FSMIds that lack DetailTrace coverage
        if not blk_fsmid or blk_fsmid not in _cleanup_fsmid_set:
            continue
        if blk_fsmid in _detail_fsmids:
            continue
        # Build a synthetic label: app_name or msg_type
        app_nm = r.get('app_name', '') or msg_type_hint or 'MAP'
        rec = dict(r)
        rec['source']        = 'tcap_only'
        rec['remote_entity'] = 'Network'
        rec['pcap']          = {}
        rec['event_name']    = app_nm
        rec['fsmid']         = blk_fsmid
        if blk_fsmid and did not in did_to_fsmid:
            did_to_fsmid[did] = blk_fsmid
        tcap_only_records.append(rec)

    def _ts_to_sec(ts: str) -> float:
        try:
            t = ts.strip()
            if 'T' in t:
                t = t.split('T', 1)[1].split(' ')[0]  # ISO: "YYYY-MM-DDTHH:MM:SS..." → "HH:MM:SS..."
            else:
                t = t.split(' ')[-1]                   # TcapServer: "... HH:MM:SS.mmm"
            h, mi, s = t[:12].split(':')
            return int(h) * 3600 + int(mi) * 60 + float(s)
        except Exception:
            return 0.0

    used_pcap_idxs: dict = defaultdict(set)

    def _best_pcap_entry(did: str, ref_ts: str) -> dict:
        candidates = [(i, r) for i, r in enumerate(pcap_by_did.get(did, []))
                      if i not in used_pcap_idxs[did]]
        if not candidates:
            return {}
        best_i, best_r = min(candidates,
                             key=lambda x: abs(_ts_to_sec(x[1].get('timestamp', ''))
                                               - _ts_to_sec(ref_ts)))
        used_pcap_idxs[did].add(best_i)
        return best_r.get('pcap', {})

    # Per-dialog, per-direction sorted list of (ts_sec, tcap_instance) from TcapServer
    # flow_records.  Lets each detail record get the TCAP instance that actually handled
    # that specific message rather than a single dialog-level fallback.
    _did_flows_in:  dict = defaultdict(list)   # did -> [(ts_sec, tcap_instance), ...]
    _did_flows_out: dict = defaultdict(list)   # did -> [(ts_sec, tcap_instance), ...]
    for _fr in flow_records:
        if _fr.get('source') == 'pcap':
            continue
        _fdid = _fr.get('dialog_id', '')
        if not _fdid:
            continue
        _fts = _ts_to_sec(_fr.get('timestamp', ''))
        _fti = _fr.get('tcap_instance', '') or 'TcapServer'
        if _fr.get('direction', 'in') == 'out':
            _did_flows_out[_fdid].append((_fts, _fti))
        else:
            _did_flows_in[_fdid].append((_fts, _fti))
    for _lst in _did_flows_in.values():
        _lst.sort()
    for _lst in _did_flows_out.values():
        _lst.sort()
    _used_fi: dict = defaultdict(set)
    _used_fo: dict = defaultdict(set)

    def _best_tcap(did: str, dirn: str, ref_sec: float) -> str:
        """Return the tcap_instance of the TcapServer block closest in time to ref_sec."""
        if dirn == 'out':
            flows, used = _did_flows_out[did], _used_fo[did]
        else:
            flows, used = _did_flows_in[did], _used_fi[did]
        candidates = [(i, f) for i, f in enumerate(flows) if i not in used]
        if not candidates:
            return did_meta.get(did, {}).get('tcap_instance', 'TcapServer')
        best_i, best_f = min(candidates, key=lambda x: abs(x[1][0] - ref_sec))
        used.add(best_i)
        return best_f[1]

    # Build all_msgs: detail + anomaly + orphaned PCAP
    all_msgs: list = []

    for r in detail_records:
        did    = r.get('dialog_id', '')
        meta   = did_meta.get(did, {})
        pentry = _best_pcap_entry(did, r.get('timestamp', ''))
        if pcap_by_did and not pentry:
            continue           # PCAP is authoritative — drop unmatched detail records
        merged = dict(r)
        merged['cs_instance']   = meta.get('cs_instance', 'CallService')
        merged['tcap_instance'] = _best_tcap(
            did, r.get('direction', 'in'), _ts_to_sec(r.get('timestamp', '')))
        merged['pcap']          = pentry
        if pentry.get('ts'):
            merged['timestamp'] = pentry['ts']
        all_msgs.append(merged)

    for r in anomaly_records:
        did    = r.get('dialog_id', '')
        meta   = did_meta.get(did, {})
        pentry = _best_pcap_entry(did, r.get('timestamp', ''))
        merged = dict(r)
        merged['cs_instance']   = meta.get('cs_instance', 'CallService')
        merged['tcap_instance'] = (r.get('tcap_instance')
                                   or meta.get('tcap_instance', 'TcapServer'))
        merged['pcap']          = pentry
        if merged['remote_entity'] == 'Network' and pentry:
            proto = pentry.get('protocol', '')
            if 'camel' in proto.lower():
                merged['remote_entity'] = 'Network-CAMEL'
            elif 'map' in proto.lower() or 'gsm' in proto.lower():
                merged['remote_entity'] = 'Network-MAP'
        if pentry.get('ts'):
            merged['timestamp'] = pentry['ts']
        all_msgs.append(merged)

    for r in tcap_only_records:
        did    = r.get('dialog_id', '')
        meta   = did_meta.get(did, {})
        merged = dict(r)
        merged['cs_instance']   = (r.get('cs_instance')
                                   or meta.get('cs_instance', 'CallService'))
        merged['tcap_instance'] = (r.get('tcap_instance')
                                   or meta.get('tcap_instance', 'TcapServer'))
        merged['pcap']          = {}
        all_msgs.append(merged)

    for did, recs in pcap_by_did.items():
        for i, r in enumerate(recs):
            if i not in used_pcap_idxs.get(did, set()):
                pentry = r.get('pcap', {})
                orphan = dict(r)
                orphan['source']        = 'pcap_orphan'
                orphan['pcap']          = pentry
                orphan['remote_entity'] = orphan.get('remote_entity', 'Network')
                meta = did_meta.get(did, {})
                orphan['cs_instance']   = meta.get('cs_instance', 'CallService')
                orphan['tcap_instance'] = meta.get('tcap_instance', '')
                orphan['timestamp']     = pentry.get('ts', r.get('timestamp', ''))
                all_msgs.append(orphan)

    # PCAP ip_src/ip_dst is authoritative for direction — override any DetailedTrace direction
    if our_ips:
        for r in all_msgs:
            pcap   = r.get('pcap', {})
            ip_src = pcap.get('ip_src', '')
            ip_dst = pcap.get('ip_dst', '')
            if ip_dst in our_ips:
                r['direction'] = 'in'
            elif ip_src in our_ips:
                r['direction'] = 'out'

    # Union-Find grouping into transactions
    parent = {}

    def _find(i):
        parent.setdefault(i, i)
        if parent[i] != i:
            parent[i] = _find(parent[i])
        return parent[i]

    def _union(i, j):
        ri, rj = _find(i), _find(j)
        if ri != rj:
            parent[ri] = rj

    for rec in all_msgs:
        o, d = rec.get('otid', ''), rec.get('dtid', '')
        if o and d:
            _union(o, d)

    transactions: dict = defaultdict(list)
    for rec in all_msgs:
        o, d = rec.get('otid', ''), rec.get('dtid', '')
        did  = rec.get('dialog_id', '')
        if did and did.isdigit():
            tx_key = f"Dialog-{did}"
        elif o or d:
            kt   = _find(o) if o else _find(d)
            comp = sorted({k for k in parent if _find(k) == kt})
            tx_key = ' - '.join(comp) if comp else kt
        elif did:
            tx_key = f"Dialog-{did}"
        else:
            tx_key = 'Unknown'
        transactions[tx_key].append(rec)

    # --- Inner helpers -------------------------------------------------------
    _SCTP_NOISE_RE = re.compile(r'^(?:(?:SACK|DATA)\s*\([^)]*\)\s*)+', re.IGNORECASE)

    def _op_name(r: dict) -> str:
        pcap = r.get('pcap', {})
        # col_info is Wireshark's own dissected label — always human-readable and correct
        info = _SCTP_NOISE_RE.sub('', pcap.get('col_info', '')).strip()
        if info:
            return info
        v = _decode_int(pcap.get('cam_op', ''))
        if v is not None:
            return CAMEL_OP_MAP.get(v, f"camel-op-{v}")
        v = _decode_int(pcap.get('map_op', ''))
        if v is None:
            v = _decode_int(pcap.get('tcap_op', ''))
        if v is not None:
            return MAP_OP_MAP.get(v, f"map-op-{v}")
        return r.get('event_name', '') or 'Message'

    def _build_arrow_label(r: dict, short: bool = False, network: bool = True) -> str:
        ts  = r.get('timestamp', '')
        _t  = ts.strip()
        if 'T' in _t:
            _t = _t.split('T', 1)[1].split(' ')[0]
        else:
            _t = _t.split(' ')[-1]
        ts_short = _t[:12]
        pcap     = r.get('pcap', {})
        op       = _op_name(r)

        parts_l = ([f"[{ts_short}]", op] if network else [op])

        anomaly = r.get('anomaly', '')
        if anomaly == 'dropped':
            parts_l.insert(1, '⚠ DROPPED')
        elif anomaly == 'direct_response':
            parts_l.insert(1, '⚠ DIRECT')

        return _sanitize_label(' '.join(parts_l))

    def _build_note(r: dict):
        """Return a single note string with all fields (network then app), or None."""
        pcap   = r.get('pcap', {})
        op     = _op_name(r)
        fields = []

        # ── network-layer ─────────────────────────────────────────────────
        cg    = pcap.get('sccp_cg', '') or r.get('cgpa', '')
        cd    = pcap.get('sccp_cd', '') or r.get('cdpa', '')
        cg_tt = pcap.get('cg_tt', '')
        cd_tt = pcap.get('cd_tt', '')
        if cg and cg != 'NA':
            tt_str = f" (TT:{cg_tt})" if cg_tt else ''
            fields.append(('SCCPCgPA', f"{cg}{tt_str}"))
        if cd:
            tt_str = f" (TT:{cd_tt})" if cd_tt else ''
            fields.append(('SCCPCdPA', f"{cd}{tt_str}"))

        otid = pcap.get('otid', '') or r.get('otid', '')
        dtid = pcap.get('dtid', '') or r.get('dtid', '')
        if otid:
            fields.append(('OTID', otid))
        if dtid:
            fields.append(('DTID', dtid))
        inv = pcap.get('invoke_id', '')
        if inv:
            fields.append(('InvID', inv))
        tcap_mt = pcap.get('tcap_mt', '')
        if tcap_mt:
            v = _decode_int(tcap_mt)
            fields.append(('TCAP', TCAP_MSGTYPE_MAP.get(v, tcap_mt) if v is not None else tcap_mt))

        anomaly = r.get('anomaly', '')
        if anomaly == 'dropped':
            fields.append(('⚠', 'NOT forwarded to CallService'))
        elif anomaly == 'direct_response':
            fields.append(('⚠', 'TcapServer responded directly to network'))

        # ── application-layer ────────────────────────────────────────────
        op_lo  = op.lower()
        dirn_r = r.get('direction', '').lower()

        if 'initialdp' in op_lo:
            imsi = pcap.get('imsi', '') or r.get('imsi', '')
            if imsi:
                fields.append(('IMSI', imsi))
            cg_num = pcap.get('e164_cg', '') or r.get('calling_number', '')
            cd_num = pcap.get('e164_cd', '') or r.get('called_number', '')
            if not cg_num:
                for ln in r.get('lines', []):
                    m = _CS_CALL_RE.search(ln)
                    if m:
                        cg_num, cd_num = m.group(1), m.group(2)
                        break
            if cg_num:
                fields.append(('CallingNumber', cg_num))
            if cd_num:
                fields.append(('CalledNumber', cd_num))
            # Forwarding reason for correlated (FTN) calls
            if correlation_meta:
                _rec_fsmid = r.get('fsmid', '')
                _fwd = (correlation_meta.get('fwd_fsmids') or {}).get(_rec_fsmid)
                if _fwd:
                    _reason_label = {'busy': 'Busy', 'no_reply': 'No Reply',
                                     'not_reachable': 'Not Reachable'}.get(_fwd[1], _fwd[1])
                    fields.append(('FwdReason', _reason_label))

        # MAP SendParameters request → IMSI sent to HLR
        if 'sendparameters' in op_lo and dirn_r == 'out':
            imsi_val = r.get('imsi', '') or pcap.get('imsi', '')
            if imsi_val:
                fields.append(('IMSI', imsi_val))

        # MAP SendParameters response → MSISDN and any forwarding numbers returned
        if 'sendparameters' in op_lo and dirn_r == 'in':
            hex_p = r.get('hex_payload', '')
            if hex_p:
                msisdn = _find_msisdn_from_hex(hex_p)
                if msisdn:
                    fields.append(('MSISDN', msisdn))
                ftns_sp = _find_ftns_from_hex(hex_p)
                if ftns_sp:
                    fields.append(('FTN', ', '.join(ftns_sp)))

        # InsertSubscriberData request → ForwardedToNumber list
        if 'insertsubscriberdata' in op_lo and dirn_r == 'out':
            hex_p = r.get('hex_payload', '')
            if hex_p:
                ftns_isd = _find_ftns_from_hex(hex_p)
                if ftns_isd:
                    fields.append(('FTN', ', '.join(ftns_isd)))

        if 'connect' in op_lo and 'requestreport' not in op_lo:
            conn_num = pcap.get('e164_cd', '') or r.get('connect_num', '')
            if not conn_num:
                for ln in r.get('lines', []):
                    m = _CS_CONNECT_RE.search(ln)
                    if m:
                        conn_num = m.group(1)
                        break
            if conn_num:
                fields.append(('ConnectedNumber', conn_num))

        if 'requestreport' in op_lo:
            # RRBCSM: show all monitored BCSM events decoded from hex payload
            hex_p = r.get('hex_payload', '')
            bcsm_ints = _find_bcsm_types_in_hex(hex_p) if hex_p else []
            if bcsm_ints:
                fields.append(('BCSMs', ', '.join(
                    BCASM_EVENT_MAP.get(v, str(v)) for v in bcsm_ints)))
            else:
                bcasm_val = pcap.get('cam_bcasm', '')
                if bcasm_val:
                    fields.append(('eventTypeBCSM', str(bcasm_val)))
            monmode_val = pcap.get('cam_monmode', '')
            if monmode_val:
                fields.append(('monitorMode', str(monmode_val)))

        elif 'eventreport' in op_lo:
            # ERBCSM: show the specific BCSM event that triggered
            erb_type = r.get('erb_bcsm_type', '')
            if erb_type:
                try:
                    v = int(erb_type)
                    fields.append(('BCSMEvent', BCASM_EVENT_MAP.get(v, str(v))))
                except ValueError:
                    fields.append(('BCSMEvent', erb_type))
            else:
                hex_p = r.get('hex_payload', '')
                m_b = re.search(r'(?i)8001([0-9a-f]{2})', hex_p) if hex_p else None
                if m_b:
                    v = int(m_b.group(1), 16)
                    fields.append(('BCSMEvent', BCASM_EVENT_MAP.get(v, str(v))))
                else:
                    bcasm_val = pcap.get('cam_bcasm', '')
                    if bcasm_val:
                        fields.append(('eventTypeBCSM', str(bcasm_val)))
            monmode_val = pcap.get('cam_monmode', '')
            if monmode_val:
                fields.append(('monitorMode', str(monmode_val)))

        cam_sk = pcap.get('cam_sk', '')
        if cam_sk:
            fields.append(('ServiceKey', cam_sk))

        for key, label in [('cam_err', 'CamelErr'), ('map_err', 'MapErr'),
                            ('p_abort', 'P-Abort'), ('u_abort', 'U-Abort'),
                            ('tcap_err', 'TcapErr')]:
            val = pcap.get(key, '')
            if val:
                fields.append((label, val))

        if not fields:
            return None
        return ' | '.join(f"{k}։{v}" for k, v in fields)

    def _mermaid(tx_flows: list) -> str:
        has_anomaly = any(r.get('source') == 'anomaly'     for r in tx_flows)
        has_orphan  = any(r.get('source') == 'pcap_orphan' for r in tx_flows)
        needs_tcap  = True  # TcapServer always shown: Network↔SmartSTP↔TcapServer↔CallService

        # Per-signode SPC tracking: {signode_name: {'physical': set(), 'alias': set()}}
        # ip.src in our_ips → physical OPC for that signode
        # ip.dst in our_ips → alias DPC for that signode
        signode_spcs: dict = {}
        remote_spcs:  set  = set()

        remote_entity_names: set = set()
        cs_names:   list = []
        tcap_names: list = []

        for r in tx_flows:
            ent = (r.get('remote_entity', '') or '').strip()
            if ent:
                remote_entity_names.add(ent)
            cs = (r.get('cs_instance',  'CallService') or 'CallService').strip()
            ti = (r.get('tcap_instance', '') or '').strip()
            if cs not in cs_names:
                cs_names.append(cs)
            if needs_tcap and ti and ti not in tcap_names:
                tcap_names.append(ti)

            pcap   = r.get('pcap', {})
            ip_src = pcap.get('ip_src', '')
            ip_dst = pcap.get('ip_dst', '')
            opc    = _decode_int(pcap.get('opc', ''))
            dpc    = _decode_int(pcap.get('dpc', ''))

            if ip_src in our_ips:
                node = (node_ip_map or {}).get(ip_src, 'SmartSTP')
                if node not in signode_spcs:
                    signode_spcs[node] = {'physical': set(), 'alias': set()}
                if opc is not None: signode_spcs[node]['physical'].add(opc)
                if dpc is not None: remote_spcs.add(dpc)
            elif ip_dst in our_ips:
                node = (node_ip_map or {}).get(ip_dst, 'SmartSTP')
                if node not in signode_spcs:
                    signode_spcs[node] = {'physical': set(), 'alias': set()}
                if dpc is not None: signode_spcs[node]['alias'].add(dpc)
                if opc is not None: remote_spcs.add(opc)
            else:
                if opc is not None: remote_spcs.add(opc)
                if dpc is not None: remote_spcs.add(dpc)

        # If --signode given but no PCAP data yet, seed from node_ip_map names
        if node_ip_map and not signode_spcs:
            for node in set(node_ip_map.values()):
                signode_spcs[node] = {'physical': set(), 'alias': set()}

        # Strip our own SPCs from remote_spcs
        our_all_spcs: set = set()
        for spcs in signode_spcs.values():
            our_all_spcs |= spcs['physical'] | spcs['alias']
        remote_spcs -= our_all_spcs

        # Physical wins over alias within the same signode
        for spcs in signode_spcs.values():
            spcs['alias'] -= spcs['physical']

        # Guarantee correct participant order: Remote → SmartSTP → TcapServer → CallService.
        # When our_ips detection fails (no --signode, no matching PCAP IPs) signode_spcs
        # stays empty; when tcap_instance is absent tcap_names stays [].  In both cases
        # the drawing loop still emits arrows using 'SmartSTP'/'TcapServer' as fallbacks,
        # but Mermaid would auto-create undeclared participants after CallService — making
        # inbound arrows appear to flow right-to-left.
        if not signode_spcs:
            signode_spcs['SmartSTP'] = {'physical': set(), 'alias': set()}
        if needs_tcap and not tcap_names:
            tcap_names.append('TcapServer')

        if len(remote_entity_names) == 1:
            remote_name = next(iter(remote_entity_names))
        elif remote_entity_names:
            known = {'SSP', 'HLR', 'VLR'}
            named = remote_entity_names & known
            remote_name = '/'.join(sorted(named)) if named else 'Remote'
        else:
            remote_name = 'Remote'

        def _fmt_spcs(spcs: set) -> str:
            parts = []
            for s in sorted(spcs):
                zone   = (s >> 11) & 0x7
                region = (s >> 3)  & 0xFF
                sp     = s         & 0x7
                parts.append(f"SPC:{zone}-{region}-{sp}/{s}")
            return ' | '.join(parts)

        # Calculate per-diagram actorMargin from the longest network-facing label
        _net_labels = [
            _build_arrow_label(r, network=True)
            for r in tx_flows
            if r.get('source') not in ('anomaly',)
        ]
        _max_chars = max((len(l) for l in _net_labels), default=30)
        # ~7px per char at 18px font; clamp 10–80px
        _actor_margin = max(10, min(80, _max_chars * 7 // 10))
        _init = (f'%%{{init: {{"sequence":{{"actorMargin":{_actor_margin},'
                 f'"messageMargin":10,"noteMargin":6,"fontSize":18,'
                 f'"noteFontSize":14,"wrap":true,"mirrorActors":true}}}}}}%%')

        lines = [_init, "sequenceDiagram"]
        # 1. Remote participant — short name only (SPC in footnote)
        lines.append(f"    participant {_sanitize_id(remote_name)} as {remote_name}")
        import re as _re
        def _display_node_name(name: str) -> str:
            return _re.sub(r'(?i)^signode(\d+)$', r'SignallingNode\1', name)

        # 2. One participant per signode — short name only (SPC in footnote)
        for node in sorted(signode_spcs):
            display_node = _display_node_name(node)
            lines.append(f"    participant {_sanitize_id(node)} as {display_node}")
        # 3. TcapServer instances
        for ti in tcap_names:
            ti_label = f"{ti} ⚠" if has_anomaly else ti
            lines.append(f"    participant {_sanitize_id(ti)} as {ti_label}")
        # 4. CallService instances
        for cs in cs_names:
            lines.append(f"    participant {_sanitize_id(cs)} as {cs}")

        for r in sorted(tx_flows, key=lambda x: _ts_to_sec(x.get('timestamp', ''))):
            src_type = r.get('source', 'detail')
            dirn     = r.get('direction', 'in')
            cs       = (r.get('cs_instance', 'CallService') or 'CallService').strip()
            ti       = (r.get('tcap_instance', '') or 'TcapServer').strip()
            label    = _build_arrow_label(r)
            ent_p    = _sanitize_id(remote_name)
            cs_p     = _sanitize_id(cs)
            ti_p     = _sanitize_id(ti)
            # Resolve which signode this record belongs to via PCAP IP
            pcap_r   = r.get('pcap', {})
            _ip_src  = pcap_r.get('ip_src', '')
            _ip_dst  = pcap_r.get('ip_dst', '')
            _node    = ((node_ip_map or {}).get(_ip_src)
                        or (node_ip_map or {}).get(_ip_dst)
                        or (next(iter(sorted(signode_spcs))) if signode_spcs else 'SmartSTP'))
            stp_p    = _sanitize_id(_node)
            anomaly  = r.get('anomaly', '')

            if src_type == 'anomaly':
                label_int = _build_arrow_label(r, network=False)
                if anomaly == 'dropped':
                    lines.append(f"    {ent_p}->>{stp_p}: {label}")
                    lines.append(f"    {stp_p}->>{ti_p}: {label_int}")
                elif anomaly == 'direct_response':
                    lines.append(f"    {ent_p}->>{stp_p}: {label}")
                    lines.append(f"    {stp_p}->>{ti_p}: {label_int}")
                    lines.append(f"    {ti_p}-->>{stp_p}: ⚠ DIRECT RESPONSE")
                    lines.append(f"    {stp_p}-->>{ent_p}: ⚠ DIRECT RESPONSE")
            elif src_type == 'pcap_orphan':
                arrow = '->>' if dirn == 'in' else '-->>'
                lines.append(f"    {ent_p}{arrow}{stp_p}: {label}")
            else:
                label_int = _build_arrow_label(r, network=False)
                if dirn == 'in':
                    lines.append(f"    {ent_p}->>{stp_p}: {label}")
                    lines.append(f"    {stp_p}->>{ti_p}: {label_int}")
                    lines.append(f"    {ti_p}->>{cs_p}: {label_int}")
                else:
                    lines.append(f"    {cs_p}-->>{ti_p}: {label_int}")
                    lines.append(f"    {ti_p}-->>{stp_p}: {label_int}")
                    lines.append(f"    {stp_p}-->>{ent_p}: {label}")

            note = _build_note(r)
            if note:
                note_end = ti_p if src_type in ('anomaly', 'pcap_orphan') else cs_p
                lines.append(f"    Note over {ent_p},{note_end}: {_sanitize_label(note)}")

        return '\n'.join(lines)

    # --- HTML ----------------------------------------------------------------
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Call Flow: {display_id}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  :root {{
    --bg:#1e1e2e;--surface:#313244;--border:#45475a;--text:#cdd6f4;
    --muted:#6c7086;--accent:#89b4fa;--h2:#89dceb;
  }}
  body.light {{
    --bg:#eff1f5;--surface:#ffffff;--border:#ccd0da;--text:#4c4f69;
    --muted:#9ca0b0;--accent:#1e66f5;--h2:#179299;
  }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; font-size:16px; background:var(--bg);
          color:var(--text); margin:0; padding:20px;
          transition:background .25s,color .25s; }}
  h1   {{ font-size:1.3rem; color:var(--accent); margin-bottom:4px; }}
  .tx-header {{ display:flex; align-items:baseline;
                justify-content:space-between; flex-wrap:wrap; gap:10px;
                border-bottom:1px solid var(--border); padding-bottom:8px; margin-bottom:6px; }}
  .tx-header h2 {{ font-size:1.05rem; color:var(--h2); margin:0; }}
  .tx-box {{ background:var(--surface); border:1px solid var(--border);
             border-radius:10px; padding:20px 24px; margin-bottom:32px; }}
  .mermaid {{ background:var(--bg); border-radius:8px; padding:16px;
              overflow-x:auto; transition:background .25s; }}
  hr.sep {{ border:none; border-top:2px dashed var(--border); margin:24px 0; }}
  #toolbar {{ position:fixed; top:14px; right:18px; z-index:999;
              display:flex; gap:8px; }}
  .tb-btn {{ background:var(--surface); border:1px solid var(--border);
             color:var(--text); border-radius:18px; padding:5px 14px;
             font-size:.8rem; cursor:pointer; white-space:nowrap;
             transition:background .15s; }}
  .tb-btn:hover {{ background:var(--accent); color:#fff; border-color:var(--accent); }}
  .copy-btn {{ background:var(--surface); border:1px solid var(--border);
               color:var(--text); border-radius:6px; padding:3px 10px;
               font-size:.74rem; cursor:pointer; transition:background .15s; }}
  .copy-btn:hover {{ background:var(--accent); color:#fff; }}
</style>
</head>
<body>
<div id="toolbar">
  <button class="tb-btn" id="copy-all-btn" onclick="copyAll(this)">📷 Copy All</button>
  <button class="tb-btn" id="theme-btn"    onclick="toggleTheme()">☀️ Light</button>
</div>
<h1>Call Flow: {display_id}</h1>
""".format(display_id=display_id)

    # Correlation banner (shown when forwarded legs or cleanup FSMIds were found)
    if correlation_meta and (correlation_meta.get('fwd_fsmids')
                             or correlation_meta.get('cleanup_fsmids')):
        cm = correlation_meta
        fwd_rows = ''
        for fwd_id, (ftn, reason) in (cm.get('fwd_fsmids') or {}).items():
            reason_label = {'busy': 'Busy', 'no_reply': 'No Reply',
                            'not_reachable': 'Not Reachable'}.get(reason, reason)
            fwd_rows += (
                f'<tr>'
                f'<td style="padding:2px 12px;font-family:monospace">{fwd_id}</td>'
                f'<td style="padding:2px 12px">{reason_label}</td>'
                f'<td style="padding:2px 12px;font-family:monospace">{ftn}</td>'
                f'</tr>\n'
            )
        ftn_summary = ' &nbsp;|&nbsp; '.join(filter(None, [
            (f'busy={cm["busy"]}'              if cm.get('busy')          else ''),
            (f'noReply={cm["no_reply"]}'       if cm.get('no_reply')      else ''),
            (f'notReachable={cm["not_reachable"]}' if cm.get('not_reachable') else ''),
        ]))
        fwd_section = ''
        if fwd_rows:
            fwd_section = (
                f'<p style="margin:2px 0 6px;color:var(--muted)">FTNs: {ftn_summary}</p>'
                '<table style="border-collapse:collapse;font-size:.83rem">'
                '<tr><th style="text-align:left;padding:2px 12px">Forwarded FSMId</th>'
                '<th style="text-align:left;padding:2px 12px">Forward Reason</th>'
                '<th style="text-align:left;padding:2px 12px">FTN</th></tr>'
                + fwd_rows + '</table>'
            )
        cln_rows = ''
        for cln_id in (cm.get('cleanup_fsmids') or []):
            cln_rows += (
                f'<tr>'
                f'<td style="padding:2px 12px;font-family:monospace">{cln_id}</td>'
                f'<td style="padding:2px 12px">RESTORE-ISD-SENT-FROM-CLEANUPRULE</td>'
                f'</tr>\n'
            )
        cln_section = ''
        if cln_rows:
            cln_section = (
                '<p style="margin:10px 0 4px;font-weight:600">Cleanup FSMIds</p>'
                '<table style="border-collapse:collapse;font-size:.83rem">'
                '<tr><th style="text-align:left;padding:2px 12px">Cleanup FSMId</th>'
                '<th style="text-align:left;padding:2px 12px">Trigger</th></tr>'
                + cln_rows + '</table>'
            )
        html += (
            '<details open style="margin-bottom:18px;font-size:.85rem;'
            'background:var(--surface);border:1px solid var(--border);'
            'border-radius:8px;padding:10px 16px">'
            '<summary style="cursor:pointer;font-weight:600;color:var(--accent)">'
            '&#9432; VMCC Forwarding Correlation</summary>'
            f'<p style="margin:6px 0 4px">Primary: <code>{display_id}</code>'
            f' &nbsp;|&nbsp; A#: <code>{cm.get("a_number","")}</code>'
            f' &nbsp;|&nbsp; IMSI: <code>{cm.get("imsi","")}</code></p>'
            + fwd_section + cln_section +
            '</details>\n'
        )

    for t_idx, (tx_key, tx_flows) in enumerate(transactions.items()):
        has_anom = any(r.get('source') == 'anomaly' for r in tx_flows)

        # Collect remote IP → SPC and local node → SPC mapping for footnote
        remote_ip_spcs:  dict = defaultdict(set)
        local_node_spcs: dict = {}
        our_all_spcs:    set  = set()
        for r in tx_flows:
            pcap   = r.get('pcap', {})
            ip_src = pcap.get('ip_src', '')
            ip_dst = pcap.get('ip_dst', '')
            opc    = _decode_int(pcap.get('opc', ''))
            dpc    = _decode_int(pcap.get('dpc', ''))
            if ip_src in our_ips:
                if opc: our_all_spcs.add(opc)
                node = (node_ip_map or {}).get(ip_src, 'SmartSTP')
                if node not in local_node_spcs:
                    local_node_spcs[node] = {'physical': set(), 'alias': set()}
                if opc is not None: local_node_spcs[node]['physical'].add(opc)
            else:
                if ip_src and opc: remote_ip_spcs[ip_src].add(opc)
            if ip_dst in our_ips:
                if dpc: our_all_spcs.add(dpc)
                node = (node_ip_map or {}).get(ip_dst, 'SmartSTP')
                if node not in local_node_spcs:
                    local_node_spcs[node] = {'physical': set(), 'alias': set()}
                if dpc is not None: local_node_spcs[node]['alias'].add(dpc)
            else:
                if ip_dst and dpc: remote_ip_spcs[ip_dst].add(dpc)
        for spcs in remote_ip_spcs.values():
            spcs -= our_all_spcs
        for spcs in local_node_spcs.values():
            spcs['alias'] -= spcs['physical']

        mmd      = _mermaid(tx_flows)

        if has_anom:
            lines_out = []
            in_anom   = False
            for ln in mmd.splitlines():
                is_anom = '⚠ DROPPED' in ln or '⚠ DIRECT' in ln
                if is_anom and not in_anom:
                    lines_out.append('    rect rgba(255,80,80,0.15)')
                    in_anom = True
                elif in_anom and not is_anom and ln.strip():
                    stripped = ln.strip()
                    if not stripped.startswith(('Note', 'rect', 'end', 'participant',
                                                'sequenceDiagram', '⚠')):
                        lines_out.append('    end')
                        in_anom = False
                lines_out.append(ln)
            if in_anom:
                lines_out.append('    end')
            mmd = '\n'.join(lines_out)

        # Node SPC footnote (local signalling nodes + remote nodes)
        _node_to_ips: dict = {}
        for _ip, _nm in (node_ip_map or {}).items():
            _node_to_ips.setdefault(_nm, []).append(_ip)
        for _v in _node_to_ips.values():
            _v.sort()

        import re as _re_fn
        def _fn_display_node(name: str) -> str:
            return _re_fn.sub(r'(?i)^signode(\d+)$', r'SignallingNode\1', name)

        def _fn_spc_str(spcs_set: set) -> str:
            return ', '.join(
                f"SPC:{((s>>11)&0x7)}-{((s>>3)&0xFF)}-{(s&0x7)}/{s}"
                for s in sorted(spcs_set) if s
            )

        footnote = ''
        local_rows = ''
        for node in sorted(local_node_spcs):
            phys_str  = _fn_spc_str(local_node_spcs[node]['physical'])
            alias_str = _fn_spc_str(local_node_spcs[node]['alias'])
            if phys_str or alias_str:
                ip_list = ', '.join(_node_to_ips.get(node, []))
                local_rows += (
                    f'<tr>'
                    f'<td style="padding:2px 12px;font-family:monospace">{_fn_display_node(node)}</td>'
                    f'<td style="padding:2px 12px;font-family:monospace">{ip_list or "—"}</td>'
                    f'<td style="padding:2px 12px;font-family:monospace">{phys_str or "—"}</td>'
                    f'<td style="padding:2px 12px;font-family:monospace">{alias_str or "—"}</td>'
                    f'</tr>\n'
                )

        remote_rows = ''
        for ip in sorted(remote_ip_spcs):
            spcs_str = _fn_spc_str(remote_ip_spcs[ip])
            if spcs_str:
                remote_rows += (
                    f'<tr>'
                    f'<td style="padding:2px 12px;font-family:monospace">{ip}</td>'
                    f'<td style="padding:2px 12px;font-family:monospace;colspan=2">{spcs_str}</td>'
                    f'</tr>\n'
                )

        if local_rows or remote_rows:
            table_html = '<table style="border-collapse:collapse;margin-top:6px;width:100%">'
            if local_rows:
                table_html += (
                    '<tr><th style="text-align:left;padding:4px 12px;color:var(--accent)"'
                    ' colspan="4">Local Signalling Nodes</th></tr>'
                    '<tr>'
                    '<th style="text-align:left;padding:2px 12px">Node</th>'
                    '<th style="text-align:left;padding:2px 12px">IP Address(es)</th>'
                    '<th style="text-align:left;padding:2px 12px">Physical SPCs</th>'
                    '<th style="text-align:left;padding:2px 12px">Alias SPCs</th>'
                    '</tr>'
                    + local_rows
                )
            if remote_rows:
                sep = '<tr><td colspan="4" style="padding:6px 0"></td></tr>' if local_rows else ''
                table_html += (
                    sep
                    + '<tr><th style="text-align:left;padding:4px 12px;color:var(--accent)"'
                    ' colspan="4">Remote Nodes</th></tr>'
                    '<tr>'
                    '<th style="text-align:left;padding:2px 12px">IP Address</th>'
                    '<th style="text-align:left;padding:2px 12px" colspan="3">SPCs observed</th>'
                    '</tr>'
                    + remote_rows
                )
            table_html += '</table>'
            footnote = (
                '<details style="margin-top:8px;font-size:.8rem;color:var(--muted)">'
                '<summary style="cursor:pointer">&#9654; Node SPC Reference</summary>'
                + table_html + '</details>'
            )

        # Collect all BCASM integer values seen across this transaction for the legend
        bcasm_ints_seen: set = set()
        for r in tx_flows:
            bv = r.get('pcap', {}).get('cam_bcasm', '')
            if bv:
                for tok in str(bv).split(','):
                    tok = tok.strip()
                    v = _decode_int(tok)
                    if v is not None:
                        bcasm_ints_seen.add(v)

        bcasm_legend = ''
        if bcasm_ints_seen:
            legend_rows = ''.join(
                f'<tr>'
                f'<td style="padding:2px 10px;font-family:monospace;text-align:right">{n}</td>'
                f'<td style="padding:2px 10px">{BCASM_EVENT_MAP.get(n, "unknown")}</td>'
                f'</tr>'
                for n in sorted(bcasm_ints_seen)
            )
            bcasm_legend = (
                '<details style="font-size:.8rem;color:var(--muted)">'
                '<summary style="cursor:pointer">&#9654; EventTypeBCSM Legend</summary>'
                '<table style="border-collapse:collapse;margin-top:6px">'
                '<tr><th style="text-align:right;padding:2px 10px">#</th>'
                '<th style="text-align:left;padding:2px 10px">Name</th></tr>'
                + legend_rows + '</table></details>'
            )

        # Collect monitorMode values seen in this transaction
        monmode_ints_seen: set = set()
        for r in tx_flows:
            mv = r.get('pcap', {}).get('cam_monmode', '')
            if mv:
                for tok in str(mv).split(','):
                    tok = tok.strip()
                    v = _decode_int(tok)
                    if v is not None:
                        monmode_ints_seen.add(v)

        monmode_legend = ''
        if monmode_ints_seen:
            monmode_rows = ''.join(
                f'<tr>'
                f'<td style="padding:2px 10px;font-family:monospace;text-align:right">{n}</td>'
                f'<td style="padding:2px 10px">{MONITOR_MODE_MAP.get(n, "unknown")}</td>'
                f'</tr>'
                for n in sorted(monmode_ints_seen)
            )
            monmode_legend = (
                '<details style="font-size:.8rem;color:var(--muted)">'
                '<summary style="cursor:pointer">&#9654; MonitorMode Legend</summary>'
                '<table style="border-collapse:collapse;margin-top:6px">'
                '<tr><th style="text-align:right;padding:2px 10px">#</th>'
                '<th style="text-align:left;padding:2px 10px">Name</th></tr>'
                + monmode_rows + '</table></details>'
            )

        bottom_bar = (
            '<div style="display:flex;justify-content:space-between;align-items:flex-start;'
            'gap:20px;margin-top:8px;flex-wrap:wrap">'
            + footnote
            + bcasm_legend
            + monmode_legend
            + '</div>'
        ) if (footnote or bcasm_legend or monmode_legend) else ''

        safe_key = tx_key.replace('"', '&quot;').replace('<', '&lt;')
        # Annotate with FSMId when multiple FSMIds are present
        _tx_fsmid = ''
        if did_to_fsmid:
            _tx_did = tx_key[7:] if tx_key.startswith('Dialog-') else ''
            if _tx_did:
                _tx_fsmid = did_to_fsmid.get(_tx_did, '')
            if not _tx_fsmid:
                for _r in tx_flows:
                    _f = _r.get('fsmid', '')
                    if _f:
                        _tx_fsmid = _f
                        break
        # Build label: show FSMId + role suffix (Forwarded reason or Cleanup)
        _fsmid_role = ''
        if _tx_fsmid and correlation_meta:
            _fwd = (correlation_meta.get('fwd_fsmids') or {}).get(_tx_fsmid)
            if _fwd:
                _fsmid_role = ' — ' + {'busy': 'Busy', 'no_reply': 'No Reply',
                                        'not_reachable': 'Not Reachable'}.get(_fwd[1], _fwd[1])
            elif _tx_fsmid in (correlation_meta.get('cleanup_fsmids') or []):
                _fsmid_role = ' — Cleanup'
        _fsmid_tag = (f' <span style="font-size:.8em;font-weight:normal;'
                      f'color:var(--muted)">({_tx_fsmid}{_fsmid_role})</span>'
                      if _tx_fsmid else '')
        html += f"""
  <div class="tx-box">
    <div class="tx-header">
      <h2>Transaction: {safe_key}{_fsmid_tag}</h2>
      <button class="copy-btn" onclick="copyDiagram(this)">📷 Copy</button>
    </div>
    <div class="mermaid">
{mmd}
    </div>
    {bottom_bar}
  </div>
"""
        if t_idx < len(transactions) - 1:
            html += '  <hr class="sep" />\n'

    html += """
<script>
  let isDark = true;
  function mermaidCfg(theme) {
    return { startOnLoad:false, theme,
             sequence:{ mirrorActors:true, useMaxWidth:false, fontSize:18 } };
  }
  async function renderAll(theme) {
    mermaid.initialize(mermaidCfg(theme));
    document.querySelectorAll('.mermaid').forEach(el => {
      if (!el.dataset.src) el.dataset.src = el.textContent.trim();
      el.removeAttribute('data-processed');
      el.innerHTML = el.dataset.src;
    });
    await mermaid.run({ nodes: document.querySelectorAll('.mermaid') });
    document.querySelectorAll('.mermaid svg').forEach(svg => {
      const vb = svg.viewBox && svg.viewBox.baseVal;
      if (vb && vb.width && vb.height) {
        // Expand viewBox/height to capture content Mermaid places at the boundary
        let h = vb.height;
        try { const bb = svg.getBBox(); h = Math.max(h, bb.y + bb.height + 10); } catch(_) {}
        svg.setAttribute('width',  vb.width + 'px');
        svg.setAttribute('height', h + 'px');
        if (h > vb.height) svg.setAttribute('viewBox', `${vb.x} ${vb.y} ${vb.width} ${h}`);
      }
      svg.removeAttribute('style');
      svg.style.display = 'block';
    });
  }
  function toggleTheme() {
    isDark = !isDark;
    document.body.classList.toggle('light', !isDark);
    document.getElementById('theme-btn').textContent = isDark ? '☀️ Light' : '🌙 Dark';
    renderAll(isDark ? 'dark' : 'default');
  }
  function flash(btn, orig) {
    btn.textContent = '✅ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1800);
  }
  function flashErr(btn, orig) {
    btn.textContent = '❌ Failed';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  }
  function svgToPng(svg) {
    return new Promise((res, rej) => {
      const vb  = svg.viewBox && svg.viewBox.baseVal;
      const r   = svg.getBoundingClientRect();
      const vbW = (vb && vb.width)  || r.width  || 900;
      const vbH = (vb && vb.height) || r.height || 500;
      // getBBox() gives the actual content bounding box, which may exceed the
      // declared viewBox when Mermaid places bottom actor boxes at the edge.
      // Inline SVG shows this overflow; a blob-URL <img> clips to the viewBox.
      let contentH = vbH;
      try {
        const bb = svg.getBBox();
        contentH = Math.max(vbH, bb.y + bb.height + 10);
      } catch(_) {}
      const w  = Math.ceil(vbW);
      const h  = Math.ceil(contentH);
      const sc = 2;
      const clone = svg.cloneNode(true);
      clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      clone.setAttribute('width',  w);
      clone.setAttribute('height', h);
      // Expand the viewBox so the bottom actor boxes are included in the image
      clone.setAttribute('viewBox', `${(vb && vb.x) || 0} ${(vb && vb.y) || 0} ${w} ${h}`);
      const url = URL.createObjectURL(
        new Blob([new XMLSerializer().serializeToString(clone)],
                 {type:'image/svg+xml;charset=utf-8'}));
      const img = new Image();
      img.onload = () => {
        const c = document.createElement('canvas');
        c.width = w*sc; c.height = h*sc;
        const ctx = c.getContext('2d');
        ctx.scale(sc,sc);
        ctx.fillStyle = isDark ? '#1e1e2e' : '#eff1f5';
        ctx.fillRect(0,0,w,h);
        ctx.drawImage(img,0,0,w,h);
        URL.revokeObjectURL(url);
        res({canvas:c, h:h*sc});
      };
      img.onerror = e => { URL.revokeObjectURL(url); rej(e); };
      img.src = url;
    });
  }
  async function copyDiagram(btn) {
    const orig = '📷 Copy';
    const svg  = btn.closest('.tx-box')?.querySelector('.mermaid svg');
    if (!svg) return;
    try {
      const {canvas} = await svgToPng(svg);
      canvas.toBlob(async blob => {
        await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
        flash(btn, orig);
      }, 'image/png');
    } catch(e) { flashErr(btn, orig); }
  }
  async function copyAll(btn) {
    const orig = '📷 Copy All';
    const svgs = [...document.querySelectorAll('.mermaid svg')];
    if (!svgs.length) return;
    try {
      const results = await Promise.all(svgs.map(svgToPng));
      const gap  = 32;
      const maxW = Math.max(...results.map(r => r.canvas.width));
      const totH = results.reduce((s,r) => s + r.canvas.height + gap, -gap);
      const combined = document.createElement('canvas');
      combined.width = maxW; combined.height = totH;
      const ctx = combined.getContext('2d');
      ctx.fillStyle = isDark ? '#1e1e2e' : '#eff1f5';
      ctx.fillRect(0,0,maxW,totH);
      let y = 0;
      for (const {canvas} of results) {
        ctx.drawImage(canvas, Math.floor((maxW-canvas.width)/2), y);
        y += canvas.height + gap;
      }
      combined.toBlob(async blob => {
        await navigator.clipboard.write([new ClipboardItem({'image/png':blob})]);
        flash(btn, orig);
      }, 'image/png');
    } catch(e) { flashErr(btn, orig); }
  }
  document.addEventListener('DOMContentLoaded', () => renderAll('dark'));
</script>
</body>
</html>
"""

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[*] HTML report: {html_path}")


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Extract logs and packets for a call identified by its FSMId.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "MANDATORY arguments:  -f/--trace (at least one), -i\n"
            "CONDITIONAL mandatory:\n"
            "  -z  required when -p is given (PCAP timestamp window needs explicit timezone)\n"
            "  -t  required when --html is given\n"
            "Backward compat: --summary and --detail are accepted as aliases for --trace.\n"
        ),
    )
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
    parser.add_argument("-i", "--id",       required=True,
                        help="[MANDATORY] FSMId / StateMachineId to extract")
    parser.add_argument("-m", "--main",     required=False, default=None,
                        help="Glob pattern for main CallService log file(s). "
                             "Omit to use trace-based PCAP extraction only.")
    parser.add_argument("-o", "--output-dir", default="logs",
                        help="Output directory (default: logs/)")
    parser.add_argument("-p", "--pcaps", default=None,
                        help="Glob pattern for PCAP capture file(s). "
                             "[MANDATORY with -p]: -z/--timezone must also be supplied.")
    parser.add_argument("-z", "--timezone", default=None,
                        help="[MANDATORY when -p is used] Timezone of the log system. "
                             "Accepts IANA names (\"America/Mexico_City\") or fixed UTC "
                             "offsets (\"-0500\", \"+0530\", \"UTC-5\"). Use a fixed offset "
                             "when IANA DST rules differ from the actual system. "
                             "Run 'date +\"%%z\"' on the log system to find the value.")
    parser.add_argument("-t",  "--tcap", default=None,
                        help="Glob for TcapServer log file(s). "
                             "[MANDATORY when --html is used]")
    parser.add_argument("-te", "--tcap-event", default=None, dest="tcap_event",
                        help="Glob for TcapServerEvent log file(s) (optional)")
    parser.add_argument("-n", "--testcase", default=None,
                        help="Test case name prefix for output filenames (optional)")
    parser.add_argument("-v", "--debug", action="store_true",
                        help="Enable verbose debug logging")
    parser.add_argument("--html", action="store_true",
                        help="Generate HTML mermaid sequence diagram. "
                             "[MANDATORY with --html]: -t/--tcap must also be supplied.")
    parser.add_argument("--signode", action="append", dest="signodes", default=None,
                        metavar="NAME:IP1,IP2",
                        help="Signalling node name and its Sigtran IPs (repeatable). "
                             "Example: --signode 'signode1:172.26.131.18,172.26.131.19'. "
                             "Used for PCAP direction detection; overrides auto-detection.")

    args = parser.parse_args()

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

    if args.pcaps and not args.timezone:
        print(
            "\nERROR: -z/--timezone is required when -p (PCAP extraction) is used.\n"
            "Run the following on the log system to get its UTC offset:\n\n"
            '    date +"%z"\n\n'
            "Then re-run with:  -z <offset>  e.g.  -z \"+0400\"\n",
            file=sys.stderr)
        sys.exit(1)

    try:
        setup_logging(args.debug, args.output_dir)
    except (IOError, OSError) as e:
        print(f"Failed to setup logging: {e}", file=sys.stderr)
        sys.exit(1)

    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    if args.testcase:
        base_name = f"{args.testcase.replace(' ', '_')}-{args.id}-extract-{date_str}"
    else:
        base_name = f"TestCase-{args.id}-{date_str}"
    log_output_path = os.path.join(args.output_dir, f"{base_name}.txt")
    node_ip_map: dict = _parse_signode_ips(args.signodes)
    if node_ip_map:
        logging.info("Explicit signode IPs: %s", node_ip_map)

    # Discover correlated FSMIds from DNISCallsMap FTN forwarding (one level).
    corr_meta: dict = {}
    correlated_fsmids: list = []
    if args.main and _summary_patterns and _detail_glob:
        correlated_fsmids, corr_meta = discover_correlated_fsmids(
            args.main, args.id, _summary_patterns, _detail_glob)
    _seen_ids = {args.id.lower()}
    _fwd_list = [f for f in correlated_fsmids if f.lower() not in _seen_ids
                 and not _seen_ids.add(f.lower())]
    _cln_list = [f for f in (corr_meta.get('cleanup_fsmids') or [])
                 if f.lower() not in _seen_ids and not _seen_ids.add(f.lower())]
    all_fsmids: list = [args.id] + _fwd_list + _cln_list
    if len(all_fsmids) > 1:
        logging.info("Extracting %d FSMId(s): %s", len(all_fsmids), ', '.join(all_fsmids))

    flow_records:            list = []
    tcap_tids:               list = []
    tid_to_dialog:           dict = {}
    detail_records_for_html: list = []
    tcap_pcap_path                = None

    try:
        _sum_pats   = [p for p in args.trace if _is_summary_trace(p)]
        _det_pats   = [p for p in args.trace if _is_detail_trace(p)]
        _other_pats = [p for p in args.trace
                       if not _is_summary_trace(p) and not _is_detail_trace(p)]
        _multi = len(all_fsmids) > 1

        with open(log_output_path, 'w') as out_file:
            # 1. Summary trace — all FSMIds
            for _fsmid in all_fsmids:
                for _pattern in _sum_pats:
                    _header = _extract_trace_prefix(_pattern)
                    _section = f"{_header} [{_fsmid}]" if _multi else _header
                    process_simple_search(_pattern, _fsmid, _section, out_file)

            # 2. Detailed trace — all FSMIds
            for _fsmid in all_fsmids:
                for _pattern in _det_pats:
                    _header = _extract_trace_prefix(_pattern)
                    _section = f"{_header} [{_fsmid}]" if _multi else _header
                    process_simple_search(_pattern, _fsmid, _section, out_file)

            # 3. Other trace patterns (if any) — all FSMIds
            for _fsmid in all_fsmids:
                for _pattern in _other_pats:
                    _header = _extract_trace_prefix(_pattern)
                    _section = f"{_header} [{_fsmid}]" if _multi else _header
                    process_simple_search(_pattern, _fsmid, _section, out_file)

            # 4. Main callservice logs — all FSMIds
            if args.main:
                for _fsmid in all_fsmids:
                    _mlabel = f"Log Extract [{_fsmid}]" if _multi else 'Log Extract'
                    process_main_log(args.main, _fsmid, out_file, section_label=_mlabel)

            # --- TcapServer extraction (runs inside the same output file) ---
            if args.tcap:
                out_file.flush()   # ensure all log output is on disk before reading it back
                tcap_tids = extract_tids(log_output_path)
                # Supplement: cleanup FSMIds don't emit otid/dtid in callservice log,
                # so seed their TIDs directly from TcapServer log bracket patterns.
                _cln_ids = corr_meta.get('cleanup_fsmids') or []
                if _cln_ids:
                    _cln_tids = extract_tids_from_tcap_for_fsmids(args.tcap, _cln_ids)
                    if _cln_tids:
                        logging.info("Cleanup FSMId TID supplement: %s", _cln_tids)
                        tcap_tids = sorted(set(tcap_tids) | set(_cln_tids))
                logging.info("TcapServer search: %d TCAP TID(s)", len(tcap_tids))

                # Generate TcapServer PCAP first — needed for Phase 3 timestamp matching
                tcap_pcap_path = None
                if tcap_tids:
                    tcap_pcap_path = os.path.join(
                        args.output_dir, f"{base_name}_tcap.pcap")
                    process_tcap_pcap(args.tcap, tcap_tids, tcap_pcap_path)
                    if not os.path.exists(tcap_pcap_path) or os.path.getsize(tcap_pcap_path) <= 24:
                        tcap_pcap_path = None

                dialog_ids, flow_records, tid_to_dialog = process_tcap_logs(
                    args.tcap, tcap_tids, out_file,
                    tcap_pcap_path=tcap_pcap_path)

                if args.tcap_event:
                    search_terms = (
                        {f.lower() for f in all_fsmids}
                        | {t.replace(':', '') for t in tcap_tids}
                        | dialog_ids
                    )
                    process_tcap_events(args.tcap_event, search_terms, out_file)

            if _detail_glob:
                for _fsmid in all_fsmids:
                    detail_records_for_html += parse_detail_trace_records(
                        _detail_glob, _fsmid)
                logging.info("DetailedTrace: %d in/out records (all FSMIds)",
                             len(detail_records_for_html))

        print(f"Log extraction complete. Output written to: {log_output_path}")
    except (IOError, OSError) as e:
        logging.error("Failed to write output file: %s", e)
        print(f"Error: Could not write to {log_output_path}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logging.error("Unexpected error during extraction: %s", e)
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

    pcap_output_path = None
    if args.pcaps:
        pcap_output_path = os.path.join(args.output_dir, f"{base_name}.pcap")
        if args.main:
            extra_tids = []
            tz_for_trace = None
            pcap_files = sorted(glob.glob(args.pcaps))
            if pcap_files:
                if args.timezone:
                    try:
                        tz_for_trace = _parse_timezone(args.timezone)
                    except Exception:
                        pass
                summary_fields = []
                if _summary_glob:
                    for _fsmid in all_fsmids:
                        summary_fields += parse_summary_trace_fields(_summary_glob, _fsmid)
                detail_sccp = []
                if _detail_glob:
                    for _fsmid in all_fsmids:
                        detail_sccp += parse_detail_trace_sccp_fields(_detail_glob, _fsmid)
                trace_filter, t_min, t_max = build_trace_based_filter(
                    summary_fields, detail_sccp, tz_for_trace)
                if trace_filter:
                    pass1_filter = trace_filter
                    if t_min is not None and t_max is not None:
                        pass1_filter = (f'({trace_filter}) && '
                                        f'frame.time_epoch >= {t_min - 1.0:.3f} && '
                                        f'frame.time_epoch <= {t_max + 1.0:.3f}')
                    logging.info("Trace-based supplementary filter: %s", pass1_filter)
                    extra_tids = _extract_tids_dechunked(pcap_files, pass1_filter)
            first_ts, last_ts = _detail_trace_epoch_window(
                detail_records_for_html, tz_for_trace)
            if first_ts is not None:
                logging.info("DetailedTrace window for PCAP filter: %.3f – %.3f",
                             first_ts, last_ts)
            process_pcap(log_output_path, args.pcaps, pcap_output_path,
                         extra_tids=extra_tids or None,
                         first_ts=first_ts, last_ts=last_ts)
        else:
            if not args.timezone:
                print(
                    "\nERROR: -z/--timezone is required when -m (callservice logs) is not provided.\n"
                    "Run the following on the log system to get its UTC offset:\n\n"
                    '    date +"%z"\n\n'
                    "Then re-run with:  -z <offset>  e.g.  -z \"-0500\"\n",
                    file=sys.stderr)
                sys.exit(1)
            tz = None
            try:
                tz = _parse_timezone(args.timezone)
            except Exception as e:
                logging.error("Invalid --timezone %r: %s", args.timezone, e)
                sys.exit(1)
            process_pcap_from_traces(
                _summary_glob or '', _detail_glob or '', args.id, args.pcaps, pcap_output_path, tz)

    # --- HTML Transaction Summary Diagram ----------------------------------
    if args.html and args.tcap and (flow_records or detail_records_for_html):
        html_path = os.path.join(args.output_dir, f"{base_name}.html")
        generate_transaction_html(flow_records, html_path, args.id,
                                  pcap_path=pcap_output_path,
                                  tcap_tids=tcap_tids,
                                  tid_to_dialog=tid_to_dialog,
                                  detail_records=detail_records_for_html,
                                  node_ip_map=node_ip_map,
                                  correlation_meta=corr_meta if corr_meta else None)

    if tcap_pcap_path and os.path.exists(tcap_pcap_path):
        os.remove(tcap_pcap_path)
        logging.debug("Removed intermediate TcapServer PCAP: %s", tcap_pcap_path)


if __name__ == "__main__":
    print(
        "\nWARNING: extract-callservice-logs.py is deprecated.\n"
        "Use extract-sds7-logs.py instead — same flags, actively maintained.\n",
        file=sys.stderr,
    )
    main()
