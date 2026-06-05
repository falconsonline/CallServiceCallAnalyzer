"""
hexlog2pcap - Generic hex-dump-to-pcap conversion framework.

Architecture:
    LogParser      - parse a log file/stream → yield RawPacket
    ProtocolDecoder - decode RawPacket hex   → yield DecodedPacket
    PcapBackend    - write DecodedPackets    → .pcap file
    Hex2PcapConverter - orchestrates the pipeline

Extend by subclassing LogParser and/or ProtocolDecoder, then register
your classes with register_parser() / register_decoder() so the
convenience function convert() and the CLI can find them.

Quick usage
-----------
    import hexlog2pcap
    hexlog2pcap.convert("app.log", "out", parser="dk", decoder="sccp")

Extending
---------
    class MyParser(hexlog2pcap.LogParser):
        def parse(self, lines):
            for line in lines:
                if "HEX:" in line:
                    yield hexlog2pcap.RawPacket(hex_data=line.split("HEX:")[1].strip())

    class MyDecoder(hexlog2pcap.ProtocolDecoder):
        link_type = 1   # Ethernet
        def decode(self, pkt):
            clean = hexlog2pcap.clean_hex(pkt.hex_data)
            return hexlog2pcap.DecodedPacket(
                timestamp=pkt.timestamp,
                hex_bytes=hexlog2pcap.format_hex_bytes(clean),
            )

    hexlog2pcap.register_parser("myapp", MyParser)
    hexlog2pcap.register_decoder("raw",   MyDecoder)
    hexlog2pcap.convert("app.log", "out", parser="myapp", decoder="raw")
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Type


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def clean_hex(hex_str: str) -> str:
    """Strip every non-hex character from a string."""
    return re.sub(r'[^a-fA-F0-9]', '', hex_str)


def format_hex_bytes(hex_str: str) -> str:
    """Turn a raw hex string into a space-separated byte string: 'deadbeef' → 'de ad be ef'."""
    h = clean_hex(hex_str)
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RawPacket:
    """Hex payload plus context extracted by a LogParser."""
    hex_data: str = ""
    timestamp: str = ""            # opaque string forwarded to text2pcap
    metadata: dict = field(default_factory=dict)


@dataclass
class DecodedPacket:
    """A fully assembled packet ready to write through a PcapBackend."""
    hex_bytes: str                 # space-separated hex, e.g. "09 82 03 04 …"
    timestamp: str = ""
    byte_offset: int = 0
    link_type: Optional[int] = None  # overrides decoder default when set


# ---------------------------------------------------------------------------
# Abstract bases
# ---------------------------------------------------------------------------

class LogParser(ABC):
    """
    Parse a log file and yield RawPackets.

    Subclasses only need to implement parse().  The converter calls
    parse(file_lines) and iterates the result.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _dbg(self, msg: str) -> None:
        if self.verbose:
            print(f"[PARSER] {msg}")

    @abstractmethod
    def parse(self, lines: Iterable[str]) -> Iterator[RawPacket]:
        """Yield one RawPacket per logical hex chunk found in *lines*."""


class ProtocolDecoder(ABC):
    """
    Decode the hex payload in a RawPacket into a wire-format DecodedPacket.

    Subclasses must set *link_type* (PCAP DLT value) and implement decode().
    Return None to discard a packet.
    """

    #: PCAP link-layer type (DLT_*) used by text2pcap's -l flag.
    link_type: int = 1  # DLT_EN10MB fallback

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _dbg(self, msg: str) -> None:
        if self.verbose:
            print(f"[DECODER] {msg}")

    @abstractmethod
    def decode(self, packet: RawPacket) -> Optional[DecodedPacket]:
        """Return a DecodedPacket or None to skip this packet."""


# ---------------------------------------------------------------------------
# Pcap backend
# ---------------------------------------------------------------------------

class PcapBackend(ABC):
    """Writes decoded packets to a pcap file."""

    @abstractmethod
    def write(self, packets: Iterable[DecodedPacket], outfile: str, link_type: int, timeformat: str) -> int:
        """Write packets; return the number written."""


class Text2PcapBackend(PcapBackend):
    """
    Default backend: writes a text2pcap-compatible hex dump to a temp file,
    then invokes text2pcap to produce the final .pcap.
    """

    DEFAULT_BINARY = "/opt/homebrew/bin/text2pcap"

    def __init__(self, binary: Optional[str] = None, verbose: bool = False):
        self.binary = binary or self._find_text2pcap()
        self.verbose = verbose

    # ------------------------------------------------------------------
    def _find_text2pcap(self) -> str:
        found = shutil.which("text2pcap") or self.DEFAULT_BINARY
        return found

    def write(self, packets: Iterable[DecodedPacket], outfile: str, link_type: int, timeformat: str) -> int:
        tmpfile = re.sub(r'\.pcap$', '', outfile) + ".txt"
        count = 0
        with open(tmpfile, 'w') as f:
            for pkt in packets:
                ltype = pkt.link_type if pkt.link_type is not None else link_type
                prefix = (f"{pkt.timestamp} {pkt.byte_offset:04x} "
                          if pkt.timestamp else f"{pkt.byte_offset:04x} ")
                f.write(f"{prefix}{pkt.hex_bytes} \n")
                count += 1

        if count == 0:
            return 0

        cmd = [self.binary, "-l", str(link_type), "-t", timeformat, tmpfile, outfile]
        if self.verbose:
            print(f"[BACKEND] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] text2pcap error:\n{result.stderr}", file=sys.stderr)
        return count


# ---------------------------------------------------------------------------
# Converter (pipeline orchestrator)
# ---------------------------------------------------------------------------

class Hex2PcapConverter:
    """
    Orchestrates LogParser → ProtocolDecoder → PcapBackend.

    Parameters
    ----------
    parser      : LogParser instance
    decoder     : ProtocolDecoder instance
    infile      : input log path
    outfile     : output path; '.pcap' appended when missing
    verbose     : enable debug output
    backend     : PcapBackend instance (default: Text2PcapBackend)
    timeformat  : strftime-style format string forwarded to text2pcap
    """

    DEFAULT_TIMEFORMAT = "%a-%b-%d|%H:%M:%S.%f"

    def __init__(
        self,
        parser: LogParser,
        decoder: ProtocolDecoder,
        infile: str,
        outfile: str,
        verbose: bool = False,
        backend: Optional[PcapBackend] = None,
        timeformat: str = DEFAULT_TIMEFORMAT,
    ):
        self.parser = parser
        self.decoder = decoder
        self.infile = infile
        self.outfile = outfile if outfile.endswith(".pcap") else f"{outfile}.pcap"
        self.verbose = verbose
        self.backend = backend or Text2PcapBackend(verbose=verbose)
        self.timeformat = timeformat

    def _dbg(self, msg: str) -> None:
        if self.verbose:
            print(f"[CONVERTER] {msg}")

    def run(self) -> int:
        """Run the full pipeline; return the number of packets written."""
        print(f"[*] Input : {self.infile}")
        print(f"[*] Output: {self.outfile}")

        with open(self.infile, 'r', errors='ignore') as fh:
            raw_packets = self.parser.parse(fh)
            decoded: List[DecodedPacket] = []
            for raw in raw_packets:
                pkt = self.decoder.decode(raw)
                if pkt is not None:
                    decoded.append(pkt)

        self._dbg(f"{len(decoded)} packets decoded")

        if not decoded:
            print("[!] No valid packets detected.")
            return 0

        count = self.backend.write(
            decoded,
            self.outfile,
            self.decoder.link_type,
            self.timeformat,
        )
        print(f"[+] Done: {self.outfile}  ({count} packets)")
        return count


# ---------------------------------------------------------------------------
# DK log parser  (concrete)
# ---------------------------------------------------------------------------

class DKLogParser(LogParser):
    """
    Parses Dialogic/DK SS7 log files.

    Handles four patterns (matching dk2pcap.pl):
      • Multi-line packets identified by an 8-hex-digit thread ID and a
        Type [8742] or [c740] header line.
      • Legacy single-line  M-t<type>…-p<hex>  patterns.
      • GCT single-line     M-I<hex>-t<type>…-p(<hex>)<hex>  patterns.
      • Inline hex-dump lines: date|time|lvl|thread|HH HH HH… (Perl patterns
        10/14 — DKSS7Interface, AbstractSS7Interface, GLR logs). Hex bytes are
        accumulated across consecutive matching lines; flushed on the first
        non-hex line (equivalent to Perl's else { AnalyzeDKPacket($completeMsg) }).
    """

    _TS_RE          = re.compile(r'([A-Z][a-z]{2})\s+([A-Z][a-z]{2})\s+(\d{2})\|(\d{2}:\d{2}:\d{2})(?:\.(\d+))?')
    _HDR_RE         = re.compile(r'\|([0-9A-F]{8})\|.*Type \[(8742|c740)\]', re.IGNORECASE)
    _LEGACY_RE      = re.compile(r'M-t(?:8742|c740|C740|cf00|8f01).*?-p([0-9a-fA-F]+)', re.IGNORECASE)
    _GCT_RE         = re.compile(r'M-I[0-9a-fA-F]+-t(?:010a|8742|c740).*?-p\([0-9a-fA-F]+\)([0-9a-fA-F]+)')
    
    _NTR_RE         = re.compile(r'(?:Sent|Received|Sending)\s*:\s*([0-9a-fA-F]+)\|?', re.IGNORECASE)
    _DK_S7L_RE      = re.compile(r'S7L:.*t(?:8742|c740|cf00|0f16).*?p(?:[0-9a-fA-F]{8})?([0-9a-fA-F]+)', re.IGNORECASE)
    _NTR_PROBE_RE   = re.compile(r'\|[0-9a-fA-F]+\|SIF=([0-9a-fA-F]+)\|', re.IGNORECASE)
    _SMARTSTP_UDTS_RE = re.compile(r'^\d{4}-\d{2}-\d{2},\d{2}:\d{2}:\d{2}.*,([0-9a-fA-F]+)')
    _NTR_INPUT_RE   = re.compile(r'^\d{2}-\d{2}-\d{4},\d{2}:\d{2}:\d{2}\.\d{3}.*,([0-9a-fA-F]+)')
    _DKPROBE_RE     = re.compile(r'LINK \[\w+\].*SIO\[\w+\]:\s*([0-9a-fA-F ]+)\|', re.IGNORECASE)
    _PURE_HEX_RE    = re.compile(r'^([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)')

    # Matches message field that starts with one or more space-separated hex byte pairs
    _INLINE_HEX_RE  = re.compile(r'^([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)')

    def parse(self, lines: Iterable[str]) -> Iterator[RawPacket]:
        logtime: str = ""
        current_thread: Optional[str] = None
        hex_buffer: str = ""

        def _flush() -> Iterator[RawPacket]:
            nonlocal hex_buffer, current_thread
            if hex_buffer:
                yield RawPacket(hex_data=hex_buffer, timestamp=logtime)
            hex_buffer = ""
            current_thread = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # --- timestamp ---------------------------------------------------
            ts = self._TS_RE.search(line)
            if ts:
                day_name, mon_str, day_num, hms, sub = ts.groups()
                sub_val = (sub or "0").ljust(6, '0')[:6]
                logtime = f"{day_name}-{mon_str}-{day_num}|{hms}.{sub_val}"

            # --- multi-line header (Type [8742]) -----------------------------
            hdr = self._HDR_RE.search(line)
            if hdr:
                yield from _flush()
                current_thread = hdr.group(1)
                self._dbg(f"Header found, thread {current_thread}")
                continue

            # --- single-line legacy / GCT / generic patterns ------------------
            m_leg = self._LEGACY_RE.search(line)
            m_gct = self._GCT_RE.search(line)
            m_ntr = self._NTR_RE.search(line)
            m_s7l = self._DK_S7L_RE.search(line)
            m_npr = self._NTR_PROBE_RE.search(line)
            m_sst = self._SMARTSTP_UDTS_RE.search(line)
            m_nin = self._NTR_INPUT_RE.search(line)
            m_dkp = self._DKPROBE_RE.search(line)

            match = m_leg or m_gct or m_ntr or m_s7l or m_npr or m_sst or m_nin or m_dkp
            if match:
                yield from _flush()
                # For _GCT_RE, the data is in group(1). For all others, it's group(1).
                # _GCT_RE actually has group(1) and group(2), but group(1) is the inner hex.
                # Wait, original code: data = (m_leg or m_gct).group(1)
                data = match.group(1) if match.lastindex == 1 else match.group(match.lastindex)
                self._dbg(f"Single-line packet, {len(clean_hex(data))//2} bytes")
                yield RawPacket(hex_data=clean_hex(data), timestamp=logtime)
                continue

            # --- multi-line body (Type [8742] thread-header mode) ------------
            if current_thread:
                if current_thread in line:
                    part = re.search(rf'{current_thread}\|([0-9a-fA-F ]+)', line)
                    if part:
                        hex_buffer += clean_hex(part.group(1))
                        continue
                # Line doesn't belong to this thread → flush and fall through
                yield from _flush()

            # --- inline hex-dump (Perl patterns 10/14) -----------------------
            # Format: date|time|lvl|thread|HH HH HH …  ASCII  |file|.|lineno
            # Accumulate bytes; flushed when a non-hex line is encountered.
            parts = line.split('|')
            if len(parts) >= 5:
                m_hex = self._INLINE_HEX_RE.match(parts[4].strip())
                if m_hex:
                    hex_buffer += clean_hex(m_hex.group(1))
                    self._dbg(f"Inline hex: +{len(clean_hex(m_hex.group(1)))//2}B")
                    continue
            elif len(parts) == 1:
                # Fallback for pure hex lines (like TcapServer logs)
                m_pure = self._PURE_HEX_RE.match(line)
                if m_pure:
                    hex_buffer += clean_hex(m_pure.group(1))
                    self._dbg(f"Pure hex: +{len(clean_hex(m_pure.group(1)))//2}B")
                    continue

            # --- non-matching line: flush accumulated buffer -----------------
            yield from _flush()

        yield from _flush()


# ---------------------------------------------------------------------------
# SCCP decoder  (concrete)
# ---------------------------------------------------------------------------

class SCCPDecoder(ProtocolDecoder):
    """
    Decodes a DK-internal TLV envelope into an SCCP wire packet.

    DLT value 142 = DLT_MTP3_WITH_SCCP (used by Wireshark for SCCP).
    """

    link_type = 142  # DLT_MTP3_WITH_SCCP

    # Map DK message-type byte → SCCP message type
    _MTYPE_MAP = {1: 0x09, 2: 0x09, 3: 0x0a}

    def decode(self, packet: RawPacket) -> Optional[DecodedPacket]:
        buf = clean_hex(packet.hex_data)
        if len(buf) < 2:
            return None

        m_type = int(buf[0:2], 16)
        s_type = self._MTYPE_MAP.get(m_type)
        if s_type is None:
            return None

        cdpa = cgpa = payload = ""
        p_class = ret_cause = 0
        codeshift = 1
        idx = 2

        while idx < len(buf):
            try:
                tag    = int(buf[idx:idx+2], 16)
                length = int(buf[idx+2:idx+4], 16)
                vs     = idx + 4            # value start

                if tag == 1:
                    if int(buf[vs:vs+2], 16) == 1:
                        p_class |= 0x80
                elif tag == 2:
                    p_class |= 0x01
                elif tag == 4:
                    cgpa = buf[vs : vs + length * 2]
                elif tag == 5:
                    cdpa = buf[vs : vs + length * 2]
                elif tag == 6:
                    if codeshift == 2:
                        length  = (length << 8) + int(buf[vs:vs+2], 16)
                        payload = buf[vs + 2 : vs + 2 + length * 2]
                        idx    += 2
                    else:
                        payload = buf[vs : vs + length * 2]
                elif tag == 7:
                    ret_cause = int(buf[vs:vs+2], 16)
                elif tag == 255:
                    codeshift = int(buf[vs:vs+2], 16) + 1
                    s_type    = 0x11 if s_type == 0x09 else 0x12

                extra  = len(payload) if (tag == 6 and codeshift == 2) else length * 2
                idx   += 4 + extra
            except Exception:
                break

        hex_bytes = self._assemble(s_type, p_class, ret_cause, cdpa, cgpa, payload)
        self._dbg(f"s_type=0x{s_type:02x} cdpa={len(cdpa)//2}B cgpa={len(cgpa)//2}B pay={len(payload)//2}B")

        return DecodedPacket(
            hex_bytes=hex_bytes,
            timestamp=packet.timestamp,
            byte_offset=0,
        )

    def _assemble(self, p_type, p_class, ret_cause, cdpa, cgpa, payload) -> str:
        cdpa_len = len(cdpa) // 2
        cgpa_len = len(cgpa) // 2
        pay_len  = len(payload) // 2

        parts = [
            f"{p_type:02x}",
            f"{p_class:02x}" if p_type in (0x09, 0x11) else f"{ret_cause:02x}",
            "03",
            f"{3 + cdpa_len:02x}",
            f"{3 + cdpa_len + cgpa_len:02x}",
            f"{cdpa_len:02x}",
            format_hex_bytes(cdpa),
            f"{cgpa_len:02x}",
            format_hex_bytes(cgpa),
            f"{pay_len:02x}",
            format_hex_bytes(payload),
        ]
        return " ".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# MTP Raw decoder  (concrete)
# ---------------------------------------------------------------------------

class RawMTPDecoder(ProtocolDecoder):
    """
    Decodes pure MTP2/MTP3 payloads by simply returning the hex data as-is.
    
    DLT value 141 = DLT_MTP3 (used by Wireshark for MTP3).
    """

    link_type = 141  # DLT_MTP3

    def decode(self, packet: RawPacket) -> Optional[DecodedPacket]:
        buf = clean_hex(packet.hex_data)
        if not buf:
            return None

        return DecodedPacket(
            hex_bytes=format_hex_bytes(buf),
            timestamp=packet.timestamp,
            byte_offset=0,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_PARSERS:  Dict[str, Type[LogParser]]        = {"dk": DKLogParser}
_DECODERS: Dict[str, Type[ProtocolDecoder]]  = {"sccp": SCCPDecoder, "mtp": RawMTPDecoder}


def register_parser(name: str, cls: Type[LogParser]) -> None:
    """Register a LogParser subclass under *name* for use by convert() and the CLI."""
    _PARSERS[name] = cls


def register_decoder(name: str, cls: Type[ProtocolDecoder]) -> None:
    """Register a ProtocolDecoder subclass under *name* for use by convert() and the CLI."""
    _DECODERS[name] = cls


def list_parsers()  -> List[str]: return list(_PARSERS)
def list_decoders() -> List[str]: return list(_DECODERS)


# ---------------------------------------------------------------------------
# High-level convenience function
# ---------------------------------------------------------------------------

def convert(
    infile: str,
    outfile: str,
    parser:  str = "dk",
    decoder: str = "sccp",
    verbose: bool = False,
    text2pcap_path: Optional[str] = None,
    timeformat: str = Hex2PcapConverter.DEFAULT_TIMEFORMAT,
    backend: Optional[PcapBackend] = None,
) -> int:
    """
    Convert *infile* to *outfile*.pcap using the named parser and decoder.

    Parameters
    ----------
    infile          : path to the input log file
    outfile         : base path for output (e.g. "capture" → "capture.pcap")
    parser          : registered parser name (default "dk")
    decoder         : registered decoder name (default "sccp")
    verbose         : enable debug output
    text2pcap_path  : override path to the text2pcap binary
    timeformat      : strftime format forwarded to text2pcap
    backend         : custom PcapBackend instance; default uses Text2PcapBackend

    Returns
    -------
    Number of packets written.

    Raises
    ------
    ValueError  if *parser* or *decoder* are not registered.
    """
    parser_cls  = _PARSERS.get(parser)
    decoder_cls = _DECODERS.get(decoder)
    if parser_cls is None:
        raise ValueError(f"Unknown parser {parser!r}. Available: {list_parsers()}")
    if decoder_cls is None:
        raise ValueError(f"Unknown decoder {decoder!r}. Available: {list_decoders()}")

    _parser  = parser_cls(verbose=verbose)
    _decoder = decoder_cls(verbose=verbose)
    _backend = backend or Text2PcapBackend(binary=text2pcap_path, verbose=verbose)

    return Hex2PcapConverter(
        parser=_parser,
        decoder=_decoder,
        infile=infile,
        outfile=outfile,
        verbose=verbose,
        backend=_backend,
        timeformat=timeformat,
    ).run()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_cli_parser():
    import argparse
    ap = argparse.ArgumentParser(
        prog="hexlog2pcap",
        description="Convert hex-dump logs to .pcap. "
                    "Extend by registering custom parsers/decoders.",
    )
    ap.add_argument("infile",  nargs="?", help="Input log file")
    ap.add_argument("outfile", nargs="?", help="Output base name (e.g. 'capture' → 'capture.pcap')")
    ap.add_argument("-p", "--parser",  default="dk",   help="Log parser   (default: dk)")
    ap.add_argument("-d", "--decoder", default="sccp", help="Protocol decoder (default: sccp)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--text2pcap", metavar="PATH", help="Path to text2pcap binary")
    ap.add_argument("--timeformat", default=Hex2PcapConverter.DEFAULT_TIMEFORMAT,
                    help="Timestamp format for text2pcap")
    ap.add_argument("--list", action="store_true", help="List registered parsers/decoders and exit")
    return ap


def main(argv=None):
    ap = _build_cli_parser()
    args = ap.parse_args(argv)

    if args.list:
        print("Parsers :", ", ".join(list_parsers()))
        print("Decoders:", ", ".join(list_decoders()))
        return

    if not args.infile or not args.outfile:
        ap.error("infile and outfile are required (unless --list is used)")

    try:
        convert(
            infile=args.infile,
            outfile=args.outfile,
            parser=args.parser,
            decoder=args.decoder,
            verbose=args.verbose,
            text2pcap_path=args.text2pcap,
            timeformat=args.timeformat,
        )
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
