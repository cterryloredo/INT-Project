#!/usr/bin/env python3
"""
INT-XD telemetry collector.

Listens for In-band Network Telemetry (INT) reports exported in eXport-Data (XD)
mode and decodes them. Keeps a raw hex dump but also parses the Telemetry Report
fixed header and the encapsulated original packet's 5-tuple, so each report is
actually readable.

Usage:
    python intxd-collector.py                 # listen on 0.0.0.0:6001
    python intxd-collector.py --port 6001     # custom port
    python intxd-collector.py --raw           # raw hex dump only, no parsing
    python intxd-collector.py --pcap out.txt  # also append hex to a log file
"""

from __future__ import annotations  # allow `dict | None` hints on Python 3.9 (jumpserver)

import argparse
import socket
import struct
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime

# Set from --influx in main(); when not None, decoded reports are written to
# InfluxDB v2 as line protocol. dict(url, token, org, bucket).
INFLUX = None

# Batched writes: buffer line-protocol points and flush in one POST after
# INFLUX_BATCH points or INFLUX_PERIOD seconds. One POST per report does not
# keep up at high rates (~1000+ reports/s) and drops UDP datagrams.
INFLUX_BATCH = 200
INFLUX_PERIOD = 1.0
_influx_buf = []
_influx_last_flush = 0.0

# Quiet mode prints a one-line throughput summary every SUMMARY_PERIOD seconds
# instead of dumping every report (per-report print/hexdump is the bottleneck at
# high rates — it stalls parsing and the upstream tcpdump pipe drops packets).
SUMMARY_PERIOD = 2.0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def hexdump(data: bytes, width: int = 16) -> str:
    """Offset / hex / ASCII dump, like `xxd`."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {off:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def parse_report_header(data: bytes) -> dict:
    """
    Best-effort parse of the Telemetry Report fixed header.

    Two layouts are common. Adjust the branch that matches your lab's INT spec:
      - v0.5  (p4lang int.p4): 16-byte fixed header, ver in the top nibble.
      - v2.0/2.1: 8-byte group header (ver/hw_id/seq/node_id).

    Returns a dict of decoded fields plus the byte offset where the inner
    (encapsulated) original packet starts.
    """
    if len(data) < 8:
        return {"error": "too short for any report header"}

    ver = (data[0] >> 4) & 0xF

    if ver >= 2:
        # --- Telemetry Report v2.0 group header (8 bytes) ---
        word0, node_id = struct.unpack("!II", data[:8])
        hw_id = (word0 >> 22) & 0x3F
        seq = word0 & 0x3FFFFF
        return {
            "spec": "TR v2.0 (group header)",
            "ver": ver,
            "hw_id": hw_id,
            "seq": seq,
            "node_id": node_id,
            "inner_offset": 8,  # individual report header(s) follow; tune per setup
        }
    else:
        # --- Telemetry Report v0.5 fixed header (16 bytes) ---
        if len(data) < 16:
            return {"error": "too short for v0.5 header", "ver": ver}
        # ver(4) len(4) nProto(3) repMdBits(6) rsvd(6) d(1) q(1) f(1) hw_id(6)
        word0 = struct.unpack("!I", data[:4])[0]
        length = (word0 >> 24) & 0xF
        nproto = (word0 >> 21) & 0x7
        d = (word0 >> 8) & 0x1
        q = (word0 >> 7) & 0x1
        f = (word0 >> 6) & 0x1
        hw_id = word0 & 0x3F
        # int_xd_tofino report_fixed_header: word0 | switch_id | seq_num | ingress_tstamp
        switch_id, seq, ingress_ts = struct.unpack("!III", data[4:16])
        return {
            "spec": "INT-XD report_fixed_header",
            "ver": ver,
            "len_words": length,
            "nProto": nproto,
            "flags": f"d={d} q={q} f={f}",
            "hw_id": hw_id,
            "switch_id": switch_id,
            "seq": seq,
            "ingress_ts": ingress_ts,
            "inner_offset": 16,
        }


def parse_inner_5tuple(data: bytes, offset: int) -> dict | None:
    """
    The encapsulated original packet usually starts with an Ethernet frame.
    Pull out the inner IPv4 5-tuple if present, since that's the flow the
    telemetry report describes.
    """
    try:
        inner = data[offset:]
        if len(inner) < 14:
            return None
        ethertype = struct.unpack("!H", inner[12:14])[0]
        if ethertype != 0x0800:  # not IPv4
            return {"ethertype": hex(ethertype)}
        ip = inner[14:]
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        result = {"src_ip": src, "dst_ip": dst, "ip_proto": proto}
        if proto in (6, 17) and len(ip) >= ihl + 4:  # TCP/UDP ports
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            result["sport"] = sport
            result["dport"] = dport
        return result
    except Exception as e:  # noqa: BLE001 - best-effort decode
        return {"parse_error": str(e)}


def parse_int_metadata(data: bytes, inner_offset: int = 16) -> dict | None:
    """
    Decode the trailing INT metadata block that int_xd_tofino appends after the
    encapsulated original headers. Layout per int_xd_tofino.p4 EgressDeparser:
      report_fixed(16) | inner eth(14) | inner ip(ihl) | inner l4(8) | INT(32)
    INT block: switch_id(4) port_ids(4) hop_latency(4) q(4) ingress_ts(8) egress_ts(8)
    """
    try:
        eth = data[inner_offset:]
        if len(eth) < 14 or struct.unpack("!H", eth[12:14])[0] != 0x0800:
            return None
        ip = eth[14:]
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        # UDP header = 8B, TCP header = 20B (fixed part, options not handled).
        # int_xd_tofino emits the full tcp_h, so TCP must skip 20B not 8B or
        # the INT block is read 12B early.
        l4len = 20 if proto == 6 else (8 if proto == 17 else 0)
        off = inner_offset + 14 + ihl + l4len
        b = data[off:off + 32]
        if len(b) < 32:
            return None
        switch_id, = struct.unpack("!I", b[0:4])
        ing_port, egr_port = struct.unpack("!HH", b[4:8])
        hop_latency, = struct.unpack("!I", b[8:12])
        q_id = b[12]
        q_occupancy = int.from_bytes(b[13:16], "big")
        ingress_ts, = struct.unpack("!Q", b[16:24])
        egress_ts, = struct.unpack("!Q", b[24:32])
        return {
            "switch_id": switch_id,
            "ingress_port": ing_port,
            "egress_port": egr_port,
            "hop_latency": hop_latency,
            "q_id": q_id,
            "q_occupancy": q_occupancy,
            "ingress_ts": ingress_ts,
            "egress_ts": egress_ts,
        }
    except Exception as e:  # noqa: BLE001 - best-effort decode
        return {"int_parse_error": str(e)}


def _lp_escape(v) -> str:
    """Escape an InfluxDB line-protocol tag value."""
    return str(v).replace("\\", "\\\\").replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=")


def influx_write(hdr: dict, flow, md) -> None:
    """POST one decoded report to InfluxDB v2 as line protocol (stdlib only).

    Schema matches int_collector_influx.py's add_xd_report() exactly so the
    existing Grafana dashboards work unchanged: measurement int_telemetry,
    flow tags srcip/dstip/scrp/dstp/protocol + int_mode/switch_id, and FLOAT
    fields seq/hop_delay/q_occupancy/ingress_port/egress_port/ingress_tstamp/
    egress_tstamp (InfluxDB locks a field's type on first write).
    """
    if not INFLUX or not md or "int_parse_error" in md:
        return
    tags = {
        "int_mode": "XD",
        "platform": INFLUX.get("platform", "tofino"),
        "switch_id": str(md.get("switch_id", hdr.get("switch_id", 0))),
    }
    if flow and "src_ip" in flow:
        tags["srcip"] = flow["src_ip"]
        tags["dstip"] = flow["dst_ip"]
        tags["scrp"] = flow.get("sport", 0)        # note: original key is "scrp"
        tags["dstp"] = flow.get("dport", 0)
        tags["protocol"] = flow.get("ip_proto", 0)
    fields = {
        "seq":            float(hdr.get("seq", 0)),
        "hop_delay":      float(md["hop_latency"]),
        "q_occupancy":    float(md["q_occupancy"]),
        "ingress_port":   float(md["ingress_port"]),
        "egress_port":    float(md["egress_port"]),
        "ingress_tstamp": float(md["ingress_ts"]),
        "egress_tstamp":  float(md["egress_ts"]),
    }
    tagstr = ",".join(f"{k}={_lp_escape(v)}" for k, v in sorted(tags.items()))
    fieldstr = ",".join(f"{k}={v}" for k, v in fields.items())
    line = f"int_telemetry,{tagstr} {fieldstr} {int(time.time() * 1e9)}"
    _influx_buf.append(line)
    if len(_influx_buf) >= INFLUX_BATCH or (time.time() - _influx_last_flush) >= INFLUX_PERIOD:
        influx_flush()


def influx_flush() -> None:
    """Flush buffered line-protocol points to InfluxDB in one POST."""
    global _influx_buf, _influx_last_flush
    if not INFLUX or not _influx_buf:
        return
    body = "\n".join(_influx_buf).encode()
    _influx_buf = []
    _influx_last_flush = time.time()
    url = f"{INFLUX['url']}/api/v2/write?" + urllib.parse.urlencode(
        {"org": INFLUX["org"], "bucket": INFLUX["bucket"], "precision": "ns"})
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": f"Token {INFLUX['token']}",
                 "Content-Type": "text/plain; charset=utf-8"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:  # noqa: BLE001 - keep collecting on write failure
        print(f"  [influx write error: {e}]")


def handle_report(data: bytes, quiet: bool = False) -> None:
    """Decode a report, write it to InfluxDB (if enabled), and print it unless quiet.

    Decoding + the InfluxDB write always happen; only the (expensive) per-report
    printing is skipped in quiet mode, which is what lets the collector keep up at
    high report rates.
    """
    hdr = parse_report_header(data)
    if "error" in hdr:
        if not quiet:
            print(f"  header: {hdr['error']}")
        return
    flow = parse_inner_5tuple(data, hdr.get("inner_offset", 0))
    md = parse_int_metadata(data, hdr.get("inner_offset", 16))
    if not quiet:
        print(f"  report: {hdr['spec']}  "
              + "  ".join(f"{k}={v}" for k, v in hdr.items() if k != "spec"))
        if flow:
            print(f"  flow:   {flow}")
        if md:
            print(f"  int:    {md}")
    influx_write(hdr, flow, md)


def maybe_summary(count: int, state: dict, sample: int = 1) -> None:
    """Print a throughput summary every SUMMARY_PERIOD seconds (quiet mode)."""
    now = time.time()
    dt = now - state["last_t"]
    if dt >= SUMMARY_PERIOD:
        rate = (count - state["last_count"]) / dt
        ts = datetime.now().strftime("%H:%M:%S")
        if sample > 1:
            print(f"[{ts}] {count} processed (1/{sample} sampled), "
                  f"~{rate * sample:.0f} reports/s offered, {rate:.0f}/s processed")
        else:
            print(f"[{ts}] {count} reports total, {rate:.0f} reports/s")
        state["last_t"] = now
        state["last_count"] = count


# ---------------------------------------------------------------------------
# pcap stream sniffing (no kernel UDP delivery needed)
# ---------------------------------------------------------------------------
#
# When the report's dst MAC/IP don't match the host NIC (e.g. the Tofino sends
# to a hardcoded collector MAC/IP that this box doesn't own), the kernel drops
# the datagram before any UDP socket sees it. tcpdump/BPF still sees the frame,
# so we read a live pcap stream from tcpdump on stdin, pull the UDP payload out
# of each frame ourselves, and feed it to the same parsers.
#
#   sudo tcpdump -i en7 -s0 -U -w - udp port 6001 | python3 intxd-collector.py --sniff-stdin

def iter_pcap_stream(f):
    """Yield (ts_epoch, frame_bytes) from a libpcap stream on binary file f."""
    gh = f.read(24)
    if len(gh) < 24:
        return
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nsec = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nsec = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise ValueError(f"not a pcap stream (magic {magic.hex()})")
    rec = struct.Struct(endian + "IIII")
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            return
        ts_sec, ts_frac, incl_len, _orig = rec.unpack(hdr)
        data = f.read(incl_len)
        if len(data) < incl_len:
            return
        ts = ts_sec + ts_frac / (1e9 if nsec else 1e6)
        yield ts, data


def udp_payload_from_frame(frame: bytes):
    """Strip Ethernet (+ optional 802.1Q) / IPv4 / UDP, return (payload, dst_port)."""
    if len(frame) < 14:
        return None
    off = 12
    ethertype = struct.unpack("!H", frame[off:off + 2])[0]
    off += 2
    while ethertype == 0x8100 and len(frame) >= off + 4:   # VLAN tag(s)
        ethertype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if ethertype != 0x0800:
        return None
    ip = frame[off:]
    if len(ip) < 20 or ip[9] != 17:   # IPv4 + UDP
        return None
    ihl = (ip[0] & 0x0F) * 4
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    dport = struct.unpack("!H", udp[2:4])[0]
    return udp[8:], dport


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

class _Tee:
    """Duplicate writes to several text streams (stdout + an --out file)."""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


def run_sniff_stdin(args) -> int:
    """Read a libpcap stream on stdin (from tcpdump), decode INT-XD reports."""
    print(f"Reading pcap stream from stdin, filtering UDP dport {args.port} ... "
          f"(Ctrl+C to stop)")
    log = open(args.pcap, "a") if args.pcap else None
    count = 0
    recv = 0
    summ = {"last_t": time.time(), "last_count": 0}
    try:
        for ts_epoch, frame in iter_pcap_stream(sys.stdin.buffer):
            res = udp_payload_from_frame(frame)
            if res is None:
                continue
            data, dport = res
            if dport != args.port:
                continue
            recv += 1
            if args.sample > 1 and (recv % args.sample) != 0:
                continue
            count += 1
            if args.quiet:
                handle_report(data, quiet=True)
                maybe_summary(count, summ, args.sample)
                continue
            ts = datetime.fromtimestamp(ts_epoch).strftime("%H:%M:%S.%f")[:-3]
            print(f"\n[{ts}] #{count}  {len(data)} bytes (sniffed, {len(frame)}B frame)")
            if not args.raw:
                handle_report(data)
            print(hexdump(data))
            if log:
                log.write(f"# {ts} {len(data)}B sniffed\n{data.hex()}\n")
                log.flush()
    except KeyboardInterrupt:
        print(f"\nStopped. {count} reports decoded.")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        if log:
            log.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="INT-XD telemetry collector")
    ap.add_argument("--ip", default="0.0.0.0", help="bind address")
    ap.add_argument("--port", type=int, default=6001, help="UDP port")
    ap.add_argument("--raw", action="store_true", help="raw hex dump only")
    ap.add_argument("--pcap", metavar="FILE", help="append hex dumps to a file")
    ap.add_argument("--out", metavar="FILE",
                    help="also write the full decoded output (report/flow/int + "
                         "hexdump) to FILE, line-buffered")
    ap.add_argument("--sniff-stdin", action="store_true",
                    help="read a libpcap stream from stdin (pipe from tcpdump) "
                         "instead of binding a UDP socket; bypasses kernel MAC/IP "
                         "filtering. Filters to --port.")
    ap.add_argument("--platform", default="tofino",
                    help="value for the InfluxDB 'platform' tag (e.g. tofino, bmv2) "
                         "so hardware vs software runs are comparable in one bucket")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress per-report output (decode + InfluxDB write still "
                         "happen); print a throughput summary every few seconds. Use "
                         "at high report rates so printing doesn't choke the collector.")
    ap.add_argument("--sample", type=int, default=1, metavar="N",
                    help="process/write only 1 in N received reports (default 1 = all). "
                         "Lets the collector keep up at high offered rates; the seq-based "
                         "rate panel still shows the true total rate.")
    ap.add_argument("--influx", metavar="URL",
                    help="also write each decoded report to InfluxDB v2 at URL "
                         "(e.g. http://localhost:8086)")
    ap.add_argument("--token", default="my-super-secret-token", help="InfluxDB v2 token")
    ap.add_argument("--org", default="int-project", help="InfluxDB v2 org")
    ap.add_argument("--bucket", default="int_telemetry", help="InfluxDB v2 bucket")
    args = ap.parse_args()
    if args.sample < 1:
        args.sample = 1

    if args.influx:
        global INFLUX, _influx_last_flush
        INFLUX = {"url": args.influx.rstrip("/"), "token": args.token,
                  "org": args.org, "bucket": args.bucket, "platform": args.platform}
        _influx_last_flush = time.time()

    outf = open(args.out, "w", buffering=1) if args.out else None
    if outf:
        sys.stdout = _Tee(sys.__stdout__, outf)
    try:
        if args.sniff_stdin:
            return run_sniff_stdin(args)
        return run_socket(args)
    finally:
        influx_flush()  # flush any buffered points before exit
        if outf:
            sys.stdout = sys.__stdout__
            outf.close()


def run_socket(args) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.ip, args.port))

    print(f"Listening for INT-XD reports on UDP {args.ip}:{args.port} ... (Ctrl+C to stop)")
    log = open(args.pcap, "a") if args.pcap else None
    count = 0
    recv = 0
    summ = {"last_t": time.time(), "last_count": 0}

    try:
        while True:
            data, addr = sock.recvfrom(9000)  # jumbo-safe
            recv += 1
            if args.sample > 1 and (recv % args.sample) != 0:
                continue
            count += 1
            if args.quiet:
                handle_report(data, quiet=True)
                maybe_summary(count, summ, args.sample)
                continue
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"\n[{ts}] #{count}  {len(data)} bytes from {addr[0]}:{addr[1]}")
            if not args.raw:
                handle_report(data)
            print(hexdump(data))
            if log:
                log.write(f"# {ts} {len(data)}B from {addr}\n{data.hex()}\n")
                log.flush()
    except KeyboardInterrupt:
        print(f"\nStopped. {count} reports received.")
    finally:
        sock.close()
        if log:
            log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())