#!/usr/bin/env python3
"""
printer_exporter — a zero-dependency Prometheus exporter for SNMP printers.

Built and verified against a Xerox(R) B225 MFP (Lexmark engine, firmware
MXLSG.230.513) but written against the standard Printer-MIB (RFC 3805) and
Host-Resources-MIB, so it works with most network printers. Vendor-specific
Xerox/Lexmark usage counters are collected as a bonus when present.

No third-party packages. Pure stdlib SNMP v2c (GET + GETNEXT walk) and a
stdlib HTTP server. Scrapes the device live on every /metrics request.

Usage:
    ./printer_exporter.py --target 172.16.10.29
    ./printer_exporter.py --target 172.16.10.29 --once   # print once and exit

Environment variables (overridden by CLI flags):
    PRINTER_TARGET     printer IP/host        (default 127.0.0.1)
    PRINTER_COMMUNITY  SNMP v2c community     (default public)
    PRINTER_SNMP_PORT  SNMP UDP port          (default 161)
    EXPORTER_PORT      HTTP listen port       (default 9109)
    EXPORTER_ADDR      HTTP listen address    (default 0.0.0.0)
    SNMP_TIMEOUT       per-request seconds    (default 2.0)

Metrics are read-only: the exporter only issues SNMP GET/GETNEXT. It never
sets a value, prints, or scans.
"""

import argparse
import os
import socket
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Minimal SNMP v2c (GET + GETNEXT) over UDP — pure stdlib BER encode/decode.
# --------------------------------------------------------------------------


class SNMPError(Exception):
    pass


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, val):
    return bytes([tag]) + _enc_len(len(val)) + val


def _enc_int(i):
    length = max(1, (i.bit_length() + 8) // 8)
    return _tlv(0x02, i.to_bytes(length, "big", signed=True))


def _enc_oid(oid):
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for x in parts[2:]:
        if x < 0x80:
            out += bytes([x])
            continue
        stack = [x & 0x7F]
        x >>= 7
        while x:
            stack.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(stack))
    return _tlv(0x06, out)


def _dec_tlv(b, i):
    tag = b[i]
    length = b[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + length], i + length


def _dec_oid(v):
    parts = [v[0] // 40, v[0] % 40]
    x = 0
    for c in v[1:]:
        x = (x << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(x)
            x = 0
    return ".".join(map(str, parts))


# ASN.1 tags we return as a tagged value so callers can tell types apart.
NOSUCHOBJECT = 0x80
NOSUCHINSTANCE = 0x81
ENDOFMIBVIEW = 0x82


def _decode_value(tag, raw):
    if tag in (NOSUCHOBJECT, NOSUCHINSTANCE, ENDOFMIBVIEW):
        return None
    if tag == 0x02:  # INTEGER
        return int.from_bytes(raw, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(raw, "big")
    if tag == 0x40:  # IpAddress
        return ".".join(str(b) for b in raw)
    if tag == 0x06:  # OID
        return _dec_oid(raw)
    if tag == 0x04:  # OCTET STRING
        try:
            s = raw.decode("utf-8")
            return s if s.isprintable() or s == "" else raw.hex()
        except UnicodeDecodeError:
            return raw.hex()
    if tag == 0x05:  # NULL
        return None
    return raw.hex()


class SNMPClient:
    def __init__(self, host, community="public", port=161, timeout=2.0):
        self.host = host
        self.community = community.encode()
        self.port = port
        self.timeout = timeout
        self._rid = int(time.time()) & 0x7FFFFFFF

    def _request(self, pdu_tag, oid):
        self._rid = (self._rid + 1) & 0x7FFFFFFF
        varbind = _tlv(0x30, _enc_oid(oid) + b"\x05\x00")
        varbind_list = _tlv(0x30, varbind)
        pdu = _tlv(
            pdu_tag,
            _enc_int(self._rid) + _enc_int(0) + _enc_int(0) + varbind_list,
        )
        msg = _tlv(0x30, _enc_int(1) + _tlv(0x04, self.community) + pdu)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(msg, (self.host, self.port))
            data, _ = sock.recvfrom(65535)
        finally:
            sock.close()

        # SEQUENCE { version, community, PDU { rid, err, erridx, varbinds } }
        _, body, _ = _dec_tlv(data, 0)
        i = 0
        _, _, i = _dec_tlv(body, i)  # version
        _, _, i = _dec_tlv(body, i)  # community
        _, pdu_body, _ = _dec_tlv(body, i)
        j = 0
        _, _, j = _dec_tlv(pdu_body, j)  # request-id
        _, err, j = _dec_tlv(pdu_body, j)  # error-status
        _, _, j = _dec_tlv(pdu_body, j)  # error-index
        _, vbl, _ = _dec_tlv(pdu_body, j)  # varbind list
        if int.from_bytes(err, "big"):
            raise SNMPError(f"SNMP error-status {int.from_bytes(err, 'big')}")
        _, vb, _ = _dec_tlv(vbl, 0)
        _, oid_raw, k = _dec_tlv(vb, 0)
        vtag, vraw, _ = _dec_tlv(vb, k)
        return _dec_oid(oid_raw), vtag, _decode_value(vtag, vraw)

    def get(self, oid):
        """Return the value of exactly `oid`, or None if absent."""
        ret_oid, vtag, val = self._request(0xA0, oid)
        if vtag in (NOSUCHOBJECT, NOSUCHINSTANCE) or ret_oid != oid.strip("."):
            return None
        return val

    def walk(self, root):
        """Yield (oid, value) for every leaf under `root`."""
        root = root.strip(".")
        oid = root
        seen = 0
        while seen < 10000:
            ret_oid, vtag, val = self._request(0xA1, oid)  # GETNEXT
            if vtag == ENDOFMIBVIEW:
                return
            if not (ret_oid == root or ret_oid.startswith(root + ".")):
                return
            if ret_oid == oid:  # no progress — avoid infinite loop
                return
            yield ret_oid, val
            oid = ret_oid
            seen += 1


# --------------------------------------------------------------------------
# OIDs. Standard first (portable), vendor extras last (collected if present).
# --------------------------------------------------------------------------

# Scalars (Host-Resources + system)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# Printer-MIB (RFC 3805) tables
PRT_CONSOLE_DISPLAY = "1.3.6.1.2.1.43.16.5.1.2.1.1"   # console message, scalar-ish
PRT_MARKER_LIFECOUNT = "1.3.6.1.2.1.43.10.2.1.4.1.1"  # lifetime impressions
PRT_SUPPLY_DESC = "1.3.6.1.2.1.43.11.1.1.6"           # <idx> -> description
PRT_SUPPLY_MAX = "1.3.6.1.2.1.43.11.1.1.8"            # <idx> -> max capacity
PRT_SUPPLY_LEVEL = "1.3.6.1.2.1.43.11.1.1.9"          # <idx> -> current level
PRT_INPUT_MAX = "1.3.6.1.2.1.43.8.2.1.9"              # <idx> -> tray max capacity
PRT_INPUT_LEVEL = "1.3.6.1.2.1.43.8.2.1.10"           # <idx> -> tray current level
PRT_INPUT_NAME = "1.3.6.1.2.1.43.8.2.1.13"            # <idx> -> tray name
HR_PRINTER_STATUS = "1.3.6.1.2.1.25.3.5.1.1"          # <idx> -> 1..5

# Interfaces (ifTable)
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

# Vendor extras (best-effort): Xerox usage counters — names and values tables.
XEROX_CNT_VALUE = "1.3.6.1.4.1.253.8.53.13.2.1.6.1.20"
XEROX_CNT_NAME = "1.3.6.1.4.1.253.8.53.13.2.1.8.1.20"
# Lexmark/common identity
PRT_GENERAL_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"      # prtGeneralSerialNumber

HR_PRINTER_STATE_NAMES = {
    1: "other", 2: "unknown", 3: "idle", 4: "printing", 5: "warmup",
}


# --------------------------------------------------------------------------
# Prometheus text exposition helpers.
# --------------------------------------------------------------------------


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _labels(d):
    if not d:
        return ""
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in d.items()) + "}"


class Metrics:
    def __init__(self):
        self.lines = []
        self._declared = set()

    def declare(self, name, mtype, help_text):
        if name in self._declared:
            return
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {mtype}")
        self._declared.add(name)

    def add(self, name, value, labels=None):
        self.lines.append(f"{name}{_labels(labels)} {value}")

    def render(self):
        return "\n".join(self.lines) + "\n"


def _tail_index(oid, base):
    """Return the index suffix of `oid` relative to `base`."""
    return oid[len(base.strip(".")) + 1:]


def collect(client, target):
    m = Metrics()
    start = time.time()
    ok = 1

    def safe_get(oid):
        try:
            return client.get(oid)
        except (OSError, SNMPError):
            return None

    def safe_walk(oid):
        try:
            return list(client.walk(oid))
        except (OSError, SNMPError):
            return []

    # ---- Reachability probe (sysUpTime is cheap and universal) -----------
    uptime_ticks = safe_get(SYS_UPTIME)
    if uptime_ticks is None:
        ok = 0

    m.declare("printer_up", "gauge",
              "1 if the printer answered SNMP this scrape, else 0.")
    m.add("printer_up", ok, {"target": target})

    if ok:
        # ---- Identity ----------------------------------------------------
        descr = safe_get(SYS_DESCR) or ""
        name = safe_get(SYS_NAME) or ""
        location = safe_get(SYS_LOCATION) or ""
        serial = safe_get(PRT_GENERAL_SERIAL) or ""
        m.declare("printer_info", "gauge",
                  "Static printer identity; value is always 1.")
        m.add("printer_info", 1, {
            "target": target,
            "sys_name": name,
            "sys_descr": descr,
            "location": location,
            "serial": serial,
        })

        # ---- Uptime ------------------------------------------------------
        if uptime_ticks is not None:
            m.declare("printer_uptime_seconds", "gauge",
                      "Device uptime (sysUpTime), seconds.")
            m.add("printer_uptime_seconds", int(uptime_ticks) / 100.0,
                  {"target": target})

        # ---- Printer state (stateset) ------------------------------------
        states = safe_walk(HR_PRINTER_STATUS)
        if states:
            m.declare("printer_status", "gauge",
                      "hrPrinterStatus as a stateset (1 marks the active state).")
            _, raw = states[0]
            cur = int(raw) if raw is not None else 0
            for code, sname in HR_PRINTER_STATE_NAMES.items():
                m.add("printer_status",
                      1 if code == cur else 0,
                      {"target": target, "state": sname})

        # ---- Console message --------------------------------------------
        msg = safe_get(PRT_CONSOLE_DISPLAY)
        if msg is not None:
            m.declare("printer_console_message", "gauge",
                      "Front-panel display string; value always 1.")
            m.add("printer_console_message", 1,
                  {"target": target, "message": msg})

        # ---- Page / impression counter -----------------------------------
        life = safe_get(PRT_MARKER_LIFECOUNT)
        if life is not None:
            m.declare("printer_marker_life_count_total", "counter",
                      "Lifetime marker impressions (prtMarkerLifeCount).")
            m.add("printer_marker_life_count_total", int(life),
                  {"target": target})

        # ---- Supplies (toner, imaging unit, ...) -------------------------
        desc = {_tail_index(o, PRT_SUPPLY_DESC): v
                for o, v in safe_walk(PRT_SUPPLY_DESC)}
        maxcap = {_tail_index(o, PRT_SUPPLY_MAX): v
                  for o, v in safe_walk(PRT_SUPPLY_MAX)}
        level = {_tail_index(o, PRT_SUPPLY_LEVEL): v
                 for o, v in safe_walk(PRT_SUPPLY_LEVEL)}
        if level:
            m.declare("printer_supply_level_units", "gauge",
                      "Current supply level in the device's native units.")
            m.declare("printer_supply_max_units", "gauge",
                      "Maximum supply capacity in native units (-2 = unknown).")
            m.declare("printer_supply_level_ratio", "gauge",
                      "Supply remaining as a 0..1 ratio (only when max > 0).")
            for idx, lv in level.items():
                name_i = desc.get(idx, f"supply-{idx}")
                lab = {"target": target, "supply": name_i}
                try:
                    lv_i = int(lv)
                    m.add("printer_supply_level_units", lv_i, lab)
                except (TypeError, ValueError):
                    continue
                mc = maxcap.get(idx)
                try:
                    mc_i = int(mc)
                    m.add("printer_supply_max_units", mc_i, lab)
                    if mc_i > 0 and lv_i >= 0:
                        m.add("printer_supply_level_ratio",
                              round(lv_i / mc_i, 4), lab)
                except (TypeError, ValueError):
                    pass

        # ---- Input trays -------------------------------------------------
        tray_name = {_tail_index(o, PRT_INPUT_NAME): v
                     for o, v in safe_walk(PRT_INPUT_NAME)}
        tray_max = {_tail_index(o, PRT_INPUT_MAX): v
                    for o, v in safe_walk(PRT_INPUT_MAX)}
        tray_lvl = {_tail_index(o, PRT_INPUT_LEVEL): v
                    for o, v in safe_walk(PRT_INPUT_LEVEL)}
        if tray_lvl:
            m.declare("printer_input_tray_level_sheets", "gauge",
                      "Sheets currently in the input tray (-3 = at least one).")
            m.declare("printer_input_tray_max_sheets", "gauge",
                      "Input tray maximum capacity in sheets.")
            for idx, lv in tray_lvl.items():
                lab = {"target": target,
                       "tray": tray_name.get(idx, f"tray-{idx}")}
                try:
                    m.add("printer_input_tray_level_sheets", int(lv), lab)
                except (TypeError, ValueError):
                    pass
                try:
                    m.add("printer_input_tray_max_sheets",
                          int(tray_max.get(idx)), lab)
                except (TypeError, ValueError):
                    pass

        # ---- Interfaces --------------------------------------------------
        ifd = {_tail_index(o, IF_DESCR): v for o, v in safe_walk(IF_DESCR)}
        if ifd:
            rx = {_tail_index(o, IF_IN_OCTETS): v
                  for o, v in safe_walk(IF_IN_OCTETS)}
            tx = {_tail_index(o, IF_OUT_OCTETS): v
                  for o, v in safe_walk(IF_OUT_OCTETS)}
            up = {_tail_index(o, IF_OPER_STATUS): v
                  for o, v in safe_walk(IF_OPER_STATUS)}
            m.declare("printer_network_receive_bytes_total", "counter",
                      "Interface ifInOctets.")
            m.declare("printer_network_transmit_bytes_total", "counter",
                      "Interface ifOutOctets.")
            m.declare("printer_network_interface_up", "gauge",
                      "1 if ifOperStatus is up(1), else 0.")
            for idx, dname in ifd.items():
                lab = {"target": target, "interface": dname}
                if idx in rx and rx[idx] is not None:
                    m.add("printer_network_receive_bytes_total",
                          int(rx[idx]), lab)
                if idx in tx and tx[idx] is not None:
                    m.add("printer_network_transmit_bytes_total",
                          int(tx[idx]), lab)
                if idx in up and up[idx] is not None:
                    m.add("printer_network_interface_up",
                          1 if int(up[idx]) == 1 else 0, lab)

        # ---- Vendor extra: Xerox usage counters (best-effort) ------------
        cnt_names = {_tail_index(o, XEROX_CNT_NAME): v
                     for o, v in safe_walk(XEROX_CNT_NAME)}
        cnt_vals = safe_walk(XEROX_CNT_VALUE)
        if cnt_vals:
            m.declare("printer_usage_counter_total", "counter",
                      "Vendor usage counter (Xerox/Lexmark impressions table).")
            for o, v in cnt_vals:
                idx = _tail_index(o, XEROX_CNT_VALUE)
                try:
                    m.add("printer_usage_counter_total", int(v),
                          {"target": target,
                           "counter": cnt_names.get(idx, f"counter-{idx}")})
                except (TypeError, ValueError):
                    pass

    # ---- Scrape self-metric ---------------------------------------------
    m.declare("printer_scrape_duration_seconds", "gauge",
              "Time taken to collect metrics from the printer.")
    m.add("printer_scrape_duration_seconds",
          round(time.time() - start, 4), {"target": target})
    return m.render()


# --------------------------------------------------------------------------
# HTTP server.
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    client = None
    target = None

    def log_message(self, *a):  # silence default access logging
        pass

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/metrics") or self.path == "/metrics":
            try:
                body = collect(self.client, self.target).encode()
            except Exception as e:  # never 500 the scrape on a transient error
                body = (
                    "# HELP printer_up 1 if the printer answered SNMP.\n"
                    "# TYPE printer_up gauge\n"
                    f'printer_up{{target="{_esc(self.target)}"}} 0\n'
                    f"# scrape error: {_esc(e)}\n"
                ).encode()
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/":
            page = (
                b"<html><head><title>printer_exporter</title></head>"
                b"<body><h1>printer_exporter</h1>"
                b'<p><a href="/metrics">Metrics</a></p></body></html>\n'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
        else:
            self.send_error(404)


def main():
    p = argparse.ArgumentParser(description="Prometheus exporter for SNMP printers.")
    p.add_argument("--target", default=os.environ.get("PRINTER_TARGET", "127.0.0.1"),
                   help="printer IP/host (default from PRINTER_TARGET or 127.0.0.1)")
    p.add_argument("--community", default=os.environ.get("PRINTER_COMMUNITY", "public"))
    p.add_argument("--snmp-port", type=int,
                   default=int(os.environ.get("PRINTER_SNMP_PORT", "161")))
    p.add_argument("--listen-addr", default=os.environ.get("EXPORTER_ADDR", "0.0.0.0"))
    p.add_argument("--listen-port", type=int,
                   default=int(os.environ.get("EXPORTER_PORT", "9109")))
    p.add_argument("--timeout", type=float,
                   default=float(os.environ.get("SNMP_TIMEOUT", "2.0")))
    p.add_argument("--once", action="store_true",
                   help="print metrics once to stdout and exit")
    args = p.parse_args()

    client = SNMPClient(args.target, args.community, args.snmp_port, args.timeout)

    if args.once:
        sys.stdout.write(collect(client, args.target))
        return

    Handler.client = client
    Handler.target = args.target
    srv = ThreadingHTTPServer((args.listen_addr, args.listen_port), Handler)
    print(f"printer_exporter: scraping {args.target} via SNMP:{args.snmp_port}, "
          f"serving http://{args.listen_addr}:{args.listen_port}/metrics",
          file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
