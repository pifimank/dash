#!/usr/bin/env python3
"""
Parse pcap via tshark -T fields (legacy-compatible, works on all tshark versions).
Extracts destination IPs and all DNS queries/responses, including multiple RRs per packet.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

TYPE_NAMES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "HTTPS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY",
}

IDX_IP_DST = 0
IDX_IPV6_DST = 1
IDX_QRY_NAME = 2
IDX_QRY_TYPE = 3
IDX_RESP_NAME = 4
IDX_RESP_TYPE = 5
IDX_A = 6
IDX_AAAA = 7
IDX_CNAME = 8
IDX_PTR = 9
IDX_MX = 10
IDX_SRV = 11
IDX_TXT = 12
IDX_SOA = 13
IDX_NS = 14
IDX_UDP_PORT = 15
FIELD_COUNT = 16

# Same core fields as legacy as_report.sh / getdns.sh (widely supported by tshark)
TSHARK_FIELDS = [
    "ip.dst",
    "ipv6.dst",
    "dns.qry.name",
    "dns.qry.type",
    "dns.resp.name",
    "dns.resp.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.ptr.domain_name",
    "dns.mx.mail_exchange",
    "dns.srv.name",
    "dns.txt",
    "dns.soa.mname",
    "dns.ns",
    "udp.port",
]


def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"TYPE{t}")


def split_field(value: str) -> List[str]:
    if not value:
        return []
    parts: List[str] = []
    for part in value.split(","):
        part = part.strip().strip('"')
        if part:
            parts.append(part)
    return parts


def field_at(parts: List[str], idx: int) -> str:
    if idx < len(parts):
        return parts[idx] or ""
    return ""


def is_mdns_packet(parts: List[str]) -> bool:
    ip4 = field_at(parts, IDX_IP_DST)
    ip6 = field_at(parts, IDX_IPV6_DST)
    for port in split_field(field_at(parts, IDX_UDP_PORT)):
        try:
            if int(port) == 5353:
                return True
        except ValueError:
            pass
    if ip4 == "224.0.0.251" or ip6 == "ff02::fb":
        return True
    return False


def is_response_packet(parts: List[str]) -> bool:
    if split_field(field_at(parts, IDX_RESP_TYPE)):
        return True
    for idx in (IDX_A, IDX_AAAA, IDX_CNAME, IDX_PTR, IDX_MX, IDX_SRV, IDX_TXT, IDX_NS):
        if field_at(parts, idx):
            return True
    return False


def field_list(parts: List[str], idx: int) -> List[str]:
    return split_field(field_at(parts, idx))


def build_rdata_queues(parts: List[str]) -> Dict[int, Deque[str]]:
    queues: Dict[int, Deque[str]] = defaultdict(deque)
    mapping = {
        1: field_list(parts, IDX_A),
        28: field_list(parts, IDX_AAAA),
        5: field_list(parts, IDX_CNAME),
        12: field_list(parts, IDX_PTR),
        16: field_list(parts, IDX_TXT),
        2: field_list(parts, IDX_NS),
        15: field_list(parts, IDX_MX),
        33: field_list(parts, IDX_SRV),
        6: field_list(parts, IDX_SOA),
    }
    for tnum, vals in mapping.items():
        for val in vals:
            queues[tnum].append(val)
    return queues


def pop_rdata(tnum: int, idx: int, parts: List[str], queues: Dict[int, Deque[str]]) -> str:
    q = queues.get(tnum)
    if q:
        return q.popleft()
    vals = field_list(parts, {
        1: IDX_A,
        28: IDX_AAAA,
        5: IDX_CNAME,
        12: IDX_PTR,
        15: IDX_MX,
        16: IDX_TXT,
        33: IDX_SRV,
        6: IDX_SOA,
        2: IDX_NS,
    }.get(tnum, -1))
    if idx < len(vals):
        return vals[idx]
    return ""


def emit_response(
    out,
    seen: Set[Tuple[str, str, str, str, str]],
    tstr: str,
    val: str,
    fqdn: str,
    proto: str,
    skip_mdns: bool,
) -> None:
    if not val:
        return
    if skip_mdns and (proto == "mdns" or (fqdn and fqdn.endswith(".local"))):
        return
    key = ("Response", tstr, val, fqdn, proto)
    if key in seen:
        return
    seen.add(key)
    out.write(f"Response,{tstr},{val},{fqdn},{proto}\n")


def emit_fallback_responses(
    parts: List[str],
    fqdn: str,
    proto: str,
    skip_mdns: bool,
    out,
    seen: Set[Tuple[str, str, str, str, str]],
) -> None:
    for ip in field_list(parts, IDX_A):
        emit_response(out, seen, "A", ip, fqdn, proto, skip_mdns)
    for ip in field_list(parts, IDX_AAAA):
        emit_response(out, seen, "AAAA", ip, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_CNAME):
        emit_response(out, seen, "CNAME", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_PTR):
        emit_response(out, seen, "PTR", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_NS):
        emit_response(out, seen, "NS", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_TXT):
        emit_response(out, seen, "TXT", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_MX):
        emit_response(out, seen, "MX", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_SRV):
        emit_response(out, seen, "SRV", val, fqdn, proto, skip_mdns)
    for val in field_list(parts, IDX_SOA):
        emit_response(out, seen, "SOA", val, fqdn, proto, skip_mdns)


def process_packet_line(
    line: str,
    skip_mdns: bool,
    ips_out,
    dns_out,
    seen_dns: Set[Tuple[str, str, str, str, str]],
    ips_written: Set[str],
) -> None:
    parts = line.rstrip("\n").split("\t")
    while len(parts) < FIELD_COUNT:
        parts.append("")

    for ip in split_field(field_at(parts, IDX_IP_DST)) + split_field(field_at(parts, IDX_IPV6_DST)):
        if ip and ip != "0.0.0.0" and ip not in ips_written:
            ips_written.add(ip)
            ips_out.write(ip + "\n")

    proto = "mdns" if is_mdns_packet(parts) else "unicast"
    qnames = split_field(field_at(parts, IDX_QRY_NAME))
    qtypes = split_field(field_at(parts, IDX_QRY_TYPE))
    resp_names = split_field(field_at(parts, IDX_RESP_NAME))
    default_fqdn = qnames[0] if qnames else (resp_names[0] if resp_names else "")

    if not is_response_packet(parts):
        for i, name in enumerate(qnames):
            if not name:
                continue
            if skip_mdns and (proto == "mdns" or name.endswith(".local")):
                continue
            try:
                qt = int(qtypes[i]) if i < len(qtypes) else 0
            except ValueError:
                qt = 0
            tstr = type_name(qt) if qt else "QUERY"
            key = ("Query", tstr, name, proto)
            if key in seen_dns:
                continue
            seen_dns.add(key)
            dns_out.write(f"Query,{tstr},{name},{proto}\n")
        return

    resp_types = split_field(field_at(parts, IDX_RESP_TYPE))
    queues = build_rdata_queues(parts)

    if resp_types:
        for idx, t_raw in enumerate(resp_types):
            try:
                tnum = int(t_raw)
            except ValueError:
                continue
            fqdn = resp_names[idx] if idx < len(resp_names) else default_fqdn
            val = pop_rdata(tnum, idx, parts, queues)
            if val:
                emit_response(dns_out, seen_dns, type_name(tnum), val, fqdn, proto, skip_mdns)

    emit_fallback_responses(parts, default_fqdn, proto, skip_mdns, dns_out, seen_dns)


def _run_tshark_fields(
    pcap: str, display_filter: str = None, use_occurrence: bool = True
) -> Tuple[List[str], str, int]:
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-n",
        "-q",
    ]
    if use_occurrence:
        cmd.extend(["-E", "occurrence=a"])
    if display_filter:
        cmd.extend(["-Y", display_filter])
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return lines, proc.stderr or "", proc.returncode


def parse_pcap(pcap: str, ips_out, dns_out, skip_mdns: bool) -> Tuple[int, int, int]:
    seen_dns: Set[Tuple[str, str, str, str, str]] = set()
    ips_written: Set[str] = set()
    line_count = 0
    stderr = ""

    for display_filter in ("ip || ipv6 || dns", None):
        for use_occurrence in (True, False):
            lines, stderr, rc = _run_tshark_fields(
                pcap, display_filter, use_occurrence=use_occurrence
            )
            for line in lines:
                line_count += 1
                process_packet_line(
                    line, skip_mdns, ips_out, dns_out, seen_dns, ips_written
                )
            if line_count > 0:
                break
            if rc != 0 and stderr.strip() and "occurrence" in stderr.lower():
                continue
            if line_count > 0 or not use_occurrence:
                break
        if line_count > 0:
            break

    if os.environ.get("GETIPDNS_DEBUG"):
        print(
            f"getipdns_parse: {pcap} lines={line_count} ips={len(ips_written)} dns={len(seen_dns)}",
            file=sys.stderr,
        )
        if stderr.strip():
            print(stderr.strip(), file=sys.stderr)

    if line_count == 0 and stderr.strip():
        print(f"getipdns_parse: tshark stderr for {pcap}: {stderr.strip()}", file=sys.stderr)

    return line_count, len(ips_written), len(seen_dns)


def main() -> int:
    if len(sys.argv) != 5:
        print(
            f"Usage: {sys.argv[0]} <pcap> <ips_out> <dns_out> <skip_mdns 0|1>",
            file=sys.stderr,
        )
        return 2

    pcap, ips_path, dns_path, skip_mdns_s = sys.argv[1:5]
    skip_mdns = skip_mdns_s == "1"

    with open(ips_path, "a", encoding="utf-8") as ips_out, open(
        dns_path, "a", encoding="utf-8"
    ) as dns_out:
        lines, ips_n, dns_n = parse_pcap(pcap, ips_out, dns_out, skip_mdns)

    if lines == 0 and ips_n == 0 and dns_n == 0:
        print(f"getipdns_parse: no data extracted from {pcap}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
