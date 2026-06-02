#!/usr/bin/env python3
"""
Parse a pcap with tshark JSON: extract destination IPs and all DNS queries/responses.
Output format (append to files):
  IPs: one address per line in ips_out
  DNS: Query,<type>,<name>,<proto>  or  Response,<type>,<value>,<fqdn>,<proto>
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

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
    99: "SPF",
    255: "ANY",
}

# tshark field -> RR type (for queue / fallback extraction)
FIELD_TO_TYPE: Dict[str, int] = {
    "dns.a": 1,
    "dns.aaaa": 28,
    "dns.cname": 5,
    "dns.ptr.domain_name": 12,
    "dns.mx.mail_exchange": 15,
    "dns.txt": 16,
    "dns.srv.name": 33,
    "dns.srv.target": 33,
    "dns.soa.mname": 6,
    "dns.ns": 2,
    "dns.resp.data": 0,
}

RDATA_FIELDS_BY_TYPE: Dict[int, List[str]] = {
    1: ["dns.a"],
    28: ["dns.aaaa"],
    5: ["dns.cname"],
    12: ["dns.ptr.domain_name"],
    15: ["dns.mx.mail_exchange"],
    16: ["dns.txt"],
    33: ["dns.srv.name", "dns.srv.target"],
    6: ["dns.soa.mname"],
    2: ["dns.ns"],
}


def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"TYPE{t}")


def explode_values(value: Any) -> List[str]:
    """Turn tshark JSON field values into a flat list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            out.extend(explode_values(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(explode_values(item))
        return out

    text = str(value).strip()
    if not text:
        return []

    # Quoted TXT blobs may contain commas
    if text.startswith('"') and text.endswith('"'):
        return [text[1:-1]]

    parts = [p.strip() for p in text.split(",")]
    return [p for p in parts if p]


def normalize_dns_key(key: str) -> str:
    key = key.replace("dns.dns.", "dns.")
    if key.startswith("dns."):
        return key
    idx = key.find(".dns.")
    if idx >= 0:
        return "dns." + key[idx + 5 :]
    if key.startswith("dns"):
        return "dns." + key[3:].lstrip(".")
    return key


def collect_dns_fields(layers: Any) -> Dict[str, List[str]]:
    """Collect all dns.* fields from tshark JSON layers (nested or flat)."""
    collected: Dict[str, List[str]] = defaultdict(list)

    def add_field(raw_key: str, value: Any) -> None:
        key = normalize_dns_key(raw_key)
        if not key.startswith("dns."):
            return
        for part in explode_values(value):
            if part:
                collected[key].append(part)

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if not isinstance(k, str):
                continue
            if "dns" in k.lower():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        add_field(k2, v2)
                else:
                    add_field(k, v)
            elif isinstance(v, dict):
                walk(v)

    walk(layers)
    return collected


def first_val(fields: Dict[str, List[str]], *keys: str) -> str:
    for key in keys:
        vals = fields.get(key, [])
        if vals:
            return vals[0]
    return ""


def field_vals(fields: Dict[str, List[str]], key: str) -> List[str]:
    return list(fields.get(key, []))


def is_mdns(fields: Dict[str, List[str]], ip4: str, ip6: str) -> bool:
    for port_key in ("dns.udp.dstport", "dns.udp.srcport", "udp.dstport", "udp.srcport"):
        for p in field_vals(fields, port_key):
            try:
                if int(p) == 5353:
                    return True
            except ValueError:
                pass
    if ip4 == "224.0.0.251" or ip6 == "ff02::fb":
        return True
    return False


def is_dns_response(fields: Dict[str, List[str]]) -> bool:
    resp = first_val(fields, "dns.flags.response")
    if resp in ("1", "True", "true"):
        return True
    flags = first_val(fields, "dns.flags")
    if flags:
        try:
            value = int(str(flags), 0)
            return bool(value & 0x8000)
        except ValueError:
            pass
    counts = field_vals(fields, "dns.count.answers")
    if counts:
        try:
            if int(counts[0]) > 0:
                return True
        except ValueError:
            pass
    if field_vals(fields, "dns.resp.type"):
        return True
    for field in FIELD_TO_TYPE:
        if field not in ("dns.resp.data",) and field_vals(fields, field):
            return True
    return False


def build_type_queues(fields: Dict[str, List[str]]) -> Dict[int, Deque[str]]:
    queues: Dict[int, Deque[str]] = defaultdict(deque)
    for field, tnum in FIELD_TO_TYPE.items():
        if tnum <= 0:
            continue
        for val in field_vals(fields, field):
            queues[tnum].append(val)
    return queues


def format_mx(fields: Dict[str, List[str]], idx: int) -> str:
    prefs = field_vals(fields, "dns.mx.preference")
    hosts = field_vals(fields, "dns.mx.mail_exchange")
    if idx < len(hosts):
        host = hosts[idx]
        if idx < len(prefs) and prefs[idx]:
            return f"{prefs[idx]} {host}"
        return host
    return ""


def format_srv(fields: Dict[str, List[str]], idx: int) -> str:
    names = field_vals(fields, "dns.srv.name") or field_vals(fields, "dns.srv.target")
    pri = field_vals(fields, "dns.srv.priority")
    weight = field_vals(fields, "dns.srv.weight")
    port = field_vals(fields, "dns.srv.port")
    if idx < len(names):
        parts = []
        if idx < len(pri) and pri[idx]:
            parts.append(pri[idx])
        if idx < len(weight) and weight[idx]:
            parts.append(weight[idx])
        if idx < len(port) and port[idx]:
            parts.append(port[idx])
        parts.append(names[idx])
        return " ".join(parts)
    return ""


def format_soa(fields: Dict[str, List[str]], idx: int) -> str:
    parts_keys = [
        "dns.soa.mname",
        "dns.soa.rname",
        "dns.soa.serial_number",
        "dns.soa.refresh_interval",
        "dns.soa.retry_interval",
        "dns.soa.expire_limit",
        "dns.soa.minimum_ttl",
    ]
    chunks = []
    for key in parts_keys:
        vals = field_vals(fields, key)
        if idx < len(vals) and vals[idx]:
            chunks.append(vals[idx])
    return " ".join(chunks)


def pop_rdata_for_type(
    tnum: int,
    idx: int,
    fields: Dict[str, List[str]],
    queues: Dict[int, Deque[str]],
) -> str:
    if tnum == 15:
        mx = format_mx(fields, idx)
        if mx:
            return mx
    if tnum == 33:
        srv = format_srv(fields, idx)
        if srv:
            return srv
    if tnum == 6:
        soa = format_soa(fields, idx)
        if soa:
            return soa

    q = queues.get(tnum)
    if q:
        return q.popleft()

    for field in RDATA_FIELDS_BY_TYPE.get(tnum, []):
        vals = field_vals(fields, field)
        if idx < len(vals):
            return vals[idx]
    return ""


def emit_all_rdata_fields(
    fields: Dict[str, List[str]],
    fqdn: str,
    proto: str,
    skip_mdns: bool,
    out,
    seen: Set[Tuple[str, str, str, str, str]],
) -> None:
    """Fallback: emit every populated rdata field (catches RRs missing from dns.resp.type list)."""
    if skip_mdns and (proto == "mdns" or (fqdn and fqdn.endswith(".local"))):
        return

    for field, tnum in FIELD_TO_TYPE.items():
        if tnum <= 0:
            continue
        tstr = type_name(tnum)
        vals = field_vals(fields, field)
        if tnum == 15:
            prefs = field_vals(fields, "dns.mx.preference")
            for i, host in enumerate(field_vals(fields, "dns.mx.mail_exchange")):
                pref = prefs[i] if i < len(prefs) else ""
                val = f"{pref} {host}".strip() if pref else host
                _emit_response(out, seen, tstr, val, fqdn, proto, skip_mdns)
            continue
        if tnum == 33:
            for i in range(max(len(field_vals(fields, "dns.srv.name")), len(field_vals(fields, "dns.srv.target")))):
                val = format_srv(fields, i)
                if val:
                    _emit_response(out, seen, tstr, val, fqdn, proto, skip_mdns)
            continue
        if tnum == 6:
            for i in range(len(field_vals(fields, "dns.soa.mname"))):
                val = format_soa(fields, i)
                if val:
                    _emit_response(out, seen, tstr, val, fqdn, proto, skip_mdns)
            continue
        for val in vals:
            _emit_response(out, seen, tstr, val, fqdn, proto, skip_mdns)

    # Generic unknown-type rdata
    for val in field_vals(fields, "dns.resp.data"):
        _emit_response(out, seen, "DATA", val, fqdn, proto, skip_mdns)


def _emit_response(out, seen, tstr: str, val: str, fqdn: str, proto: str, skip_mdns: bool) -> None:
    if not val:
        return
    if skip_mdns and (proto == "mdns" or (fqdn and fqdn.endswith(".local"))):
        return
    key = ("Response", tstr, val, fqdn, proto)
    if key in seen:
        return
    seen.add(key)
    out.write(f"Response,{tstr},{val},{fqdn},{proto}\n")


def extract_ips_from_layers(layers: Any) -> Set[str]:
    ips: Set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                kn = k.lower()
                if kn in ("ip.dst", "ip.dst_host") or kn.endswith(".ip.dst"):
                    ips.update(explode_values(v))
                elif kn in ("ipv6.dst", "ipv6.dst_host") or kn.endswith(".ipv6.dst"):
                    ips.update(explode_values(v))
                elif isinstance(v, dict):
                    walk(v)
                elif isinstance(v, list):
                    for item in v:
                        walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(layers)
    return {ip for ip in ips if ip and ip != "0.0.0.0"}


def process_dns_packet(
    fields: Dict[str, List[str]],
    skip_mdns: int,
    dns_out,
    seen: Set[Tuple[str, str, str, str, str]],
) -> None:
    ip4 = first_val(fields, "dns.ip.dst", "ip.dst")
    ip6 = first_val(fields, "ipv6.dst")
    proto = "mdns" if is_mdns(fields, ip4, ip6) else "unicast"

    qnames = field_vals(fields, "dns.qry.name")
    qtypes = field_vals(fields, "dns.qry.type")
    default_fqdn = qnames[0] if qnames else first_val(fields, "dns.resp.name")

    response = is_dns_response(fields)

    if not response:
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
            if key in seen:
                continue
            seen.add(key)
            dns_out.write(f"Query,{tstr},{name},{proto}\n")

    resp_types = field_vals(fields, "dns.resp.type")
    resp_names = field_vals(fields, "dns.resp.name")
    queues = build_type_queues(fields)

    if response:
        if resp_types:
            for idx, t_raw in enumerate(resp_types):
                try:
                    tnum = int(t_raw)
                except ValueError:
                    continue
                tstr = type_name(tnum)
                fqdn = resp_names[idx] if idx < len(resp_names) else default_fqdn
                val = pop_rdata_for_type(tnum, idx, fields, queues)
                if not val:
                    continue
                _emit_response(dns_out, seen, tstr, val, fqdn, proto, bool(skip_mdns))
        else:
            emit_all_rdata_fields(
                fields, default_fqdn, proto, bool(skip_mdns), dns_out, seen
            )
        # Authority / additional RRs and fields not listed in dns.resp.type
        emit_all_rdata_fields(
            fields, default_fqdn, proto, bool(skip_mdns), dns_out, seen
        )


def parse_pcap(pcap: str, ips_out, dns_out, skip_mdns: int) -> None:
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-Y",
        "dns || ip || ipv6",
        "-T",
        "json",
        "-n",
        "-l",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    seen_dns: Set[Tuple[str, str, str, str, str]] = set()
    ips_written: Set[str] = set()

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line or line in ("[", "]"):
            continue
        if line.endswith(","):
            line = line[:-1]
        try:
            packet = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(packet, list):
            items = packet
        else:
            items = [packet]

        for item in items:
            if not isinstance(item, dict):
                continue
            layers = item.get("_source", {}).get("layers", {})
            if not layers:
                continue

            for ip in extract_ips_from_layers(layers):
                if ip not in ips_written:
                    ips_written.add(ip)
                    ips_out.write(ip + "\n")

            dns_fields = collect_dns_fields(layers)
            if not dns_fields:
                continue

            process_dns_packet(dns_fields, skip_mdns, dns_out, seen_dns)

    proc.wait()


def main() -> int:
    if len(sys.argv) != 5:
        print(
            f"Usage: {sys.argv[0]} <pcap> <ips_out> <dns_out> <skip_mdns 0|1>",
            file=sys.stderr,
        )
        return 2

    pcap, ips_path, dns_path, skip_mdns_s = sys.argv[1:5]
    skip_mdns = 1 if skip_mdns_s == "1" else 0

    with open(ips_path, "a", encoding="utf-8") as ips_out, open(
        dns_path, "a", encoding="utf-8"
    ) as dns_out:
        parse_pcap(pcap, ips_out, dns_out, skip_mdns)

    return 0


if __name__ == "__main__":
    sys.exit(main())
