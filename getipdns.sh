#!/bin/bash
# =============================================================================
# getipdns.sh — IP geolocation + DNS from pcaps (one tshark pass per file)
# Outputs: /tmp/ip2loc_report.{txt,csv} and /tmp/dns_report.{txt,csv}
# =============================================================================
set -euo pipefail

# === SETTINGS ===
DB="/home/rpaltaev/IP2LOCATION/IP2LOCATION-LITE-ASN.IPV6.BIN"
MMDB="/home/rpaltaev/IP2LOCATION/ip-to-asn.mmdb"
PCAP_DIR="/mnt/pcaps"
SERVICE="traffic-capture.service"

CORES=${CORES:-$(nproc)}
PARALLEL_JOBS=${PARALLEL_JOBS:-$CORES}
IP_REPORT_BASE="${IP_REPORT_BASE:-ip2loc_report}"
DNS_OUTPUT_BASE="${DNS_OUTPUT_BASE:-/tmp/dns_report}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp}"
SAVE_DNS_CSV="${SAVE_DNS_CSV:-1}"
SKIP_MDNS=${SKIP_MDNS:-0}
# ================

if [ ! -f "$DB" ]; then
    echo "ОШИБКА: Файл базы IP2Location не найден: $DB" >&2
    exit 1
fi
if [ ! -f "$MMDB" ]; then
    echo "ОШИБКА: Файл базы MaxMind не найден: $MMDB" >&2
    exit 1
fi
if ! command -v ip2location &>/dev/null; then
    echo "ОШИБКА: ip2location не установлен" >&2
    exit 1
fi
if ! command -v mmdblookup &>/dev/null; then
    echo "ОШИБКА: mmdblookup не установлен (пакет libmaxminddb)" >&2
    exit 1
fi
if ! command -v tshark &>/dev/null; then
    echo "ОШИБКА: tshark не установлен" >&2
    exit 1
fi

sleep 2
if pgrep -x tcpdump &>/dev/null; then
    echo "ПРЕДУПРЕЖДЕНИЕ: tcpdump ещё выполняется, ждём ещё..."
    sleep 3
fi

shopt -s nullglob
pcap_files=( "$PCAP_DIR"/capture-* )
[ ${#pcap_files[@]} -eq 0 ] && pcap_files=( "$PCAP_DIR"/*.pcap* "$PCAP_DIR"/*.pcapng )
shopt -u nullglob

if [ ${#pcap_files[@]} -eq 0 ]; then
    echo "ОШИБКА: Нет pcap-файлов в $PCAP_DIR" >&2
    exit 1
fi

echo "=== getipdns: найдено pcap-файлов: ${#pcap_files[@]} ==="
for f in "${pcap_files[@]}"; do echo "  - $f"; done

valid_files=()
for f in "${pcap_files[@]}"; do
    [ -s "$f" ] && valid_files+=("$f") || echo "Пропускаем пустой: $f" >&2
done

if [ ${#valid_files[@]} -eq 0 ]; then
    echo "ОШИБКА: нет файлов для анализа" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d /tmp/getipdns_XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

PARSE_AWK="$TMP_DIR/parse.awk"
cat > "$PARSE_AWK" << 'AWK_SCRIPT'
function type_str(t) {
    if (t == 1)  return "A"
    if (t == 2)  return "NS"
    if (t == 5)  return "CNAME"
    if (t == 6)  return "SOA"
    if (t == 12) return "PTR"
    if (t == 15) return "MX"
    if (t == 16) return "TXT"
    if (t == 28) return "AAAA"
    if (t == 33) return "SRV"
    if (t == 41) return "OPT"
    if (t == 255) return "ANY"
    return "TYPE" t
}
function is_mdns_port(p) {
    return p == 5353
}
function is_mdns_addr(v4, v6) {
    return v4 == "224.0.0.251" || v6 == "ff02::fb"
}
function emit_ips(field, ips_out) {
    if (field == "") return
    n = split(field, parts, ",")
    for (i = 1; i <= n; i++) {
        if (parts[i] != "") print parts[i] >> ips_out
    }
}
function dns_proto(ip4, ip6, dport, sport) {
    if (is_mdns_port(dport) || is_mdns_port(sport) || is_mdns_addr(ip4, ip6)) return "mdns"
    return "unicast"
}
BEGIN {
    if (ips_out == "" || dns_out == "") {
        print "parse.awk: ips_out and dns_out required" >> "/dev/stderr"
        exit 1
    }
}
{
    # Fields: ip.dst ipv6.dst dns.qry.name dns.qry.type dns.resp.name dns.resp.type
    #         dns.a dns.aaaa dns.cname dns.ptr dns.mx dns.srv dns.txt dns.soa dns.ns
    #         udp.dstport udp.srcport
    emit_ips($1, ips_out)
    emit_ips($2, ips_out)

    ip4 = $1
    ip6 = $2
    dport = $16 + 0
    sport = $17 + 0
    proto = dns_proto(ip4, ip6, dport, sport)

    if ($3 != "") {
        split($3, names, ",")
        split($4, types, ",")
        for (j = 1; j <= length(names); j++) {
            name = names[j]
            t = types[j] + 0
            if (name == "") continue
            if (skip_mdns == 1 && (proto == "mdns" || name ~ /\.local$/)) continue
            print "Query," type_str(t) "," name "," proto >> dns_out
        }
    }

    fqdn = ""
    if ($3 != "") { split($3, qnames, ","); fqdn = qnames[1] }
    if (fqdn == "" && $5 != "") { split($5, rnames, ","); fqdn = rnames[1] }
    restype = $6 + 0
    if (restype == 0) next

    typestr = type_str(restype)
    if (skip_mdns == 1 && (proto == "mdns" || fqdn ~ /\.local$/)) next

    if (restype == 1 && $7 != "") {
        split($7, ips, ",")
        for (i = 1; i <= length(ips); i++) if (ips[i] != "") print "Response," typestr "," ips[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 28 && $8 != "") {
        split($8, ips, ",")
        for (i = 1; i <= length(ips); i++) if (ips[i] != "") print "Response," typestr "," ips[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 5 && $9 != "") {
        split($9, cnames, ",")
        for (i = 1; i <= length(cnames); i++) if (cnames[i] != "") print "Response," typestr "," cnames[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 12 && $10 != "") {
        split($10, ptrs, ",")
        for (i = 1; i <= length(ptrs); i++) if (ptrs[i] != "") print "Response," typestr "," ptrs[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 15 && $11 != "") {
        split($11, mxs, ",")
        for (i = 1; i <= length(mxs); i++) if (mxs[i] != "") print "Response," typestr "," mxs[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 33 && $12 != "") {
        split($12, srvs, ",")
        for (i = 1; i <= length(srvs); i++) if (srvs[i] != "") print "Response," typestr "," srvs[i] "," fqdn "," proto >> dns_out
    }
    if (restype == 16 && $13 != "") {
        txt = $13
        gsub(/^"/, "", txt); gsub(/"$/, "", txt)
        print "Response," typestr "," txt "," fqdn "," proto >> dns_out
    }
    if (restype == 6 && $14 != "") {
        print "Response," typestr "," $14 "," fqdn "," proto >> dns_out
    }
    if (restype == 2 && $15 != "") {
        split($15, nss, ",")
        for (i = 1; i <= length(nss); i++) if (nss[i] != "") print "Response," typestr "," nss[i] "," fqdn "," proto >> dns_out
    }
}
END {
    close(ips_out)
    close(dns_out)
}
AWK_SCRIPT

process_pcap_file() {
    local pcap="$1"
    local ips_out="$2"
    local dns_out="$3"
    tshark -r "$pcap" -Y "ip or ipv6" -T fields \
        -E header=n -E separator=$'\t' -n -q 2>/dev/null \
        -e ip.dst \
        -e ipv6.dst \
        -e dns.qry.name \
        -e dns.qry.type \
        -e dns.resp.name \
        -e dns.resp.type \
        -e dns.a \
        -e dns.aaaa \
        -e dns.cname \
        -e dns.ptr.domain_name \
        -e dns.mx.mail_exchange \
        -e dns.srv.name \
        -e dns.txt \
        -e dns.soa.mname \
        -e dns.ns \
        -e udp.dstport \
        -e udp.srcport \
        | awk -v skip_mdns="$SKIP_MDNS" -v ips_out="$ips_out" -v dns_out="$dns_out" -F'\t' -f "$PARSE_AWK"
}
export -f process_pcap_file
export PARSE_AWK SKIP_MDNS

total_files=${#valid_files[@]}
files_per_core=$(( (total_files + CORES - 1) / CORES ))

echo "Извлекаем IP и DNS: один проход tshark на файл ($CORES потоков)..."

pids=()
for i in $(seq 0 $((CORES - 1))); do
    start=$(( i * files_per_core ))
    [ $start -ge $total_files ] && break
    part_files=("${valid_files[@]:start:files_per_core}")

    (
        ips_file="$TMP_DIR/ips_$i.txt"
        dns_file="$TMP_DIR/dns_$i.tmp"
        : > "$ips_file"
        : > "$dns_file"
        for f in "${part_files[@]}"; do
            process_pcap_file "$f" "$ips_file" "$dns_file"
        done
    ) &
    pids+=($!)
done

echo "Ожидаем завершения потоков tshark..."
for pid in "${pids[@]}"; do
    wait "$pid"
done

# =============================================================================
# Build reports in parallel (IP lookup + DNS formatting)
# =============================================================================
build_ip_report() {
    sort -u "$TMP_DIR"/ips_*.txt 2>/dev/null > "$TMP_DIR/unique_ips.txt" || : > "$TMP_DIR/unique_ips.txt"
    total_ips=$(wc -l < "$TMP_DIR/unique_ips.txt" | tr -d ' ')
    echo "Найдено уникальных IP: $total_ips"

    process_ip() {
        local ip="$1"
        local db="$2"
        local mmdb="$3"

        local asn1="N/A"
        local org1="N/A"
        local ip2loc_out
        ip2loc_out=$(ip2location -p "$ip" -d "$db" -e ip,as_number,as_name -n 2>/dev/null | tr -d '"')
        if [ -n "$ip2loc_out" ]; then
            asn1=$(echo "$ip2loc_out" | cut -d',' -f2)
            org1=$(echo "$ip2loc_out" | cut -d',' -f3)
            [ -z "$asn1" ] && asn1="N/A"
            [ -z "$org1" ] && org1="N/A"
        fi

        local asn2="N/A"
        local org2="N/A"
        local country="N/A"
        local domain="N/A"
        local mmdb_name="N/A"
        local network="N/A"

        local asn_raw
        asn_raw=$(mmdblookup --file "$mmdb" --ip "$ip" asn 2>/dev/null | grep -oE '"[0-9]+"' | tr -d '"' | head -1)
        [ -n "$asn_raw" ] && asn2="$asn_raw"

        local org_raw
        org_raw=$(mmdblookup --file "$mmdb" --ip "$ip" org 2>/dev/null | grep -oE '"[^"]*"' | sed 's/"//g' | head -1)
        [ -n "$org_raw" ] && org2="$org_raw"

        local country_raw
        country_raw=$(mmdblookup --file "$mmdb" --ip "$ip" country_code 2>/dev/null | grep -oE '"[^"]*"' | sed 's/"//g' | head -1)
        [ -n "$country_raw" ] && country="$country_raw"

        local domain_raw
        domain_raw=$(mmdblookup --file "$mmdb" --ip "$ip" domain 2>/dev/null | grep -oE '"[^"]*"' | sed 's/"//g' | head -1)
        [ -n "$domain_raw" ] && domain="$domain_raw"

        local name_raw
        name_raw=$(mmdblookup --file "$mmdb" --ip "$ip" name 2>/dev/null | grep -oE '"[^"]*"' | sed 's/"//g' | head -1)
        [ -n "$name_raw" ] && mmdb_name="$name_raw"

        local net_raw
        net_raw=$(mmdblookup --file "$mmdb" --ip "$ip" network 2>/dev/null | grep -oE '"[^"]*"' | sed 's/"//g' | head -1)
        [ -n "$net_raw" ] && network="$net_raw"

        echo "$ip,$asn1,$org1,$asn2,$org2,$country,$domain,$mmdb_name,$network"
    }
    export -f process_ip
    export DB MMDB

    raw="$TMP_DIR/ip2loc_raw.txt"
    > "$raw"

    if [ -s "$TMP_DIR/unique_ips.txt" ]; then
        echo "Запрашиваем данные IP параллельно (потоков: $PARALLEL_JOBS)..."
        cat "$TMP_DIR/unique_ips.txt" | xargs -n 1 -P "$PARALLEL_JOBS" -I {} bash -c 'process_ip "$1" "$DB" "$MMDB"' _ {} >> "$raw"
    fi

    output_txt="${OUTPUT_DIR}/${IP_REPORT_BASE}.txt"
    output_csv="${OUTPUT_DIR}/${IP_REPORT_BASE}.csv"

    echo "\"IP\",\"NETWORK\",\"ASN(IP2L)\",\"Org(IP2L)\",\"ASN(MMDB)\",\"Org(MMDB)\",\"CC\",\"Domain\",\"AS Name\"" > "$output_csv"

    {
        printf "%-30s %-20s %-12s %-30s %-12s %-30s %-5s %-25s %-25s\n" \
            "IP" "NETWORK" "ASN(IP2L)" "Org(IP2L)" "ASN(MMDB)" "Org(MMDB)" "CC" "Domain" "AS Name"
        printf "%s\n" "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    } > "$output_txt"

    if [ -s "$raw" ]; then
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,' "$raw" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | while IFS=',' read -r ip asn1 org1 asn2 org2 country domain mmdb_name network; do
            [ -z "$asn1" ] && asn1="N/A"
            [ -z "$org1" ] && org1="N/A"
            [ -z "$asn2" ] && asn2="N/A"
            [ -z "$org2" ] && org2="N/A"
            [ -z "$country" ] && country="N/A"
            [ -z "$domain" ] && domain="N/A"
            [ -z "$mmdb_name" ] && mmdb_name="N/A"
            [ -z "$network" ] && network="N/A"

            printf "%-30s %-20s AS%-10s %-30s AS%-10s %-30s %-5s %-25s %-25s\n" \
                "$ip" "$network" "$asn1" "$org1" "$asn2" "$org2" "$country" "$domain" "$mmdb_name" >> "$output_txt"

            echo "\"$ip\",\"$network\",\"AS$asn1\",\"$org1\",\"AS$asn2\",\"$org2\",\"$country\",\"$domain\",\"$mmdb_name\"" >> "$output_csv"
        done

        grep -E '^[0-9a-fA-F:]+,' "$raw" | sort | while IFS=',' read -r ip asn1 org1 asn2 org2 country domain mmdb_name network; do
            [ -z "$asn1" ] && asn1="N/A"
            [ -z "$org1" ] && org1="N/A"
            [ -z "$asn2" ] && asn2="N/A"
            [ -z "$org2" ] && org2="N/A"
            [ -z "$country" ] && country="N/A"
            [ -z "$domain" ] && domain="N/A"
            [ -z "$mmdb_name" ] && mmdb_name="N/A"
            [ -z "$network" ] && network="N/A"

            printf "%-30s %-20s AS%-10s %-30s AS%-10s %-30s %-5s %-25s %-25s\n" \
                "$ip" "$network" "$asn1" "$org1" "$asn2" "$org2" "$country" "$domain" "$mmdb_name" >> "$output_txt"

            echo "\"$ip\",\"$network\",\"AS$asn1\",\"$org1\",\"AS$asn2\",\"$org2\",\"$country\",\"$domain\",\"$mmdb_name\"" >> "$output_csv"
        done
    else
        echo "Не найдено ни одной записи в базах." >> "$output_txt"
    fi

    echo "----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" >> "$output_txt"
    echo "Всего уникальных IP: $total_ips" >> "$output_txt"

    echo "IP-отчёт сохранён:"
    echo "  TXT: $output_txt"
    echo "  CSV: $output_csv"
}

build_dns_report() {
    all_lines="$TMP_DIR/dns_all.txt"
    cat "$TMP_DIR"/dns_*.tmp 2>/dev/null | sort -u > "$all_lines" || : > "$all_lines"

    if [ ! -s "$all_lines" ]; then
        echo "ВНИМАНИЕ: DNS-записи не найдены." > "${DNS_OUTPUT_BASE}.txt"
        return 0
    fi

    {
        echo "=== DNS QUERIES ==="
        grep "^Query," "$all_lines" | sort -u | sed 's/,/ | /g'
        echo ""
        echo "=== DNS RESPONSES ==="
        grep "^Response," "$all_lines" | sort -u | sed 's/,/ | /g'
    } > "${DNS_OUTPUT_BASE}.txt"

    if [ "$SAVE_DNS_CSV" -eq 1 ]; then
        csv_file="${DNS_OUTPUT_BASE}.csv"
        {
            echo "Direction,Type,Value,FQDN,Protocol"
            cat "$all_lines"
        } > "$csv_file"
        echo "DNS CSV сохранён: $csv_file"
    fi

    {
        echo ""
        echo "=== СТАТИСТИКА ==="
        total=$(wc -l < "$all_lines")
        echo "Всего уникальных записей: $total"

        queries=$(grep -c "^Query," "$all_lines" || true)
        responses=$(grep -c "^Response," "$all_lines" || true)
        echo "Запросов: $queries, Ответов: $responses"

        unique_domains=$(grep "^Query," "$all_lines" | cut -d',' -f4 | sort -u | wc -l)
        echo "Уникальных доменов в запросах: $unique_domains"

        echo -e "\nТоп-10 запрашиваемых доменов:"
        grep "^Query," "$all_lines" | cut -d',' -f4 | sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "  %6d  %s\n", $1, $2}'

        echo -e "\nРаспределение по типам (запросы):"
        grep "^Query," "$all_lines" | cut -d',' -f2 | sort | uniq -c | sort -rn | \
            awk '{printf "  %6d  %s\n", $1, $2}'

        mdns=$(grep -c ",mdns$" "$all_lines" || true)
        echo -e "\nПротоколы: mDNS $mdns, Unicast $((total - mdns))"
    } >> "${DNS_OUTPUT_BASE}.txt"

    echo "DNS-отчёт: ${DNS_OUTPUT_BASE}.txt"
}

export -f build_ip_report build_dns_report
export TMP_DIR OUTPUT_DIR IP_REPORT_BASE DNS_OUTPUT_BASE SAVE_DNS_CSV PARALLEL_JOBS DB MMDB

echo "Формируем отчёты IP и DNS параллельно..."
build_ip_report &
ip_report_pid=$!
build_dns_report &
dns_report_pid=$!

wait "$ip_report_pid"
wait "$dns_report_pid"

echo "=== getipdns: готово ==="
