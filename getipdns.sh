#!/bin/bash
# =============================================================================
# getipdns.sh — combined IP geolocation + DNS analysis from pcaps (one job)
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

total_files=${#valid_files[@]}
files_per_core=$(( (total_files + CORES - 1) / CORES ))

echo "Извлекаем IP и DNS параллельно ($CORES потоков)..."

pids=()
for i in $(seq 0 $((CORES - 1))); do
    start=$(( i * files_per_core ))
    [ $start -ge $total_files ] && break
    part_files=("${valid_files[@]:start:files_per_core}")

    (
        args=()
        for f in "${part_files[@]}"; do
            args+=(-r "$f")
        done

        if [ ${#args[@]} -gt 0 ]; then
            tshark "${args[@]}" -T fields -e ip.dst -e ipv6.dst -Y "ip or ipv6" 2>/dev/null \
                | tr '\t' '\n' | sed '/^$/d' >> "$TMP_DIR/ips_$i.txt"
        fi

        for f in "${part_files[@]}"; do
            tshark -r "$f" -Y "dns.qry.name" -T fields -e dns.qry.name -e dns.qry.type -e udp.port -e ip.dst \
                -E header=n -E separator=$'\t' -n -q 2>/dev/null | \
            awk -v skip_mdns="$SKIP_MDNS" -F'\t' '
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
                if (t == 255) return "ANY"
                return "TYPE" t
            }
            {
                if ($1 == "") next
                split($1, names, ",")
                split($2, types, ",")
                proto = "unicast"
                if ($3 == 5353 || $4 == "224.0.0.251" || $4 == "ff02::fb") proto = "mdns"
                for (j=1; j<=length(names); j++) {
                    name = names[j]
                    t = types[j] + 0
                    if (name == "") continue
                    if (skip_mdns == 1 && (proto == "mdns" || name ~ /\.local$/)) continue
                    print "Query," type_str(t) "," name "," proto
                }
            }' >> "$TMP_DIR/dns_$i.tmp"

            tshark -r "$f" \
                -Y "dns.a or dns.aaaa or dns.cname or dns.ptr.domain_name or dns.mx.mail_exchange or dns.srv.name or dns.txt or dns.soa.mname or dns.ns" \
                -T fields \
                -e dns.qry.name -e dns.resp.name -e dns.resp.type \
                -e dns.a -e dns.aaaa -e dns.cname \
                -e dns.ptr.domain_name -e dns.mx.mail_exchange -e dns.srv.name \
                -e dns.txt -e dns.soa.mname -e dns.ns \
                -e udp.port -e ip.dst \
                -E header=n -E separator=$'\t' -n -q 2>/dev/null | \
            awk -v skip_mdns="$SKIP_MDNS" -F'\t' '
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
                return "TYPE" t
            }
            {
                fqdn = ""
                if ($1 != "") { split($1, qnames, ","); fqdn = qnames[1] }
                if (fqdn == "" && $2 != "") { split($2, rnames, ","); fqdn = rnames[1] }
                restype = $3 + 0
                typestr = type_str(restype)

                proto = "unicast"
                if ($13 == 5353 || $14 == "224.0.0.251" || $14 == "ff02::fb") proto = "mdns"

                if (skip_mdns == 1 && (proto == "mdns" || fqdn ~ /\.local$/)) next

                if (restype == 1 && $4 != "") {
                    split($4, ips, ",")
                    for (i=1; i<=length(ips); i++) if (ips[i] != "") print "Response," typestr "," ips[i] "," fqdn "," proto
                }
                if (restype == 28 && $5 != "") {
                    split($5, ips, ",")
                    for (i=1; i<=length(ips); i++) if (ips[i] != "") print "Response," typestr "," ips[i] "," fqdn "," proto
                }
                if (restype == 5 && $6 != "") {
                    split($6, cnames, ",")
                    for (i=1; i<=length(cnames); i++) if (cnames[i] != "") print "Response," typestr "," cnames[i] "," fqdn "," proto
                }
                if (restype == 12 && $7 != "") {
                    split($7, ptrs, ",")
                    for (i=1; i<=length(ptrs); i++) if (ptrs[i] != "") print "Response," typestr "," ptrs[i] "," fqdn "," proto
                }
                if (restype == 15 && $8 != "") {
                    split($8, mxs, ",")
                    for (i=1; i<=length(mxs); i++) if (mxs[i] != "") print "Response," typestr "," mxs[i] "," fqdn "," proto
                }
                if (restype == 33 && $9 != "") {
                    split($9, srvs, ",")
                    for (i=1; i<=length(srvs); i++) if (srvs[i] != "") print "Response," typestr "," srvs[i] "," fqdn "," proto
                }
                if (restype == 16 && $10 != "") {
                    gsub(/^"/, "", $10); gsub(/"$/, "", $10)
                    print "Response," typestr "," $10 "," fqdn "," proto
                }
                if (restype == 6 && $11 != "") {
                    print "Response," typestr "," $11 "," fqdn "," proto
                }
                if (restype == 2 && $12 != "") {
                    split($12, nss, ",")
                    for (i=1; i<=length(nss); i++) if (nss[i] != "") print "Response," typestr "," nss[i] "," fqdn "," proto
                }
            }' >> "$TMP_DIR/dns_$i.tmp"
        done
    ) &
    pids+=($!)
done

echo "Ожидаем завершения потоков tshark..."
for pid in "${pids[@]}"; do
    wait "$pid"
done

# =============================================================================
# IP report (ip2loc_report.*)
# =============================================================================
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

# =============================================================================
# DNS report (dns_report.*)
# =============================================================================
all_lines="$TMP_DIR/dns_all.txt"
cat "$TMP_DIR"/dns_*.tmp 2>/dev/null | sort -u > "$all_lines" || : > "$all_lines"

if [ ! -s "$all_lines" ]; then
    echo "ВНИМАНИЕ: DNS-записи не найдены." | tee "${DNS_OUTPUT_BASE}.txt"
    echo "=== getipdns: готово ==="
    exit 0
fi

{
    echo "=== DNS QUERIES ==="
    grep "^Query," "$all_lines" | sort -u | sed 's/,/ | /g'
    echo ""
    echo "=== DNS RESPONSES ==="
    grep "^Response," "$all_lines" | sort -u | sed 's/,/ | /g'
} | tee "${DNS_OUTPUT_BASE}.txt"

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
} | tee -a "${DNS_OUTPUT_BASE}.txt"

echo ""
echo "DNS-отчёт: ${DNS_OUTPUT_BASE}.txt"
echo "=== getipdns: готово ==="
