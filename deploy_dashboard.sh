#!/bin/bash
# Run on NanoPi from project root: bash deploy_dashboard.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "=== 1. Verify pcap file detection (before restart) ==="
python3 python_app/verify_download.py

echo ""
echo "=== 2. Install getipdns.sh ==="
sudo cp getipdns.sh /usr/local/bin/getipdns.sh
sudo cp getipdns_parse.py /usr/local/bin/getipdns_parse.py
sudo chmod +x /usr/local/bin/getipdns.sh /usr/local/bin/getipdns_parse.py

echo ""
echo "=== 3. Install systemd unit ==="
sudo cp python_app/systemd_dashboard.service /etc/systemd/system/dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable dashboard.service

echo ""
echo "=== 4. Stop anything else on port 3000 ==="
if command -v ss >/dev/null 2>&1; then
  ss -tlnp | grep ':3000' || true
fi

echo ""
echo "=== 5. Restart dashboard ==="
sudo systemctl restart dashboard
sleep 2
sudo systemctl status dashboard --no-pager || true

echo ""
echo "=== 6. Startup log (must show download_available) ==="
sudo journalctl -u dashboard -n 15 --no-pager

echo ""
echo "=== 7. API check ==="
curl -s http://localhost:3000/api/download/status | python3 -m json.tool
echo ""
curl -s http://localhost:3000/api/metrics | python3 -c "
import sys, json
m = json.load(sys.stdin)
print('dashboard_build:', m.get('dashboard_build'))
print('download_available:', m.get('download_available'))
print('files:', m.get('log_files_available'))
if m.get('dashboard_build') != '20260601-getipdns-v1':
    print('ERROR: old code still running on port 3000!')
    sys.exit(1)
if not m.get('download_available'):
    print('WARN: download_available is False — check /mnt/pcaps permissions')
"

echo ""
echo "=== Done ==="
