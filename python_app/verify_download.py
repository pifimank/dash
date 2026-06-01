#!/usr/bin/env python3
"""Quick check: can the dashboard see files for 'Скачать логи'?"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import system_scripts

status = system_scripts.get_download_status()
print("=== Download status ===")
for key, value in status.items():
    print(f"{key}: {value}")

if status["download_available"]:
    print("\nOK: download should be enabled in UI")
    sys.exit(0)

print("\nFAIL: no files matched. Expected:")
print("  /tmp/ip2loc_report.* or /tmp/dns_report.*")
print("  /mnt/pcaps/capture* (e.g. capture-20260601-132616.pcap00)")
sys.exit(1)
