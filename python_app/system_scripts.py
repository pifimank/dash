import os
import sys
import json
import glob
import time
import shlex
import shutil
import threading
import urllib.request
import zipfile
import subprocess

# Load paths
PATHS_FILE = os.path.join(os.path.dirname(__file__), 'paths.json')
with open(PATHS_FILE, 'r') as f:
    PATHS = json.load(f)

_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
_PATHS_FILE = PATHS_FILE

def run_command(args, shell=False, timeout=None):
    """Run a system command and return (stdout, stderr, returncode)."""
    try:
        res = subprocess.run(
            args,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return res.stdout, res.stderr, res.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s" if timeout else "Command timed out", -1
    except Exception as e:
        return "", str(e), -1

def run_background_command(args, shell=False):
    """Start a command in the background without waiting for completion."""
    try:
        subprocess.Popen(args, shell=shell, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, ""
    except Exception as e:
        return False, str(e)

def download_and_extract_db(url, dest_dir, zip_filename):
    """Download db from url into dest_dir, save as zip_filename, and unzip it."""
    os.makedirs(dest_dir, exist_ok=True)
    zip_path = os.path.join(dest_dir, zip_filename)

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req, timeout=60) as response, open(zip_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as e:
        return False, f"Failed to download {url}: {str(e)}"

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)
    except Exception as e:
        return False, f"Failed to unzip {zip_path}: {str(e)}"

    return True, ""

_update_db_lock = threading.Lock()
_update_db_running = False

def update_databases():
    """Download and extract both DBs as specified in user criteria."""
    global _update_db_running
    with _update_db_lock:
        if _update_db_running:
            return True, ""
        _update_db_running = True

    try:
        url1 = PATHS["ip2location_url"]
        dir1 = PATHS["ip2location_dir"]
        zip1 = PATHS["ip2location_zip"]

        success1, err1 = download_and_extract_db(url1, dir1, zip1)
        if not success1:
            return False, f"Error DB1: {err1}"

        url2 = PATHS["example_url"]
        zip2 = PATHS["example_zip"]
        success2, err2 = download_and_extract_db(url2, dir1, zip2)
        if not success2:
            return False, f"Error DB2: {err2}"

        return True, ""
    finally:
        with _update_db_lock:
            _update_db_running = False

def is_update_db_running():
    with _update_db_lock:
        return _update_db_running

def check_traffic_capture_status():
    """Check if traffic-capture service is active using systemctl."""
    stdout, _, _ = run_command(["systemctl", "is-active", "traffic-capture"])
    return stdout.strip() == "active"

def control_traffic_capture(action):
    """Start or stop traffic-capture service."""
    if action not in ["start", "stop"]:
        return False, "Invalid action"
    stdout, stderr, code = run_command(["systemctl", action, "traffic-capture"])
    if code != 0:
        return False, f"systemctl {action} failed: {stderr or stdout}"
    return True, ""

CLEAN_DIRECTORIES = ["/mnt/pcaps", "/tmp"]
_clean_lock = threading.Lock()
_clean_running = False

def _clear_directory_contents(directory):
    """Remove all files and subdirectories inside directory, keep the directory itself."""
    if not os.path.isdir(directory):
        return []

    errors = []
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        try:
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
        except Exception as e:
            errors.append(f"{path}: {e}")
    return errors

def clean_directories():
    """Delete everything inside /mnt/pcaps and /tmp."""
    global _clean_running
    with _clean_lock:
        if _clean_running:
            return True, ""
        _clean_running = True

    try:
        errors = []
        for directory in CLEAN_DIRECTORIES:
            errors.extend(_clear_directory_contents(directory))
        if errors:
            return False, "; ".join(errors)
        return True, ""
    finally:
        with _clean_lock:
            _clean_running = False

def is_clean_running():
    with _clean_lock:
        return _clean_running

LOG_REPORT_GLOBS = ["ip2loc_report.*", "dns_report.*"]
PCAP_GLOB = "capture.*"

def _collect_download_archive_entries():
    """Collect ip2loc_report.* / dns_report.* from /tmp and capture.* from /mnt/pcaps."""
    entries = []
    seen = set()

    tmp_dir = PATHS["tmp_dir"]
    for pattern in LOG_REPORT_GLOBS:
        for file_path in glob.glob(os.path.join(tmp_dir, pattern)):
            if not os.path.isfile(file_path):
                continue
            arcname = os.path.basename(file_path)
            key = ("report", arcname)
            if key in seen:
                continue
            seen.add(key)
            entries.append((file_path, arcname))

    pcap_dir = PATHS.get("pcap_dir", "/mnt/pcaps")
    if os.path.isdir(pcap_dir):
        for file_path in glob.glob(os.path.join(pcap_dir, PCAP_GLOB)):
            if not os.path.isfile(file_path):
                continue
            arcname = os.path.join("pcaps", os.path.basename(file_path))
            key = ("pcap", arcname)
            if key in seen:
                continue
            seen.add(key)
            entries.append((file_path, arcname))

    return entries

def list_download_files():
    """Return archive entry names available for download."""
    return [arcname for _, arcname in _collect_download_archive_entries()]

def has_download_files():
    """True if any ip2loc_report.*, dns_report.* or /mnt/pcaps/capture.* files exist."""
    return len(_collect_download_archive_entries()) > 0

def create_logs_zip(zip_path):
    """Build ZIP archive with reports and pcap files."""
    entries = _collect_download_archive_entries()
    if not entries:
        return False, "No matching files found: /tmp/ip2loc_report.*, /tmp/dns_report.*, /mnt/pcaps/capture.*"

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for file_path, arcname in entries:
                zip_file.write(file_path, arcname)
        return True, ""
    except Exception as e:
        return False, f"Failed to build zip: {e}"

def ya_reboot():
    """Reboot the operating system immediately."""
    _, stderr, code = run_command(["shutdown", "-r", "now"])
    if code != 0:
        return False, f"Failed to execute reboot: {stderr}"
    return True, ""

# --- Background analysis jobs (tracked by PID, not Popen) ---
_active_pids = {
    "packet_analysis": None,
    "dns_analysis": None,
}
_process_lock = threading.Lock()
_spawn_lock = threading.Lock()

def _is_pid_active_unlocked(key):
    pid = _active_pids.get(key)
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        _active_pids[key] = None
        return False

def _start_background_script(key, script_path, fallback_sleep):
    """Launch a shell script fully detached from the web server process."""
    with _process_lock:
        if _is_pid_active_unlocked(key):
            return True, ""

    if os.path.exists(script_path):
        launch_cmd = f"nohup /bin/bash {shlex.quote(script_path)} >/dev/null 2>&1 & echo $!"
    else:
        launch_cmd = f"sleep {fallback_sleep} & echo $!"

    # Serialize fork/spawn so it never races with other threads in the process.
    with _spawn_lock:
        result = subprocess.run(
            launch_cmd,
            shell=True,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return False, (result.stderr or result.stdout or "Failed to start background script").strip()
        try:
            pid = int(result.stdout.strip().split()[-1])
        except (ValueError, IndexError):
            return False, "Failed to read background process PID"

    with _process_lock:
        _active_pids[key] = pid
    return True, ""

def run_as_report_async():
    """Run packet analysis command asynchronously in background."""
    return _start_background_script(
        "packet_analysis",
        PATHS["as_report_script"],
        fallback_sleep=12,
    )

def run_dns_report_async():
    """Run DNS analysis command asynchronously in background."""
    return _start_background_script(
        "dns_analysis",
        PATHS["dns_report_script"],
        fallback_sleep=15,
    )

def is_action_active(key):
    """Check if process is active."""
    with _process_lock:
        return _is_pid_active_unlocked(key)

# --- Metrics collection via /proc (no subprocess — safe under load) ---
_prev_cpu_stats = {}
_prev_proc_stats = {}
_metrics_state_lock = threading.Lock()

def _format_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.read().split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        minutes = int((secs % 3600) // 60)
        seconds = int(secs % 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        if days > 0:
            return f"{time_str} up {days} days"
        return f"{time_str} up 0 days"
    except Exception:
        return "Uptime query not available"

def _read_cpu_cores():
    if not os.path.exists("/proc/stat"):
        sec_hash = int(time.time())
        return [{"core": f"cpu{i}", "load": float((sec_hash * (i + 1) % 45) + 15)} for i in range(8)]

    with open("/proc/stat", "r") as f:
        lines = f.readlines()

    cores_data = []
    with _metrics_state_lock:
        for line in lines:
            parts = line.split()
            if len(parts) <= 4 or not parts[0].startswith("cpu") or parts[0] == "cpu":
                continue
            core_name = parts[0]
            fields = [float(x) for x in parts[1:8]]
            idle = fields[3] + fields[4]
            total = sum(fields)

            if core_name in _prev_cpu_stats:
                prev_total, prev_idle = _prev_cpu_stats[core_name]
                diff_total = total - prev_total
                diff_idle = idle - prev_idle
                if diff_total > 0:
                    usage = (diff_total - diff_idle) / diff_total
                    load = round(max(0.0, min(100.0, usage * 100)), 1)
                else:
                    load = 0.0
            elif total > 0:
                load = round(max(0.0, min(100.0, (total - idle) / total * 100)), 1)
            else:
                load = 0.0

            _prev_cpu_stats[core_name] = (total, idle)
            cores_data.append({"core": core_name, "load": load})
    return cores_data

def _read_memory():
    ram = {"total": 0, "used": 0, "free": 0}
    swap = {"total": 0, "used": 0, "free": 0}
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                info[key] = int(value.strip().split()[0])

        total_mb = info.get("MemTotal", 0) / 1024
        available_mb = info.get("MemAvailable", info.get("MemFree", 0)) / 1024
        free_mb = info.get("MemFree", 0) / 1024
        used_mb = max(0.0, total_mb - available_mb)
        ram = {"total": total_mb, "used": used_mb, "free": free_mb}

        swap_total = info.get("SwapTotal", 0) / 1024
        swap_free = info.get("SwapFree", 0) / 1024
        swap_used = max(0.0, swap_total - swap_free)
        swap = {"total": swap_total, "used": swap_used, "free": swap_free}
    except Exception:
        pass
    return ram, swap

def _read_disks():
    disks = []
    seen_mounts = set()
    try:
        with open("/proc/mounts", "r") as f:
            mount_entries = f.readlines()
        for line in mount_entries:
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mount_point, fstype = parts[0], parts[1], parts[2]
            if fstype in ("proc", "sysfs", "devpts", "tmpfs", "cgroup", "cgroup2", "pstore", "bpf", "tracefs", "debugfs", "securityfs", "hugetlbfs", "mqueue", "configfs", "fusectl", "binfmt_misc"):
                continue
            if not device.startswith("/dev/") and mount_point != "/":
                continue
            if mount_point in seen_mounts:
                continue
            try:
                stat = os.statvfs(mount_point)
            except OSError:
                continue
            seen_mounts.add(mount_point)
            total_mb = stat.f_blocks * stat.f_frsize / (1024 * 1024)
            free_mb = stat.f_bavail * stat.f_frsize / (1024 * 1024)
            used_mb = max(0.0, total_mb - free_mb)
            percent = f"{int((used_mb / total_mb) * 100)}%" if total_mb > 0 else "0%"
            disks.append({
                "device": device,
                "total": total_mb,
                "used": used_mb,
                "free": free_mb,
                "mount": mount_point,
                "percent": percent,
            })
    except Exception:
        pass

    if not disks:
        disks = [{"device": "root", "total": 10000, "used": 5000, "free": 5000, "mount": "/", "percent": "50%"}]
    return disks

def _read_top_processes(limit=8):
    if not os.path.isdir("/proc"):
        return []

    try:
        clk_tck = os.sysconf("SC_CLK_TCK") or 100
        page_size = os.sysconf("SC_PAGE_SIZE") or 4096
        num_cpus = os.cpu_count() or 1
        with open("/proc/meminfo", "r") as f:
            mem_total_kb = 0
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total_kb = int(line.split()[1])
                    break
    except Exception:
        return []

    now = time.time()
    candidates = []
    with _metrics_state_lock:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = entry
            try:
                with open(f"/proc/{pid}/stat", "r") as f:
                    stat_parts = f.read().split()
                if len(stat_parts) < 24:
                    continue
                comm = stat_parts[1].strip("()")
                utime = int(stat_parts[13])
                stime = int(stat_parts[14])
                rss_pages = int(stat_parts[23])
            except (FileNotFoundError, ProcessLookupError, ValueError, IndexError, OSError):
                continue

            if comm in ("ps", "comm") or comm.startswith("ps "):
                continue

            cpu_ticks = utime + stime
            cpu_pct = 0.0
            prev = _prev_proc_stats.get(pid)
            if prev:
                prev_ticks, prev_time = prev
                delta_ticks = cpu_ticks - prev_ticks
                delta_time = now - prev_time
                if delta_time > 0 and delta_ticks >= 0:
                    cpu_pct = 100.0 * delta_ticks / (delta_time * clk_tck * num_cpus)
            _prev_proc_stats[pid] = (cpu_ticks, now)

            mem_pct = 0.0
            if mem_total_kb > 0:
                mem_pct = 100.0 * (rss_pages * page_size / 1024) / mem_total_kb

            candidates.append({
                "pid": pid,
                "cpu": f"{max(0.0, cpu_pct):.1f}",
                "mem": f"{max(0.0, mem_pct):.1f}",
                "name": comm,
                "_cpu_sort": cpu_pct,
            })

        # Drop stale PIDs
        live_pids = {c["pid"] for c in candidates}
        for stale_pid in list(_prev_proc_stats.keys()):
            if stale_pid not in live_pids:
                del _prev_proc_stats[stale_pid]

    candidates.sort(key=lambda item: item["_cpu_sort"], reverse=True)
    return [
        {k: v for k, v in proc.items() if k != "_cpu_sort"}
        for proc in candidates[:limit]
    ]

def get_system_metrics():
    """Collect system stats from /proc without spawning shell commands."""
    ram, swap = _read_memory()
    return {
        "cores": _read_cpu_cores(),
        "ram": ram,
        "swap": swap,
        "disks": _read_disks(),
        "uptime": _format_uptime(),
        "top_processes": _read_top_processes(),
    }

def _build_dashboard_snapshot():
    metrics = get_system_metrics()
    metrics["traffic_capture_active"] = check_traffic_capture_status()
    metrics["ip_report_exists"] = os.path.exists(PATHS["ip2loc_report_csv"])
    metrics["dns_report_exists"] = os.path.exists(PATHS["dns_report_csv"])
    metrics["running_actions"] = {
        "packet_analysis": is_action_active("packet_analysis"),
        "dns_analysis": is_action_active("dns_analysis"),
        "update_db": is_update_db_running(),
        "clean": is_clean_running(),
    }

    download_files = list_download_files()
    metrics["log_files_available"] = download_files
    metrics["download_available"] = len(download_files) > 0

    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            metrics["settings"] = json.load(f)
    except Exception:
        metrics["settings"] = {}

    try:
        with open(_PATHS_FILE, "r", encoding="utf-8") as f:
            metrics["paths"] = json.load(f)
    except Exception:
        metrics["paths"] = PATHS

    return metrics

_metrics_cache = {}
_metrics_cache_lock = threading.Lock()
_collector_started = False

def _metrics_collector_loop():
    while True:
        try:
            snapshot = _build_dashboard_snapshot()
            with _metrics_cache_lock:
                _metrics_cache.clear()
                _metrics_cache.update(snapshot)
        except Exception:
            pass
        time.sleep(3)

def ensure_metrics_collector():
    global _collector_started
    if _collector_started:
        return
    _collector_started = True
    threading.Thread(target=_metrics_collector_loop, daemon=True, name="metrics-collector").start()

def get_dashboard_metrics():
    """Return cached dashboard metrics instantly (updated in background)."""
    ensure_metrics_collector()
    with _metrics_cache_lock:
        if _metrics_cache:
            return dict(_metrics_cache)
    return _build_dashboard_snapshot()

_action_queue = []
_action_queue_lock = threading.Lock()
_action_worker_started = False

def _action_worker_loop():
    while True:
        task = None
        with _action_queue_lock:
            if _action_queue:
                task = _action_queue.pop(0)
        if task is None:
            time.sleep(0.05)
            continue
        try:
            task()
        except Exception:
            pass

def ensure_action_worker():
    global _action_worker_started
    if _action_worker_started:
        return
    _action_worker_started = True
    threading.Thread(target=_action_worker_loop, daemon=True, name="action-worker").start()

def schedule_as_report():
    """Queue packet analysis so the HTTP handler returns immediately."""
    ensure_action_worker()
    with _action_queue_lock:
        _action_queue.append(run_as_report_async)

def schedule_dns_report():
    """Queue DNS analysis so the HTTP handler returns immediately."""
    ensure_action_worker()
    with _action_queue_lock:
        _action_queue.append(run_dns_report_async)

def schedule_clean():
    """Queue directory cleanup so the HTTP handler returns immediately."""
    ensure_action_worker()
    with _action_queue_lock:
        _action_queue.append(clean_directories)

def schedule_update_db():
    """Queue database update so the HTTP handler returns immediately."""
    ensure_action_worker()
    with _action_queue_lock:
        _action_queue.append(update_databases)
