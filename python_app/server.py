import sys
import os
import json
import zipfile
import glob
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import socket

# Add current directory to path to load system_scripts
sys.path.append(os.path.dirname(__file__))
import system_scripts

PORT = 3000

class DashboardHTTPRequestHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        # Enable CORS and disable client-side caching for status updates
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        BaseHTTPRequestHandler.end_headers(self)

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        # Serve React Application Build / Frontend or API endpoints
        if self.path.startswith('/api/'):
            self.handle_api_get()
        else:
            self.serve_static_files()

    def do_POST(self):
        if self.path.startswith('/api/'):
            self.handle_api_post()
        else:
            self.send_error(404, "Page Not Found")

    def serve_static_files(self):
        # Map URL to production build bundle
        # If in development or running, we might be serving from Vite, or compiled dist folder
        dist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dist'))
        
        # Safe path traversal preventer
        req_path = self.path.split('?')[0]
        if req_path == '/' or req_path == '':
            req_path = '/index.html'
            
        file_path = os.path.join(dist_path, req_path.lstrip('/'))
        if not file_path.startswith(dist_path) or not os.path.exists(file_path) or os.path.isdir(file_path):
            # Fallback to single page app index.html
            file_path = os.path.join(dist_path, 'index.html')

        mime_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
        }
        _, ext = os.path.splitext(file_path)
        content_type = mime_types.get(ext.lower(), 'application/octet-stream')

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")

    def handle_api_get(self):
        # GET metrics, state or reports
        if self.path == '/api/metrics':
            try:
                metrics = system_scripts.get_system_metrics()
                # Also include packet capture running flag
                metrics["traffic_capture_active"] = system_scripts.check_traffic_capture_status()
                
                # Check for table presence
                metrics["ip_report_exists"] = os.path.exists(system_scripts.PATHS["ip2loc_report_csv"])
                metrics["dns_report_exists"] = os.path.exists(system_scripts.PATHS["dns_report_csv"])
                
                # Check running processes state
                metrics["running_actions"] = {
                    "packet_analysis": system_scripts.is_action_active("packet_analysis"),
                    "dns_analysis": system_scripts.is_action_active("dns_analysis"),
                    "update_db": False
                }
                
                # Check if logs can be downloaded
                # dns_report.csv, dns_report.txt, ip2loc_report.txt, ip2loc_report.csv
                tmp_dir = system_scripts.PATHS["tmp_dir"]
                log_files = []
                for pattern in ["*dns_report*", "*ip2loc_report*"]:
                    for f in glob.glob(os.path.join(tmp_dir, pattern)):
                        log_files.append(os.path.basename(f))
                metrics["log_files_available"] = list(set(log_files))
                
                # Load configuration dynamically
                config_file = os.path.join(os.path.dirname(__file__), 'settings.json')
                with open(config_file, 'r', encoding='utf-8') as f:
                    metrics["settings"] = json.load(f)
                
                # Load paths dynamically
                paths_file = os.path.join(os.path.dirname(__file__), 'paths.json')
                with open(paths_file, 'r', encoding='utf-8') as f:
                    metrics["paths"] = json.load(f)

                self.send_json_response(200, metrics)
            except Exception as e:
                self.send_json_response(500, {"error": str(e)})

        elif self.path == '/api/report/ip':
            csv_path = system_scripts.PATHS["ip2loc_report_csv"]
            if not os.path.exists(csv_path):
                self.send_json_response(404, {"error": "Report file not found"})
                return
            try:
                import csv
                rows = []
                with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        rows.append(row)
                self.send_json_response(200, {"data": rows})
            except Exception as e:
                self.send_json_response(500, {"error": str(e)})

        elif self.path == '/api/report/dns':
            csv_path = system_scripts.PATHS["dns_report_csv"]
            if not os.path.exists(csv_path):
                self.send_json_response(404, {"error": "Report file not found"})
                return
            try:
                import csv
                rows = []
                with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        rows.append(row)
                self.send_json_response(200, {"data": rows})
            except Exception as e:
                self.send_json_response(500, {"error": str(e)})

        elif self.path == '/api/download/logs':
            # Create live ZIP download of logs containing dns_report or ip2loc_report
            tmp_dir = system_scripts.PATHS["tmp_dir"]
            zip_path = os.path.join(tmp_dir, "system_reports.zip")
            
            logs_to_zip = []
            for pattern in ["*dns_report*", "*ip2loc_report*"]:
                for f in glob.glob(os.path.join(tmp_dir, pattern)):
                    logs_to_zip.append(f)
            
            if not logs_to_zip:
                self.send_json_response(404, {"error": "No matching log files found in /tmp to download"})
                return
                
            try:
                # Build zip
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for f in logs_to_zip:
                        zip_file.write(f, os.path.basename(f))
                
                # Read zip bytes and stream
                with open(zip_path, 'rb') as f:
                    zip_data = f.read()
                
                # Cleanup file after reading
                try:
                    os.remove(zip_path)
                except Exception:
                    pass
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="system_reports.zip"')
                self.send_header('Content-Length', str(len(zip_data)))
                self.end_headers()
                self.wfile.write(zip_data)
            except Exception as e:
                self.send_json_response(500, {"error": f"Failed to build zip: {str(e)}"})
        else:
            self.send_json_response(404, {"error": "Route not found"})

    def handle_api_post(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        payload = {}
        if post_data:
            try:
                payload = json.loads(post_data.decode('utf-8'))
            except Exception:
                pass

        if self.path == '/api/actions/update-db':
            # 2.1.2 Download & extract DBs
            success, err = system_scripts.update_databases()
            if success:
                self.send_json_response(200, {"success": True, "message": "Databases successfully updated and extracted."})
            else:
                self.send_json_response(500, {"success": False, "error": err})

        elif self.path == '/api/actions/traffic-capture':
            # Start/Stop Capture control
            action = payload.get("action")
            if action not in ["start", "stop"]:
                self.send_json_response(400, {"success": False, "error": "Action must be start or stop"})
                return
            success, err = system_scripts.control_traffic_capture(action)
            if success:
                self.send_json_response(200, {"success": True, "message": f"Traffic-capture successfully {action}ed."})
            else:
                self.send_json_response(500, {"success": False, "error": err})

        elif self.path == '/api/actions/packet-analysis':
            # Execute analysis script asynchronously in background
            success, err = system_scripts.run_as_report_async()
            if success:
                self.send_json_response(200, {"success": True, "message": "Анализ пакетов запущен в фоновом режиме."})
            else:
                self.send_json_response(500, {"success": False, "error": err})

        elif self.path == '/api/actions/dns-analysis':
            # Execute dns analysis script asynchronously in background
            success, err = system_scripts.run_dns_report_async()
            if success:
                self.send_json_response(200, {"success": True, "message": "Анализ ДНС запущен в фоновом режиме."})
            else:
                self.send_json_response(500, {"success": False, "error": err})

        elif self.path == '/api/actions/ya-sleep':
            # Ya sleep -> Shutdown now
            # Execute shutdown
            _, stderr, code = system_scripts.run_command(["shutdown", "now"])
            if code == 0:
                self.send_json_response(200, {"success": True, "message": "System is shutting down now."})
            else:
                self.send_json_response(500, {"success": False, "error": f"Failed to execute shutdown: {stderr}"})
        else:
            self.send_json_response(404, {"error": "Route not found"})

    def send_json_response(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        response_bytes = json.dumps(data).encode('utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

# Dual stack IPv4 and IPv6 HTTPServer (threaded so long-running actions
# don't block /api/metrics polling for CPU, RAM, etc.)
class DualStackHTTPServer(HTTPServer):
    def server_bind(self):
        # Enable dual stack
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        HTTPServer.server_bind(self)

class ThreadingDualStackHTTPServer(ThreadingMixIn, DualStackHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def run():
    server_address = ('', PORT)
    # Use IPv6 socket to bind both IPv4 and IPv6 interfaces
    ThreadingDualStackHTTPServer.address_family = socket.AF_INET6
    httpd = ThreadingDualStackHTTPServer(server_address, DashboardHTTPRequestHandler)
    print(f"Server starts on port {PORT} (IPv4 and IPv6 compatible)...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
    run()
