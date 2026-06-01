import express from "express";
import path from "path";
import fs from "fs";
import { exec } from "child_process";
import { createServer as createViteServer } from "vite";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Setup initial mock directories and CSV files for fully robust development and live visualization in AI Studio
  const tmpDir = "/tmp";
  if (!fs.existsSync(tmpDir)) {
    try {
      fs.mkdirSync(tmpDir, { recursive: true });
    } catch (e) {}
  }

  // Ensure /mnt/pcaps directory exists on start
  const pcapDir = "/mnt/pcaps";
  try {
    if (!fs.existsSync(pcapDir)) {
      fs.mkdirSync(pcapDir, { recursive: true });
    }
    const samplePcapFile = path.join(pcapDir, "capture-20260601-131232.pcap00");
    if (!fs.existsSync(samplePcapFile)) {
      fs.writeFileSync(samplePcapFile, "Pcap file content placeholder", "utf-8");
    }
  } catch (e: any) {
    console.warn("Could not handle /mnt/pcaps layout folder startup, this is fine:", e.message);
  }

  const mockIpCsvPath = path.join(tmpDir, "ip2loc_report.csv");
  if (!fs.existsSync(mockIpCsvPath)) {
    try {
      fs.writeFileSync(
        mockIpCsvPath,
        `IP Address,Country,Region,City,ISP,ASN\n192.168.1.1,Local,Internal,Gateway,Private,AS0\n8.8.8.8,United States,California,Mountain View,Google LLC,AS15169\n77.88.8.8,Russian Federation,Moscow,Moscow,Yandex,AS13238\n2a03:2880:f10c:83:face:b00c:0:25de,Ireland,Dublin,Dublin,Facebook,AS32934`,
        "utf-8"
      );
    } catch (e) {}
  }

  const mockDnsCsvPath = path.join(tmpDir, "dns_report.csv");
  if (!fs.existsSync(mockDnsCsvPath)) {
    try {
      fs.writeFileSync(
        mockDnsCsvPath,
        `Domain,Query Type,Response,Resolution Time (ms),Status\ngoogle.com,A,142.250.74.46,12.4,SUCCESS\nyandex.ru,A,77.88.55.242,28.1,SUCCESS\ngithub.com,A,140.82.121.4,15.8,SUCCESS\nexample.com,AAAA,2606:2800:220:1:248:1893:25c8:1946,8.2,SUCCESS`,
        "utf-8"
      );
    } catch (e) {}
  }

  // Create mock txt log files for active download qualification
  const mockIpTxtPath = path.join(tmpDir, "ip2loc_report.txt");
  if (!fs.existsSync(mockIpTxtPath)) {
    try {
      fs.writeFileSync(mockIpTxtPath, "Mock IP logs list details", "utf-8");
    } catch (e) {}
  }

  // Initialize service active status and db simulated status
  let trafficCaptureActive = false;
  let dbSimulatedError = false;
  let updateDbActive = false;
  let pcapAnalysisActive = false;
  let cleanActive = false;
  const killedPids = new Set<string>();

  // Read settings from python_app
  const getSettings = () => {
    try {
      const p = path.join(process.cwd(), "python_app", "settings.json");
      return JSON.parse(fs.readFileSync(p, "utf-8"));
    } catch (e) {
      return {
        enable_system_metrics: true,
        enable_service_control: true,
        buttons: {}
      };
    }
  };

  const collectDownloadFiles = (): string[] => {
    const files: string[] = [];
    const matchName = (name: string, pattern: string) => {
      const re = new RegExp("^" + pattern.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
      return re.test(name);
    };

    try {
      for (const name of fs.readdirSync(tmpDir)) {
        const fullPath = path.join(tmpDir, name);
        if (!fs.statSync(fullPath).isFile()) continue;
        if (matchName(name, "ip2loc_report.*") || matchName(name, "dns_report.*")) {
          files.push(name);
        }
      }
    } catch (e) {}

    try {
      const pcapDir = "/mnt/pcaps";
      if (fs.existsSync(pcapDir)) {
        for (const name of fs.readdirSync(pcapDir)) {
          const fullPath = path.join(pcapDir, name);
          if (!fs.statSync(fullPath).isFile()) continue;
          if (name.startsWith("capture")) {
            files.push(path.join("pcaps", name));
          }
        }
      }
    } catch (e) {}

    return files;
  };

  const hasPcapFiles = (): boolean => {
    try {
      const pcapDir = "/mnt/pcaps";
      if (!fs.existsSync(pcapDir)) return false;
      return fs.readdirSync(pcapDir).some((name) => {
        if (!name.startsWith("capture")) return false;
        return fs.statSync(path.join(pcapDir, name)).isFile();
      });
    } catch (e) {
      return false;
    }
  };

  // Serve API routes first
  app.get("/api/metrics", (req, res) => {
    // Generate realistic simulated statistics for the AI Studio live preview
    const randLoad = (base: number) => Math.min(100, Math.max(0, Math.round(base + (Math.random() * 20 - 10))));
    
    // Check files
    const ipReportExists = fs.existsSync(mockIpCsvPath);
    const dnsReportExists = fs.existsSync(mockDnsCsvPath);
    
    // Check if capture* pcap files exist in /mnt/pcaps
    const captureFilesExist = hasPcapFiles();

    const mockMetrics = {
      cores: [
        { core: "cpu0", load: randLoad(45) },
        { core: "cpu1", load: randLoad(32) },
        { core: "cpu2", load: randLoad(58) },
        { core: "cpu3", load: randLoad(20) },
        { core: "cpu4", load: randLoad(70) },
        { core: "cpu5", load: randLoad(51) },
        { core: "cpu6", load: randLoad(15) },
        { core: "cpu7", load: randLoad(88) }
      ],
      ram: {
        total: 16064,
        used: Math.round(8200 + Math.random() * 200),
        free: Math.round(7864 - Math.random() * 200)
      },
      swap: {
        total: 4096,
        used: 1240,
        free: 2856
      },
      disks: [
        { device: "/dev/sda1", total: 491520, used: 215000, free: 276520, mount: "/", percent: "44%" },
        { device: "/dev/sdb1", total: 983040, used: 450000, free: 533040, mount: "/home", percent: "46%" }
      ],
      uptime: "20:15:24 up 12 days, 4:18, 2 users, load average: 0.45, 0.38, 0.31",
      top_processes: [
        { pid: "1254", cpu: (15.4 + Math.random() * 2).toFixed(1), mem: "4.2", name: "python3 backend" },
        { pid: "31105", cpu: (12.1 + Math.random() * 2).toFixed(1), mem: "8.5", name: "node vite-dev" },
        { pid: "845", cpu: "2.8", mem: "1.1", name: "systemd" },
        { pid: "1421", cpu: "1.5", mem: "0.8", name: "traffic-capture" },
        { pid: "3200", cpu: "0.9", mem: "2.5", name: "nginx" },
        { pid: "987", cpu: "0.6", mem: "0.4", name: "sshd" },
        { pid: "1054", cpu: "0.4", mem: "0.3", name: "rsyslogd" },
        { pid: "24412", cpu: "0.2", mem: "0.5", name: "bash" }
      ].filter(p => !killedPids.has(p.pid) && p.name !== "ps"),
      running_actions: {
        pcap_analysis: pcapAnalysisActive,
        packet_analysis: pcapAnalysisActive,
        dns_analysis: pcapAnalysisActive,
        update_db: updateDbActive,
        clean: cleanActive,
      },
      traffic_capture_active: trafficCaptureActive,
      ip_report_exists: ipReportExists,
      dns_report_exists: dnsReportExists,
      capture_files_exist: captureFilesExist,
      log_files_available: collectDownloadFiles(),
      download_available: collectDownloadFiles().length > 0,
      settings: getSettings(),
      paths: {
        ip2location_url: "https://www.ip2location.com/download?token=EScQtt2L2hVy4ya8vnFvaWh8ixG4gnORKLaefL9Gz9x9RlGVTV265eSK6pc1M00V&file=DBASNLITEBINIPV6",
        ip2location_dir: "/home/rpaltaev/IP2LOCATION",
        ip2location_zip: "DB11LITEBINIPV6.BIN.ZIP",
        example_url: "https://www.example.com/download?token=EScQtt2L2hVy4ya8vnFvaWh8ixG4gnORKLaefL9Gz9x9RlGVTV265eSK6pc1M00V&file=DBASNLITEBINIPV6",
        example_zip: "ip-to-asn.mmdb.ZIP",
        tmp_dir: "/tmp",
        pcap_dir: "/mnt/pcaps",
        pcap_analysis_script: "/usr/local/bin/getipdns.sh",
        ip2loc_report_csv: "/tmp/ip2loc_report.csv",
        dns_report_csv: "/tmp/dns_report.csv"
      }
    };

    res.json(mockMetrics);
  });

  app.get("/api/report/ip", (req, res) => {
    if (!fs.existsSync(mockIpCsvPath)) {
      return res.status(404).json({ error: "Report file not found" });
    }
    const content = fs.readFileSync(mockIpCsvPath, "utf-8");
    const rows = content.split("\n").filter(Boolean).map(row => row.split(","));
    res.json({ data: rows });
  });

  app.get("/api/report/dns", (req, res) => {
    if (!fs.existsSync(mockDnsCsvPath)) {
      return res.status(404).json({ error: "Report file not found" });
    }
    const content = fs.readFileSync(mockDnsCsvPath, "utf-8");
    const rows = content.split("\n").filter(Boolean).map(row => row.split(","));
    res.json({ data: rows });
  });

  app.post("/api/actions/update-db", (req, res) => {
    updateDbActive = true;
    res.json({ success: true, message: "Обновление баз запущено в фоновом режиме." });
    setTimeout(() => {
      if (dbSimulatedError) {
        dbSimulatedError = false;
        updateDbActive = false;
        return;
      }
      updateDbActive = false;
    }, 8000);
  });

  app.post("/api/actions/traffic-capture", (req, res) => {
    const { action } = req.body;
    if (action === "start") {
      trafficCaptureActive = true;
    } else {
      trafficCaptureActive = false;
    }
    res.json({ success: true, message: `Traffic-capture successfully ${action}ed.` });
  });

  const runShellScript = (scriptPath: string): Promise<{ success: boolean; message: string; error?: string }> => {
    return new Promise((resolve) => {
      if (!fs.existsSync(scriptPath)) {
        // Fallback simulation representing complete success if file not present in developer environment
        setTimeout(() => {
          resolve({ success: true, message: `Completed simulation successfully (Script ${scriptPath} not present on search path)` });
        }, 1500);
        return;
      }
      // Execute the script with NO TIMEOUT to avoid client interruption during long operations
      exec(scriptPath, (error, stdout, stderr) => {
        if (error) {
          resolve({ success: false, message: `Execution failed: ${error.message}`, error: stderr || stdout || error.message });
        } else {
          resolve({ success: true, message: stdout || "Success" });
        }
      });
    });
  };

  const startCombinedPcapAnalysis = (req: express.Request, res: express.Response) => {
    if (!hasPcapFiles()) {
      return res.status(400).json({ success: false, error: "Нет pcap-файлов в /mnt/pcaps (capture*)" });
    }
    if (pcapAnalysisActive) {
      return res.json({ success: true, message: "Анализ IP и DNS уже выполняется." });
    }

    pcapAnalysisActive = true;
    res.json({ success: true, message: "Анализ IP и DNS запущен (getipdns.sh)." });

    const script = "/usr/local/bin/getipdns.sh";
    const localScript = path.join(process.cwd(), "getipdns.sh");

    if (fs.existsSync(script)) {
      exec(script, () => {
        pcapAnalysisActive = false;
      });
      return;
    }

    if (fs.existsSync(localScript)) {
      exec(`bash ${localScript}`, () => {
        pcapAnalysisActive = false;
      });
      return;
    }

    setTimeout(() => {
      pcapAnalysisActive = false;
    }, 20000);
  };

  for (const route of [
    "/api/actions/pcap-analysis",
    "/api/actions/packet-analysis",
    "/api/actions/dns-analysis",
  ]) {
    app.post(route, startCombinedPcapAnalysis);
  }

  app.post("/api/actions/kill-process", (req, res) => {
    const { pid } = req.body;
    if (pid) {
      killedPids.add(pid.toString());
      try {
        process.kill(Number(pid));
      } catch (err) {}
      res.json({ success: true, message: `Процесс с PID ${pid} успешно завершен.` });
    } else {
      res.status(400).json({ success: false, error: "PID не указан" });
    }
  });

  app.post("/api/actions/ya-sleep", (req, res) => {
    res.json({ success: true, message: "System is shutting down now (simulated shutdown triggered)." });
  });

  app.post("/api/actions/clean", (req, res) => {
    cleanActive = true;
    res.json({ success: true, message: "Очистка /mnt/pcaps и /tmp запущена." });
    setTimeout(() => {
      cleanActive = false;
    }, 3000);
  });

  app.post("/api/actions/ya-reboot", (req, res) => {
    res.json({ success: true, message: "Система перезагружается... (simulated reboot triggered)." });
  });

  app.get("/api/download/logs", (req, res) => {
    // Generate simple standard text as mock zip down stream
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="system_reports.zip"');
    res.send(Buffer.from("PK\x03\x04MockZipFileStructurePlaceholderForPreview"));
  });

  // Proxy settings endpoint for developer console updates
  app.post("/api/settings", (req, res) => {
    const settingsPath = path.join(process.cwd(), "python_app", "settings.json");
    try {
      fs.writeFileSync(settingsPath, JSON.stringify(req.body, null, 2), "utf-8");
      res.json({ success: true, settings: req.body });
    } catch (e: any) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Development Node Proxy running on http://localhost:${PORT}`);
  });
}

startServer();
