/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef } from "react";
import { 
  Activity, 
  Cpu, 
  Database, 
  Disc, 
  Download, 
  FileSpreadsheet, 
  FileText, 
  HardDrive, 
  HelpCircle, 
  Layers, 
  Moon, 
  Network, 
  RefreshCw, 
  RotateCw,
  Trash2,
  Search, 
  Settings, 
  Shield, 
  Terminal, 
  Clock,
  X,
  CheckCircle2,
  AlertOctagon,
  ArrowRight,
  ExternalLink
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { SystemMetricsResponse, SystemSettings } from "./types";

const DNS_RECORD_TYPE_ORDER = ["A", "AAAA", "MX", "PTR", "SRV"] as const;

function findColumnIndex(headers: string[], candidates: string[]): number {
  const normalized = headers.map((h) => h.trim().toLowerCase());
  for (const candidate of candidates) {
    const idx = normalized.indexOf(candidate.toLowerCase());
    if (idx >= 0) return idx;
  }
  return -1;
}

function normalizeDnsRecordType(value: string): string {
  return value.trim().toUpperCase();
}

function sortDnsRows(rows: string[][], headers: string[]): string[][] {
  const typeCol = findColumnIndex(headers, ["query type", "type", "qtype", "record type", "тип"]);
  const domainCol = findColumnIndex(headers, ["domain", "name", "hostname", "домен"]);

  if (typeCol < 0) {
    return rows;
  }

  return [...rows].sort((a, b) => {
    const typeA = normalizeDnsRecordType(a[typeCol] ?? "");
    const typeB = normalizeDnsRecordType(b[typeCol] ?? "");

    const priorityA = DNS_RECORD_TYPE_ORDER.indexOf(typeA as (typeof DNS_RECORD_TYPE_ORDER)[number]);
    const priorityB = DNS_RECORD_TYPE_ORDER.indexOf(typeB as (typeof DNS_RECORD_TYPE_ORDER)[number]);
    const rankA = priorityA >= 0 ? priorityA : DNS_RECORD_TYPE_ORDER.length;
    const rankB = priorityB >= 0 ? priorityB : DNS_RECORD_TYPE_ORDER.length;

    if (rankA !== rankB) return rankA - rankB;
    if (rankA === DNS_RECORD_TYPE_ORDER.length && typeA !== typeB) {
      return typeA.localeCompare(typeB);
    }

    if (domainCol >= 0) {
      const domainA = (a[domainCol] ?? "").toLowerCase();
      const domainB = (b[domainCol] ?? "").toLowerCase();
      if (domainA !== domainB) return domainA.localeCompare(domainB);
    }

    return a.join("\0").localeCompare(b.join("\0"));
  });
}

/// --- CSV TABLE VIEW COMPONENT ---
function ReportTable({ type }: { type: "ip" | "dns" }) {
  const [data, setData] = useState<string[][]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const title = type === "ip" ? "Отчет по IP адресам" : "Отчет по DNS запросам";
  const label = type === "ip" ? "/tmp/ip2loc_report.csv" : "/tmp/dns_report.csv";

  useEffect(() => {
    fetch(`/api/report/${type}`)
      .then((res) => {
        if (!res.ok) {
          throw new Error(`Ошибка загрузки данных или файл ${label} отсутствует`);
        }
        return res.json();
      })
      .then((resData) => {
        if (resData.data && Array.isArray(resData.data)) {
          setData(resData.data);
        } else {
          setError("Неверный формат данных в CSV файле");
        }
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [type, label]);

  // Headers are the first row, data rows are the rest
  const headers = data.length > 0 ? data[0] : [];
  const rows = data.length > 1 ? data.slice(1) : [];

  // Sort rows: DNS by record type groups; IP by fewest N/A values first
  const countNA = (row: string[]) => {
    return row.filter(val => {
      if (!val) return true;
      const s = val.toString().trim().toUpperCase();
      return s === "N/A" || s === "NA" || s === "-" || s === "" || s === "NULL" || s === "NONE";
    }).length;
  };
  const sortedRows =
    type === "dns"
      ? sortDnsRows(rows, headers)
      : [...rows].sort((a, b) => countNA(a) - countNA(b));

  // Filter rows based on search
  const filteredRows = sortedRows.filter((row) =>
    row.some((val) => val && val.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="min-h-screen bg-sky-50 text-slate-800 p-6 font-sans">
      <div className="w-full space-y-6">
        {/* Header Block */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-white border border-sky-200/85 rounded-xl p-5 gap-4 shadow-xl shadow-sky-100/30">
          <div>
            <div className="flex items-center gap-3">
              <FileSpreadsheet className="w-8 h-8 text-blue-500 animate-pulse" />
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">{title}</h1>
            </div>
            <p className="text-slate-500 mt-1 font-mono text-sm">
              Источник: {label}
            </p>
          </div>
          
          <div className="flex items-center gap-3 w-full md:w-auto">
            <div className="relative w-full md:w-80">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                <Search className="h-5 w-5 text-slate-400" />
              </span>
              <input
                type="text"
                className="w-full bg-white border border-sky-200 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-800 placeholder-slate-400 focus:outline-none focus:border-blue-400 focus:ring-1 focus:ring-blue-400"
                placeholder="Поиск по таблице..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <button
              onClick={() => window.close()}
              className="px-4 py-2 bg-white hover:bg-sky-50 text-slate-700 font-medium rounded-lg text-sm transition-all border border-sky-200 shadow-sm"
            >
              Закрыть вкладку
            </button>
          </div>
        </div>

        {/* Content Table */}
        <div className="bg-white border border-sky-200/80 rounded-xl overflow-hidden shadow-2xl">
          {loading ? (
            <div className="py-20 flex flex-col justify-center items-center gap-4">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
              <span className="text-slate-500 font-medium">Чтение CSV отчета...</span>
            </div>
          ) : error ? (
            <div className="p-12 flex flex-col justify-center items-center text-center gap-4">
              <div className="p-4 bg-red-50 border border-red-200 rounded-full text-red-500">
                <AlertOctagon className="w-10 h-10 animate-bounce" />
              </div>
              <h2 className="text-lg font-semibold text-slate-800">Файл отчета недоступен</h2>
              <p className="text-slate-500 max-w-md">{error}</p>
              <p className="text-xs text-slate-400">
                Убедитесь, что анализ был запущен и успешно создал отчет по пути: {label}
              </p>
            </div>
          ) : data.length === 0 ? (
            <div className="py-20 text-center text-slate-400 font-medium font-sans">Файл отчета пуст.</div>
          ) : (
            <div className="overflow-x-auto text-slate-700">
              <table className="w-full text-left border-collapse font-sans">
                <thead>
                  <tr className="bg-sky-100/60 border-b border-sky-200 font-sans">
                    {headers.map((h, i) => (
                      <th
                        key={i}
                        className="p-4 text-xs font-semibold uppercase tracking-wider text-sky-950 font-mono"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-sky-100">
                  {filteredRows.length === 0 ? (
                    <tr>
                      <td
                        colSpan={headers.length}
                        className="p-8 text-center text-slate-400"
                      >
                        Строки, соответствующие условиям поиска, не найдены.
                      </td>
                    </tr>
                  ) : (
                    filteredRows.map((row, rIdx) => (
                      <tr
                        key={rIdx}
                        className="hover:bg-sky-50 transition-all font-mono text-sm odd:bg-white even:bg-sky-50/20"
                      >
                        {row.map((val, cIdx) => (
                          <td key={cIdx} className="p-4 text-slate-700 whitespace-nowrap">
                            {val && (val.toString().toUpperCase() === "N/A" || val.toString().toUpperCase() === "NA") ? (
                              <span className="text-slate-400 italic">N/A</span>
                            ) : (
                              val
                            )}
                          </td>
                        ))}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
              <div className="bg-sky-50 border-t border-sky-150 p-4 flex justify-between items-center text-xs text-slate-500 font-mono font-sans">
                <span>Всего записей: {rows.length}</span>
                {searchQuery && (
                  <span className="text-blue-600 font-semibold">Найдено: {filteredRows.length}</span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// --- MAIN DASHBOARD APP ---
export default function App() {
  // Check router condition
  const path = window.location.pathname;
  if (path === "/report-ip" || path === "/reports/ip") {
    return <ReportTable type="ip" />;
  }
  if (path === "/report-dns" || path === "/reports/dns") {
    return <ReportTable type="dns" />;
  }

  // Live state declarations
  const [metrics, setMetrics] = useState<SystemMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningActions, setRunningActions] = useState<Record<string, boolean>>({});
  const [localKilledPids, setLocalKilledPids] = useState<Set<string>>(new Set());
  const [errorLog, setErrorLog] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [localSettings, setLocalSettings] = useState<SystemSettings | null>(null);
  const prevUpdateDbRunning = useRef(false);

  const displaySettings = localSettings || metrics?.settings;

  const MAIN_SERVICE_ACTION_KEYS = ["update_db", "traffic_capture", "packet_analysis", "dns_analysis"] as const;
  const BACKGROUND_ACTION_KEYS = new Set(["update_db", "packet_analysis", "dns_analysis", "clean"]);

  const isActionRunning = (key: string) => {
    return !!(runningActions[key] || metrics?.running_actions?.[key]);
  };

  const isCaptureServiceActive = metrics?.traffic_capture_active === true;
  const isAnyMainServiceActionRunning = MAIN_SERVICE_ACTION_KEYS.some((key) => isActionRunning(key));
  // Lock panel while a main action runs, clean runs, or packet capture service is active
  const isPanelLocked = isAnyMainServiceActionRunning || isActionRunning("clean") || isCaptureServiceActive;
  // Allow stopping capture while service is active — only this button stays clickable
  const isTrafficCaptureClickable =
    displaySettings?.buttons?.traffic_capture?.enabled !== false &&
    !(isPanelLocked && !isCaptureServiceActive);
  const isAnyActionRunning = isPanelLocked;

  const formatUptime = (raw: string | undefined): string => {
    if (!raw) return "Опрос...";
    const cleaned = raw.trim();
    const parts = cleaned.split(/\s+/);
    const time = parts[0] || "";
    
    const daysMatch = cleaned.match(/(\d+)\s+days?/i) || cleaned.match(/(\d+)\s+дн[еяей]+/i);
    if (daysMatch) {
      const numDays = parseInt(daysMatch[1], 10);
      const getRussianDays = (num: number) => {
        const lastDigit = num % 10;
        const lastTwoDigits = num % 100;
        if (lastTwoDigits >= 11 && lastTwoDigits <= 19) {
          return `${num} дней`;
        }
        if (lastDigit === 1) {
          return `${num} день`;
        }
        if (lastDigit >= 2 && lastDigit <= 4) {
          return `${num} дня`;
        }
        return `${num} дней`;
      };
      return `${time} (${getRussianDays(numDays)})`;
    }
    
    return `${time} (0 дней)`;
  };

  // Fetch metrics helper
  const fetchMetrics = (): Promise<void> => {
    return fetch("/api/metrics")
      .then((res) => res.json())
      .then((data: SystemMetricsResponse) => {
        setMetrics(data);
        if (!localSettings && data.settings) {
          setLocalSettings(data.settings);
        }
        setLoading(false);
      })
      .catch((err) => {
        console.error("Ошибка опроса метрик:", err);
        setErrorLog("Не удалось получить метрики сервера");
      });
  };

  // Poll server every 5 seconds
  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, [localSettings]);

  // Clear local running state when background jobs finish on the server
  useEffect(() => {
    if (!metrics?.running_actions) return;
    setRunningActions((prev) => {
      let changed = false;
      const next = { ...prev };
      for (const key of BACKGROUND_ACTION_KEYS) {
        if (!metrics.running_actions?.[key] && next[key]) {
          next[key] = false;
          changed = true;
        }
      }
      return changed ? next : prev;
    });
  }, [metrics?.running_actions]);

  // Notify when background database update completes
  useEffect(() => {
    const running = metrics?.running_actions?.update_db === true;
    if (prevUpdateDbRunning.current && !running) {
      setSuccessMessage("Базы данных успешно обновлены.");
    }
    prevUpdateDbRunning.current = running;
  }, [metrics?.running_actions?.update_db]);

  // Trigger Backend Python Actions (now uses non-blocking runningActions)
  const runAction = async (actionKey: string, endpoint: string, body?: any) => {
    if (
      MAIN_SERVICE_ACTION_KEYS.includes(actionKey as typeof MAIN_SERVICE_ACTION_KEYS[number]) &&
      isAnyMainServiceActionRunning
    ) {
      return;
    }
    if (actionKey !== "traffic_capture" && isCaptureServiceActive) {
      return;
    }
    if (actionKey === "clean" && (isAnyMainServiceActionRunning || isCaptureServiceActive || isActionRunning("clean"))) {
      return;
    }
    if (runningActions[actionKey]) return;
    setRunningActions(prev => ({ ...prev, [actionKey]: true }));
    setErrorLog(null);
    setSuccessMessage(null);

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
      });

      const resData = await res.json();
      if (!res.ok || resData.success === false) {
        throw new Error(resData.error || "Произошла неизвестная системная ошибка");
      }

      setSuccessMessage(resData.message || "Действие выполнено успешно!");
      await fetchMetrics();
    } catch (err: any) {
      console.error(err);
      setErrorLog(`${err.message}`);
    } finally {
      if (!BACKGROUND_ACTION_KEYS.has(actionKey)) {
        setRunningActions(prev => ({ ...prev, [actionKey]: false }));
      }
    }
  };

  const runEmergencyAction = async (endpoint: string, confirmMessage: string) => {
    if (!window.confirm(confirmMessage)) return;
    setErrorLog(null);
    setSuccessMessage(null);
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const resData = await res.json();
      if (!res.ok || resData.success === false) {
        throw new Error(resData.error || "Произошла неизвестная системная ошибка");
      }
      setSuccessMessage(resData.message || "Действие выполнено успешно!");
    } catch (err: any) {
      console.error(err);
      setErrorLog(`${err.message}`);
    }
  };

  // Dedicated Update DB triggering action
  const handleUpdateDB = () => {
    runAction("update_db", "/api/actions/update-db");
  };

  // Packet Capture toggler
  const handleTrafficCapture = () => {
    const isRunning = metrics?.traffic_capture_active;
    runAction(
      "traffic_capture",
      "/api/actions/traffic-capture",
      { action: isRunning ? "stop" : "start" }
    );
  };

  // Run reports
  const handlePacketAnalysis = () => {
    runAction("packet_analysis", "/api/actions/packet-analysis");
  };

  const handleDnsAnalysis = () => {
    runAction("dns_analysis", "/api/actions/dns-analysis");
  };

  const handleClean = () => {
    runAction("clean", "/api/actions/clean");
  };

  const handleYaReboot = () => {
    runEmergencyAction(
      "/api/actions/ya-reboot",
      "Вы уверены, что хотите перезагрузить сервер (shutdown -r now)?"
    );
  };

  // Kill Process Row Handler
  const handleKillProcess = async (pid: string, name: string) => {
    if (localKilledPids.has(pid)) return;
    setLocalKilledPids(prev => {
      const updated = new Set(prev);
      updated.add(pid);
      return updated;
    });

    try {
      const res = await fetch("/api/actions/kill-process", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pid }),
      });
      const resData = await res.json();
      if (!res.ok || resData.success === false) {
        throw new Error(resData.error || "Ошибка при остановке процесса");
      }
      setSuccessMessage(`Процесс ${name} (PID ${pid}) успешно выключен.`);
      fetchMetrics();
    } catch (err: any) {
      // Revert optimism on error
      setLocalKilledPids(prev => {
        const updated = new Set(prev);
        updated.delete(pid);
        return updated;
      });
      setErrorLog(err.message);
    }
  };

  const handleYaSleep = () => {
    runEmergencyAction(
      "/api/actions/ya-sleep",
      "Вы уверены, что хотите выключить сервер через 'shutdown now'?"
    );
  };

  // Log Zip Downloader
  const handleDownloadLogs = () => {
    window.location.href = "/api/download/logs";
  };

  // Update Dynamic Local Settings in client / settings.json
  const toggleSetting = async (key: keyof SystemSettings | string, subKey?: string) => {
    if (!localSettings) return;

    let updated: SystemSettings;
    if (subKey && typeof localSettings.buttons === 'object') {
      const buttons = { ...localSettings.buttons };
      const btnKey = subKey as keyof typeof buttons;
      buttons[btnKey] = {
        ...buttons[btnKey],
        [key]: !buttons[btnKey][key as keyof typeof buttons[typeof btnKey]]
      };
      updated = { ...localSettings, buttons };
    } else {
      updated = { ...localSettings, [key]: !localSettings[key as keyof SystemSettings] };
    }

    setLocalSettings(updated);

    // Save configuration updates to settings.json via API
    try {
      await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updated),
      });
    } catch (e) {
      console.error("Failed to save settings changes to server file:", e);
    }
  };

  // Download available: independent of analysis/capture tasks — only file presence matters
  const downloadFileCount = metrics?.log_files_available?.length ?? 0;
  const logsExist = Boolean(metrics?.download_available) || downloadFileCount > 0;
  const downloadEnabled = logsExist && displaySettings?.buttons?.download_logs?.enabled !== false;

  return (
    <div className="min-h-screen bg-sky-50 text-slate-805 pb-20 font-sans relative antialiased leading-relaxed select-text">
      
      {/* Top ambient glowing background */}
      <div className="absolute top-0 left-0 right-0 h-96 bg-gradient-to-b from-sky-200/40 to-transparent pointer-events-none z-0" />

      <div className="w-full px-4 sm:px-6 lg:px-8 pt-6 relative z-10 space-y-6">
        
        {/* TOP LINE: TITLE & UPTIME HEADER */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center bg-white border border-sky-200/80 rounded-xl p-5 shadow-xl shadow-sky-100/30 gap-4">
          <div className="flex items-center gap-4">
            <div className="w-3.5 h-3.5 rounded-full bg-blue-500 animate-pulse shrink-0" />
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight uppercase">ЗОМБ-АКУЛА v2.4.0</h1>
                <span className="px-2 py-0.5 bg-sky-100 border border-sky-200 text-blue-700 rounded-md font-mono text-[10px] tracking-widest uppercase font-semibold">
                  ● LIVE
                </span>
              </div>
              <p className="text-slate-500 text-xs sm:text-sm mt-0.5">
                Панель управления сетевыми службами машинного хостинга
              </p>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 w-full md:w-auto">
            {/* Blinking traffic active banner indicator */}
            <AnimatePresence>
              {metrics?.traffic_capture_active && (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="flex items-center gap-2 px-3 py-1.5 bg-blue-50 border border-blue-200 text-blue-700 rounded-lg text-xs font-semibold shrink-0 shadow-sm"
                >
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-ping" />
                  <span className="font-mono tracking-tight uppercase">Capture Active</span>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="flex items-center gap-3 px-4 py-2 bg-sky-50 border border-sky-100 rounded-xl">
              <Clock className="w-5 h-5 text-blue-500 shrink-0" />
              <div className="truncate">
                <span className="block text-[10px] uppercase text-slate-400 font-mono tracking-widest">System Uptime</span>
                <span className="text-xs font-mono text-blue-700 block truncate max-w-[280px]" title={metrics?.uptime}>
                  {formatUptime(metrics?.uptime)}
                </span>
              </div>
            </div>
          </div>
        </header>

        {/* NOTIFICATIONS CONTAINER AREA */}
        <AnimatePresence>
          {errorLog && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="bg-red-50 border border-red-200 rounded-xl p-4 flex gap-3 text-red-800 shadow-lg overflow-hidden"
            >
              <AlertOctagon className="w-5 h-5 text-red-500 shrink-0" />
              <div className="text-sm">
                <span className="font-semibold block">Системное оповещение об ошибке:</span>
                <p className="font-mono mt-1 text-xs text-red-650">{errorLog}</p>
              </div>
            </motion.div>
          )}

          {successMessage && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 flex gap-3 text-emerald-800 shadow-lg overflow-hidden"
              onAnimationComplete={() => {
                // Dim after 6 seconds
                setTimeout(() => setSuccessMessage(null), 6000);
              }}
            >
              <CheckCircle2 className="w-5 h-5 text-emerald-505 shrink-0" />
              <div className="text-sm">
                <span className="font-semibold block">Операция выполнена успешно:</span>
                <p className="mt-1 text-xs text-emerald-700">{successMessage}</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* 1. TOP WINDOW: SYSTEM STATUS METRICS (Updates every 5 seconds) */}
        {displaySettings?.enable_system_metrics !== false && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* 1.1 CPU & DISK METRICS GRID */}
            <div className="lg:col-span-8 space-y-6">
              
              {/* Core load meters */}
              <div className="bg-white border border-sky-200/80 rounded-xl p-5 shadow-xl shadow-sky-100/10">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-blue-500" />
                    <h2 className="text-xs font-bold text-slate-500 uppercase tracking-wider font-sans">CPU Core Usage</h2>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">
                    {metrics?.cores?.length || 8} Cores @ 3.4GHz
                  </span>
                </div>

                {loading ? (
                  <div className="py-12 flex justify-center items-center">
                    <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                  </div>
                ) : (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {metrics?.cores?.map((c, i) => {
                      let color = "bg-blue-500";
                      let bg = "bg-sky-50/30 border-sky-100/60";
                      let text = "text-blue-600";
                      
                      if (c.load > 75) {
                        color = "bg-red-500";
                        bg = "bg-red-50/50 border-red-100";
                        text = "text-red-600 font-semibold";
                      } else if (c.load > 45) {
                        color = "bg-amber-500";
                        bg = "bg-amber-50/50 border-amber-100";
                        text = "text-amber-600 font-semibold";
                      }

                      return (
                        <div 
                          key={i} 
                          className={`p-3 border ${bg} rounded-xl flex flex-col justify-between h-20 hover:scale-[1.02] transition-all`}
                        >
                          <div className="flex justify-between items-center text-xs font-mono">
                            <span className="text-slate-500 font-bold uppercase">{c.core}</span>
                            <span className={`${text} font-bold`}>{c.load}%</span>
                          </div>
                          
                          {/* Progress slider style */}
                          <div className="w-full h-1.5 bg-sky-100 rounded-full overflow-hidden mt-2">
                            <motion.div 
                              className={`h-full ${color}`} 
                              initial={{ width: 0 }}
                              animate={{ width: `${c.load}%` }}
                              transition={{ duration: 0.5 }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Memory allocations: RAM & SWAP */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                
                {/* RAM Allocation */}
                <div className="bg-white border border-sky-200/80 rounded-xl p-5 shadow-xl shadow-sky-100/10">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-blue-500" />
                      <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider font-sans">RAM Usage</h3>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">
                      {metrics ? `${((metrics.ram.used / metrics.ram.total) * 100).toFixed(0)}%` : "---"}
                    </span>
                  </div>

                  {loading || !metrics ? (
                    <div className="py-6 flex justify-center">
                      <RefreshCw className="w-5 h-5 animate-spin text-blue-400" />
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Bar graphical display */}
                      <div className="w-full h-2 bg-sky-100 rounded-full overflow-hidden">
                        <motion.div 
                          className="h-full bg-blue-500 rounded-full" 
                          initial={{ width: 0 }}
                          animate={{ width: `${(metrics.ram.used / metrics.ram.total) * 100}%` }}
                          transition={{ duration: 0.5 }}
                        />
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                        <div className="p-2 bg-sky-50/60 border border-sky-100 rounded-lg">
                          <span className="block text-slate-400 text-[10px]">USED</span>
                          <span className="font-bold text-slate-700">
                            {(metrics.ram.used / 1024).toFixed(2)} GB
                          </span>
                        </div>
                        <div className="p-2 bg-sky-50/60 border border-sky-105 rounded-lg">
                          <span className="block text-slate-400 text-[10px]">FREE</span>
                          <span className="font-bold text-slate-600">
                            {(metrics.ram.free / 1024).toFixed(2)} GB
                          </span>
                        </div>
                      </div>
                      
                      <div className="text-[11px] font-mono text-slate-450 text-center font-semibold">
                        Total allocated: {(metrics.ram.total / 1024).toFixed(2)} GB
                      </div>
                    </div>
                  )}
                </div>

                {/* SWAP Allocation */}
                <div className="bg-white border border-sky-200/80 rounded-xl p-5 shadow-xl shadow-sky-100/10">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Layers className="w-4 h-4 text-blue-600" />
                      <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider font-sans">SWAP Space</h3>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">
                      {metrics ? `${metrics.swap.total > 0 ? ((metrics.swap.used / metrics.swap.total) * 100).toFixed(0) : 0}%` : "---"}
                    </span>
                  </div>

                  {loading || !metrics ? (
                    <div className="py-6 flex justify-center">
                      <RefreshCw className="w-5 h-5 animate-spin text-blue-600" />
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="w-full h-2 bg-sky-100 rounded-full overflow-hidden">
                        <motion.div 
                          className="h-full bg-blue-650 rounded-full" 
                          initial={{ width: 0 }}
                          animate={{ width: `${metrics.swap.total > 0 ? (metrics.swap.used / metrics.swap.total) * 100 : 0}%` }}
                          transition={{ duration: 0.5 }}
                        />
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                        <div className="p-2 bg-sky-50/60 border border-sky-100 rounded-lg">
                          <span className="block text-slate-400 text-[10px]">USED</span>
                          <span className="font-bold text-slate-700">
                            {(metrics.swap.used / 1024).toFixed(2)} GB
                          </span>
                        </div>
                        <div className="p-2 bg-sky-50/60 border border-sky-100 rounded-lg">
                          <span className="block text-slate-400 text-[10px]">FREE</span>
                          <span className="font-bold text-slate-600">
                            {(metrics.swap.free / 1024).toFixed(2)} GB
                          </span>
                        </div>
                      </div>
                      
                      <div className="text-[11px] font-mono text-slate-455 text-center font-semibold">
                        Total allocated: {(metrics.swap.total / 1024).toFixed(2)} GB
                      </div>
                    </div>
                  )}
                </div>

              </div>

              {/* Disk usage details */}
              <div className="bg-white border border-sky-200/80 rounded-xl p-5 shadow-xl shadow-sky-100/10">
                <div className="flex items-center gap-2 mb-4">
                  <HardDrive className="w-4 h-4 text-indigo-505 animate-pulse" />
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider font-sans">Disk Usage details</h3>
                </div>

                {loading || !metrics ? (
                  <div className="py-6 flex justify-center">
                    <RefreshCw className="w-5 h-5 animate-spin text-indigo-500" />
                  </div>
                ) : (
                  <div className="space-y-4 divide-y divide-sky-100">
                    {metrics.disks.map((disk, i) => (
                      <div key={i} className={`${i > 0 ? 'pt-4' : ''}`}>
                        <div className="flex justify-between items-center text-xs font-mono mb-2">
                          <div className="flex items-center gap-2 text-slate-500">
                            <Disc className="w-4 h-4 text-slate-450 shrink-0" />
                            <span className="font-bold text-slate-800">{disk.device}</span>
                            <span className="text-slate-405 font-sans">mount</span>
                            <span className="px-1.5 py-0.5 bg-sky-50 border border-sky-200 text-blue-700 rounded text-[10px] font-bold">{disk.mount}</span>
                          </div>
                          <span className="text-slate-505 font-bold">{disk.percent}</span>
                        </div>
                        
                        <div className="w-full h-2 bg-sky-100 rounded-full overflow-hidden mb-2">
                          <motion.div 
                            className="h-full bg-blue-500 rounded-full" 
                            initial={{ width: 0 }}
                            animate={{ width: disk.percent }}
                            transition={{ duration: 0.5 }}
                          />
                        </div>

                        <div className="flex justify-between text-[11px] text-slate-450 font-mono">
                          <span>USED: {(disk.used / 1024).toFixed(1)} GB</span>
                          <span>TOTAL: {(disk.total / 1024).toFixed(1)} GB</span>
                          <span>FREE: {(disk.free / 1024).toFixed(1)} GB</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>

            {/* 1.2 SYSTEM UPTIME & TOP 8 COMPUTER PROCESSES */}
            <div className="lg:col-span-4 bg-white border border-sky-200/80 rounded-xl overflow-hidden flex flex-col justify-between shadow-xl shadow-sky-100/10">
              <div>
                <div className="px-4 py-3 bg-sky-50 border-b border-sky-200/80 flex justify-between items-center">
                  <h3 className="text-xs font-bold text-slate-705 uppercase flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-blue-500" />
                    <span>Top Processes (Click row to turn off)</span>
                  </h3>
                </div>

                {loading || !metrics ? (
                  <div className="py-20 flex justify-center">
                    <RefreshCw className="w-5 h-5 animate-spin text-blue-500" />
                  </div>
                ) : (
                  /* HORIZONTALLY SCROLLABLE WRAPPER FOR PROCESSES */
                  <div className="overflow-x-auto w-full select-text scrollbar-thin whitespace-nowrap">
                    <table className="min-w-[340px] w-full text-left font-mono text-[11px]">
                      <thead className="text-slate-500 bg-sky-50/50">
                        <tr className="border-b border-sky-150">
                          <th className="px-4 py-2 font-bold uppercase">PID</th>
                          <th className="px-2 py-2 font-bold uppercase">PROCESS</th>
                          <th className="px-2 py-2 font-bold uppercase text-right">%CPU</th>
                          <th className="px-2 py-2 font-bold uppercase text-right">%MEM</th>
                          <th className="px-4 py-2 font-bold uppercase text-center">ACTION</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-sky-100">
                        {metrics.top_processes.filter((proc) => proc.name !== "ps" && proc.name !== "[ps]" && proc.name !== "ps ").map((proc, idx) => {
                          const isKilled = localKilledPids.has(proc.pid);
                          return (
                            <tr 
                              key={idx} 
                              onClick={() => {
                                if (!isKilled) handleKillProcess(proc.pid, proc.name);
                              }}
                              className={`transition-all duration-300 group ${
                                isKilled 
                                  ? "opacity-30 border-l-4 border-l-red-550 line-through bg-slate-50 pointer-events-none italic" 
                                  : "hover:bg-sky-50/70 cursor-pointer"
                              }`}
                            >
                              <td className="px-4 py-2.5 text-slate-400 group-hover:text-blue-600 font-semibold">{proc.pid}</td>
                              <td className="px-2 py-2.5 font-bold text-slate-700 max-w-[130px] truncate" title={proc.name}>
                                {proc.name} {isKilled && <span className="text-red-500 text-[9px] uppercase ml-1 font-bold">[ВЫКЛЮЧЕН]</span>}
                              </td>
                              <td className="px-2 py-2.5 text-right font-bold text-blue-700">{proc.cpu}</td>
                              <td className="px-2 py-2.5 text-right text-slate-500">{proc.mem}</td>
                              <td className="px-4 py-2.5 text-center">
                                <button
                                  type="button"
                                  disabled={isKilled}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleKillProcess(proc.pid, proc.name);
                                  }}
                                  className={`px-2 py-0.5 text-[10px] rounded font-bold transition-all ${
                                    isKilled 
                                      ? "bg-slate-100 text-slate-400 cursor-not-allowed" 
                                      : "bg-red-50 hover:bg-red-500 text-red-650 hover:text-white border border-red-200"
                                  }`}
                                >
                                  {isKilled ? "Выключен" : "Выключить"}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="p-3 bg-sky-50/50 border-t border-sky-100 text-[10px] text-slate-400 font-mono text-center flex items-center justify-center gap-1.5">
                <Activity className="w-3.5 h-3.5 animate-pulse text-blue-500" />
                <span>AUTO-REFRESH: 5S</span>
              </div>
            </div>

          </div>
        )}        {/* 2. MAIN WINDOW: CONTROL SERVICE & SYSTEM ACTIONS GRID */}
        <section className="bg-white border border-sky-200/80 rounded-xl p-6 shadow-xl shadow-sky-100/10 relative overflow-hidden">
          
          <div className="border-b border-sky-200 pb-4 mb-6 flex justify-between items-center">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-500" />
              <h2 className="text-xs font-bold text-slate-700 uppercase tracking-wider font-sans">Control Services & System Actions</h2>
            </div>
            
            {isAnyActionRunning && (
              <span className="flex items-center gap-2 px-2.5 py-1 bg-sky-50 border border-blue-500/20 text-blue-700 rounded-md text-xs font-mono font-semibold animate-pulse">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-500" />
                Выполняются фоновые задачи...
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

            {/* --- 2.1 UPDATE BASE BUTTON --- */}
            {displaySettings?.buttons?.update_db?.visible !== false && (
              <button
                disabled={isPanelLocked || displaySettings?.buttons?.update_db?.enabled === false}
                onClick={handleUpdateDB}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    isActionRunning("update_db")
                      ? "bg-blue-600 border-blue-500 text-white shadow-lg cursor-wait"
                      : isPanelLocked || displaySettings?.buttons?.update_db?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:border-blue-450 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <Database className={`w-4 h-4 ${isActionRunning("update_db") ? "text-white" : "text-blue-550"}`} />
                  </span>
                  {isActionRunning("update_db") && (
                    <RefreshCw className="w-4 h-4 animate-spin text-white mt-1" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-800">{displaySettings?.buttons?.update_db?.label || "Обновить базы"}</span>
                  <span className="text-[11px] text-slate-405 group-hover:text-slate-550 font-normal mt-0.5 block font-sans">
                    Загрузка IP2Loc и ASN БД
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.2 PACKET CAPTURE BUTTON --- */}
            {displaySettings?.buttons?.traffic_capture?.visible !== false && (
              <button
                disabled={!isTrafficCaptureClickable}
                onClick={handleTrafficCapture}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    isActionRunning("traffic_capture")
                      ? "bg-blue-600 border-blue-500 text-white shadow-lg cursor-wait"
                      : !isTrafficCaptureClickable
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : metrics?.traffic_capture_active
                      ? "bg-emerald-50 border-emerald-350 text-emerald-800 font-bold cursor-pointer"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-805 hover:border-emerald-500/40 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <Network className={`w-4 h-4 ${isActionRunning("traffic_capture") ? "text-white" : metrics?.traffic_capture_active ? "text-emerald-600 animate-pulse" : "text-emerald-500"}`} />
                  </span>
                  {isActionRunning("traffic_capture") ? (
                    <RefreshCw className="w-4 h-4 animate-spin text-white mt-1" />
                  ) : metrics?.traffic_capture_active ? (
                     <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping mt-1.5" />
                  ) : null}
                </div>
                <div>
                  <span className="block font-bold text-slate-800">{displaySettings?.buttons?.traffic_capture?.label || "Захват пакетов"}</span>
                  <span className="text-[11px] text-slate-405 font-normal mt-0.5 block font-sans">
                    {metrics?.traffic_capture_active ? "Остановить службу сбора" : "Запуск traffic-capture"}
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.3 PACKET ANALYSIS BUTTON --- */}
            {displaySettings?.buttons?.packet_analysis?.visible !== false && (
              <button
                disabled={isPanelLocked || displaySettings?.buttons?.packet_analysis?.enabled === false}
                onClick={handlePacketAnalysis}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    isActionRunning("packet_analysis")
                      ? "bg-blue-600 border-blue-500 text-white shadow-lg cursor-wait"
                      : isPanelLocked || displaySettings?.buttons?.packet_analysis?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:border-blue-405 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <FileText className={`w-4 h-4 ${isActionRunning("packet_analysis") ? "text-white" : "text-purple-500"}`} />
                  </span>
                  {isActionRunning("packet_analysis") && (
                    <RefreshCw className="w-4 h-4 animate-spin text-white mt-1" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-800">{displaySettings?.buttons?.packet_analysis?.label || "Анализ пакетов"}</span>
                  <span className="text-[11px] text-slate-405 font-normal mt-0.5 block font-sans">
                    Скрипт as_report.sh
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.4 DNS ANALYSIS BUTTON --- */}
            {displaySettings?.buttons?.dns_analysis?.visible !== false && (
              <button
                disabled={isPanelLocked || displaySettings?.buttons?.dns_analysis?.enabled === false}
                onClick={handleDnsAnalysis}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    isActionRunning("dns_analysis")
                      ? "bg-blue-600 border-blue-500 text-white shadow-lg cursor-wait"
                      : isPanelLocked || displaySettings?.buttons?.dns_analysis?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-808 hover:border-[#10b981]/40 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <Activity className={`w-4 h-4 ${isActionRunning("dns_analysis") ? "text-white" : "text-teal-500"}`} />
                  </span>
                  {isActionRunning("dns_analysis") && (
                    <RefreshCw className="w-4 h-4 animate-spin text-white mt-1" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-800">{displaySettings?.buttons?.dns_analysis?.label || "Анализ ДНС"}</span>
                  <span className="text-[11px] text-slate-405 font-normal mt-0.5 block font-sans">
                    Скрипт getdns.sh
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.5 IP ADDRESSES TABLE --- */}
            {displaySettings?.buttons?.ip_addresses?.visible !== false && (
              <a
                href={metrics?.ip_report_exists && !isPanelLocked ? "/report-ip" : undefined}
                target="_blank"
                rel="noopener noreferrer"
                aria-disabled={isPanelLocked || !metrics?.ip_report_exists || displaySettings?.buttons?.ip_addresses?.enabled === false}
                onClick={(e) => {
                  if (!metrics?.ip_report_exists || isPanelLocked || displaySettings?.buttons?.ip_addresses?.enabled === false) {
                    e.preventDefault();
                  }
                }}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative select-none
                  ${
                    !metrics?.ip_report_exists || isPanelLocked || displaySettings?.buttons?.ip_addresses?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50 font-semibold pointer-events-none"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:translate-y-[-2px] shadow-sm border-l-4 border-l-blue-500 cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <FileSpreadsheet className={`w-4 h-4 ${!metrics?.ip_report_exists ? "text-slate-400" : "text-blue-500 group-hover:text-blue-600"}`} />
                  </span>
                  {metrics?.ip_report_exists && (
                    <ExternalLink className="w-4 h-4 text-blue-500 hover:text-blue-700 mt-1 shrink-0" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-850">{displaySettings?.buttons?.ip_addresses?.label || "IP адреса"}</span>
                  <span className="text-[11px] text-slate-400 font-normal mt-0.5 block">
                    {metrics?.ip_report_exists ? "Открыть CSV отчет" : "Недоступно (нет ip2loc_report.csv)"}
                  </span>
                </div>
              </a>
            )}

            {/* --- 2.6 DNS RECORDS TABLE --- */}
            {displaySettings?.buttons?.dns_records?.visible !== false && (
              <a
                href={metrics?.dns_report_exists && !isPanelLocked ? "/report-dns" : undefined}
                target="_blank"
                rel="noopener noreferrer"
                aria-disabled={isPanelLocked || !metrics?.dns_report_exists || displaySettings?.buttons?.dns_records?.enabled === false}
                onClick={(e) => {
                  if (!metrics?.dns_report_exists || isPanelLocked || displaySettings?.buttons?.dns_records?.enabled === false) {
                    e.preventDefault();
                  }
                }}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative select-none
                  ${
                    !metrics?.dns_report_exists || isPanelLocked || displaySettings?.buttons?.dns_records?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50 font-semibold pointer-events-none"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:translate-y-[-2px] shadow-sm border-l-4 border-l-blue-500 cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <FileSpreadsheet className={`w-4 h-4 ${!metrics?.dns_report_exists ? "text-slate-400" : "text-blue-500 group-hover:text-blue-600"}`} />
                  </span>
                  {metrics?.dns_report_exists && (
                    <ExternalLink className="w-4 h-4 text-blue-500 hover:text-blue-700 mt-1 shrink-0" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-855">{displaySettings?.buttons?.dns_records?.label || "ДНС"}</span>
                  <span className="text-[11px] text-slate-400 font-normal mt-0.5 block">
                    {metrics?.dns_report_exists ? "Открыть CSV отчет" : "Недоступно (нет dns_report.csv)"}
                  </span>
                </div>
              </a>
            )}

            {/* --- 2.7 DOWNLOAD LOGS ZIP --- */}
            {displaySettings?.buttons?.download_logs?.visible !== false && (
              <button
                disabled={!downloadEnabled}
                onClick={handleDownloadLogs}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    !downloadEnabled
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <Download className={`w-4 h-4 ${downloadEnabled ? "text-blue-500 animate-bounce" : "text-slate-400"}`} />
                  </span>
                </div>
                <div>
                  <span className="block font-bold">{displaySettings?.buttons?.download_logs?.label || "Скачать логи"}</span>
                  <span className="text-[11px] text-slate-400 font-normal mt-0.5 block">
                    {!logsExist
                      ? "Нет файлов: /tmp ip2loc_report.*, dns_report.* или /mnt/pcaps/capture*"
                      : `Скачать ${downloadFileCount} файл(ов) в ZIP`}
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.8 CLEAN DIRECTORIES --- */}
            {displaySettings?.buttons?.clean?.visible !== false && (
              <button
                disabled={isAnyMainServiceActionRunning || isCaptureServiceActive || isActionRunning("clean") || displaySettings?.buttons?.clean?.enabled === false}
                onClick={handleClean}
                className={`flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-semibold transition-all group relative
                  ${
                    isActionRunning("clean")
                      ? "bg-blue-600 border-blue-500 text-white shadow-lg cursor-wait"
                      : isAnyMainServiceActionRunning || isCaptureServiceActive || displaySettings?.buttons?.clean?.enabled === false
                      ? "bg-slate-50 border-slate-100 text-slate-400 cursor-not-allowed opacity-50"
                      : "bg-sky-50/60 hover:bg-sky-100 border-sky-200 text-slate-800 hover:border-orange-400/40 hover:translate-y-[-2px] shadow-sm cursor-pointer"
                  }
                `}
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-sky-200">
                    <Trash2 className={`w-4 h-4 ${isActionRunning("clean") ? "text-white" : "text-orange-500"}`} />
                  </span>
                  {isActionRunning("clean") && (
                    <RefreshCw className="w-4 h-4 animate-spin text-white mt-1" />
                  )}
                </div>
                <div>
                  <span className="block font-bold text-slate-800">{displaySettings?.buttons?.clean?.label || "Очистить"}</span>
                  <span className="text-[11px] text-slate-405 font-normal mt-0.5 block font-sans">
                    Очистка /mnt/pcaps и /tmp
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.9 YA REBOOT --- */}
            {displaySettings?.buttons?.ya_reboot?.visible !== false && (
              <button
                onClick={handleYaReboot}
                className="flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-bold transition-all group relative cursor-pointer bg-amber-50 hover:bg-amber-500 text-amber-700 hover:text-white border-amber-200 hover:translate-y-[-2px] shadow-sm"
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-amber-200">
                    <RotateCw className="w-4 h-4 text-amber-600" />
                  </span>
                </div>
                <div>
                  <span className="block font-bold uppercase tracking-wider">{displaySettings?.buttons?.ya_reboot?.label || "YA_РЯБУТ"}</span>
                  <span className="text-[11px] text-amber-600 group-hover:text-amber-100 font-bold mt-0.5 block font-mono">
                    shutdown -r now
                  </span>
                </div>
              </button>
            )}

            {/* --- 2.10 YA SLEEP --- */}
            {displaySettings?.buttons?.ya_sleep?.visible !== false && (
              <button
                onClick={handleYaSleep}
                className="flex flex-col justify-between items-start text-left p-4 h-32 rounded-xl border text-sm font-bold transition-all group relative cursor-pointer bg-red-50 hover:bg-red-500 text-red-650 hover:text-white border-red-250 hover:translate-y-[-2px] shadow-sm font-bold"
              >
                <div className="flex justify-between w-full">
                  <span className="p-2 rounded-lg bg-white border border-red-200">
                    <Moon className="w-4 h-4 text-red-500" />
                  </span>
                </div>
                <div>
                  <span className="block font-bold uppercase tracking-wider">{displaySettings?.buttons?.ya_sleep?.label || "YA_СПАТЬ"}</span>
                  <span className="text-[11px] text-red-500 group-hover:text-red-100 font-bold mt-0.5 block font-mono">
                    shutdown now
                  </span>
                </div>
              </button>
            )}

          </div>
        </section>
      </div>

      {/* 3. SETTINGS TOGGLE PANEL (Hides and configures UI elements) */}
      <div className="fixed bottom-6 right-6 z-50">
        <button
          onClick={() => setShowSettings(!showSettings)}
          className="p-3.5 bg-white hover:bg-sky-50 text-blue-600 rounded-full shadow-2xl hover:scale-105 active:scale-95 transition-all border border-sky-200 cursor-pointer"
          title="Настройки интерфейса"
        >
          <Settings className={`w-5 h-5 ${showSettings ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <AnimatePresence>
        {showSettings && (
          <motion.div
            initial={{ opacity: 0, x: 200 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 200 }}
            className="fixed top-0 right-0 h-screen w-80 bg-white border-l border-sky-150 shadow-2xl p-6 z-40 overflow-y-auto"
          >
            <div className="flex justify-between items-center pb-4 border-b border-sky-100 mb-6">
              <h3 className="text-xs font-bold text-slate-700 uppercase tracking-widest flex items-center gap-2 font-sans">
                <Settings className="w-4 h-4 text-blue-500" />
                <span>Interface Configuration</span>
              </h3>
              <button
                onClick={() => setShowSettings(false)}
                className="p-1 hover:bg-sky-50 rounded text-slate-400 hover:text-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-6">
              <div>
                <p className="text-[10px] text-blue-600 font-bold uppercase tracking-wider font-sans mb-2">Глобальные блоки</p>
                <div className="space-y-3">
                  <label className="flex items-center justify-between p-2 hover:bg-sky-50/60 rounded-lg cursor-pointer transition-colors">
                    <span className="text-sm font-medium text-slate-700">Блок графиков ЖД/ЦП</span>
                    <input
                      type="checkbox"
                      checked={localSettings?.enable_system_metrics !== false}
                      onChange={() => toggleSetting("enable_system_metrics")}
                      className="rounded bg-white border-sky-200 text-blue-500 focus:ring-0 focus:ring-offset-0 w-4 h-4 cursor-pointer"
                    />
                  </label>
                </div>
              </div>

              <div>
                <p className="text-[10px] text-blue-600 font-bold uppercase tracking-wider font-sans mb-3">Видимость кнопок</p>
                <div className="space-y-2">
                  {[
                    { key: "update_db", label: "Обновить базы" },
                    { key: "traffic_capture", label: "Захват пакетов" },
                    { key: "packet_analysis", label: "Анализ пакетов" },
                    { key: "dns_analysis", label: "Анализ ДНС" },
                    { key: "ip_addresses", label: "IP адреса" },
                    { key: "dns_records", label: "ДНС" },
                    { key: "download_logs", label: "Скачать логи" },
                    { key: "clean", label: "Очистить" },
                    { key: "ya_reboot", label: "YA_РЯБУТ", alwaysActive: true },
                    { key: "ya_sleep", label: "YA_СПАТЬ", alwaysActive: true },
                  ].map((btn) => {
                    const cfg = (localSettings?.buttons as any)?.[btn.key];
                    const alwaysActive = "alwaysActive" in btn && btn.alwaysActive;
                    return (
                      <div key={btn.key} className="p-3 bg-sky-50/40 border border-sky-100/80 rounded-xl space-y-2 animate-fade-in">
                        <div className="text-xs font-bold text-slate-700 font-sans">{btn.label}</div>
                        <div className="grid grid-cols-2 gap-2">
                          <label className="flex items-center justify-between bg-white border border-sky-100/50 p-1.5 px-2 rounded cursor-pointer text-[10px] text-slate-500 font-mono">
                            <span>SHOW</span>
                            <input
                              type="checkbox"
                              checked={cfg?.visible !== false}
                              onChange={() => toggleSetting("visible", btn.key)}
                              className="rounded bg-white border-sky-200 text-blue-500 focus:ring-0 scale-90 w-3.5 h-3.5"
                            />
                          </label>
                          {alwaysActive ? (
                            <div className="flex items-center justify-center bg-white border border-sky-100/50 p-1.5 px-2 rounded text-[10px] text-emerald-600 font-mono font-semibold">
                              ALWAYS ON
                            </div>
                          ) : (
                            <label className="flex items-center justify-between bg-white border border-sky-100/50 p-1.5 px-2 rounded cursor-pointer text-[10px] text-slate-500 font-mono">
                              <span>ACTIVE</span>
                              <input
                                type="checkbox"
                                checked={cfg?.enabled !== false}
                                onChange={() => toggleSetting("enabled", btn.key)}
                                className="rounded bg-white border-sky-200 text-blue-500 focus:ring-0 scale-90 w-3.5 h-3.5"
                              />
                            </label>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="text-[10px] text-slate-400 font-sans text-center pt-4 border-t border-sky-100">
                Все настройки сохраняются напрямую в файл <code className="text-blue-500 font-semibold font-mono">settings.json</code> в реальном времени!
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
}
