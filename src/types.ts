export interface CoreMetric {
  core: string;
  load: number;
}

export interface RamMetric {
  total: number;
  used: number;
  free: number;
}

export interface SwapMetric {
  total: number;
  used: number;
  free: number;
}

export interface DiskMetric {
  device: string;
  total: number;
  used: number;
  free: number;
  mount: string;
  percent: string;
}

export interface ProcessMetric {
  pid: string;
  cpu: string;
  mem: string;
  name: string;
}

export interface ButtonConfig {
  visible: boolean;
  enabled: boolean;
  label: string;
}

export interface SystemSettings {
  enable_system_metrics: boolean;
  enable_service_control: boolean;
  buttons: {
    update_db: ButtonConfig;
    traffic_capture: ButtonConfig;
    packet_analysis: ButtonConfig;
    ip_addresses: ButtonConfig;
    dns_records: ButtonConfig;
    download_logs: ButtonConfig;
    clean: ButtonConfig;
    ya_reboot: ButtonConfig;
    ya_sleep: ButtonConfig;
  };
}

export interface SystemMetricsResponse {
  cores: CoreMetric[];
  ram: RamMetric;
  swap: SwapMetric;
  disks: DiskMetric[];
  uptime: string;
  top_processes: ProcessMetric[];
  traffic_capture_active: boolean;
  ip_report_exists: boolean;
  dns_report_exists: boolean;
  log_files_available: string[];
  download_available?: boolean;
  capture_files_exist?: boolean;
  running_actions?: Record<string, boolean>;
  settings?: SystemSettings;
  paths?: Record<string, string>;
}
